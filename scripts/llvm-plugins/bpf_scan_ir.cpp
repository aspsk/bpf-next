// SPDX-License-Identifier: GPL-2.0-only
/* bpf_scan_ir: optimizer-last LLVM IR analysis for BPF. */

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR >= 19
#include "llvm/IR/Analysis.h"
#endif
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace {

static constexpr int MaxErrno = 4095;

// is Range in [-4095, 0) ?
static bool isErrnoRange(const ConstantRange &Range)
{
	unsigned Width = Range.getBitWidth();

	if (Width != 32 && Width != 64)
		return false;

	auto L = APInt(Width, 0) - APInt(Width, MaxErrno);
	auto R = APInt(Width, 0);
	return !Range.isEmptySet() && ConstantRange(L, R).contains(Range);
}

static bool rangeAtUseIsErrno(const Use &U, LazyValueInfo &LVI)
{
	Value *V = U.get();

	return V->getType()->isIntegerTy() &&
	       isErrnoRange(LVI.getConstantRangeAtUse(U, false));
}

static bool isErrnoConstant(const Value *V)
{
	auto *C = dyn_cast<ConstantInt>(V);
	int64_t N;

	if (!C || (C->getBitWidth() != 32 && C->getBitWidth() != 64))
		return false;

	N = C->getSExtValue();
	return N >= -MaxErrno && N < 0;
}

static bool isCleanInstruction(const Instruction &I)
{
	if (auto *Intrinsic = dyn_cast<IntrinsicInst>(&I)) {
		switch (Intrinsic->getIntrinsicID()) {
		case Intrinsic::assume:
		case Intrinsic::lifetime_start:
		case Intrinsic::lifetime_end:
		case Intrinsic::invariant_start:
		case Intrinsic::invariant_end:
			return true;
		default:
			break;
		}
	}
	return !I.mayHaveSideEffects();
}

static bool cleanBB(BasicBlock *BB)
{
	for (Instruction &I : *BB) {
		if (!isCleanInstruction(I))
			return false;
	}
	return true;
}

static bool functionHasCleanErrnoPath(Function &F, LazyValueInfo &LVI)
{
	SmallPtrSet<BasicBlock *, 32> CleanEntries;
	SmallPtrSet<BasicBlock *, 32> CleanBBs;
	SmallVector<BasicBlock *, 32> Worklist;

	// build the list of "clean" BBs
	CleanEntries.insert(&F.getEntryBlock());
	Worklist.push_back(&F.getEntryBlock());
	while (!Worklist.empty()) {
		BasicBlock *BB = Worklist.pop_back_val();
		if (!cleanBB(BB))
			continue;

		CleanBBs.insert(BB);

		for (BasicBlock *Successor : successors(BB)) {
			auto havent_seen = CleanEntries.insert(Successor).second;
			if (havent_seen)
				Worklist.push_back(Successor);
		}
	}

	// consider the return values of "clean" exits, i.e.,
	// exits, where all predcessors were "clean"
	for (BasicBlock *BB : CleanBBs) {
		auto *Return = dyn_cast<ReturnInst>(BB->getTerminator());
		if (!Return || !Return->getReturnValue())
			continue;

		if (rangeAtUseIsErrno(Return->getOperandUse(0), LVI) ||
		    isErrnoConstant(Return->getReturnValue()))
			return true;
	}
	return false;
}

static void emitCandidates(Module &M, ArrayRef<Constant *> Fns)
{
	auto *PtrTy = PointerType::getUnqual(M.getContext());
	auto *ArrTy = ArrayType::get(PtrTy, Fns.size());
	auto isConstant = true;
	auto *GV = new GlobalVariable(M, ArrTy, isConstant,
				      GlobalValue::PrivateLinkage,
				      ConstantArray::get(ArrTy, Fns),
				      "fmodret_candidates.table");
	GV->setSection(".BTF_fmodret_candidates");
	GV->setAlignment(M.getDataLayout().getPointerABIAlignment(0));
	appendToUsed(M, {GV});
}

#if LLVM_VERSION_MAJOR >= 24
class BpfScanIRPass : public RequiredPassInfoMixin<BpfScanIRPass>
#else
class BpfScanIRPass : public PassInfoMixin<BpfScanIRPass>
#endif
{
public:
	PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM)
	{
		// Avoid emitting duplicate descriptions if bpf_scan_ir runs again
		// on the same module.
		if (M.getNamedMetadata("bpf_scan_ir.done"))
			return PreservedAnalyses::all();

		SmallVector<Constant *> Fns;
		auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

		for (Function &F : M) {
			if (F.isDeclaration() ||
			    F.hasWeakAnyLinkage() || // to be removed later when we can track __weak properly
			    F.hasAvailableExternallyLinkage() ||
			    !F.getReturnType()->isIntegerTy())
				continue;

			unsigned Width = F.getReturnType()->getIntegerBitWidth();
			if (Width != 32 && Width != 64)
				continue;

			auto &LVI = FAM.getResult<LazyValueAnalysis>(F);
			if (functionHasCleanErrnoPath(F, LVI))
				Fns.push_back(&F);
		}

		if (Fns.empty())
			return PreservedAnalyses::all();

		emitCandidates(M, Fns);
		M.getOrInsertNamedMetadata("bpf_scan_ir.done");

		PreservedAnalyses PA;
		PA.preserve<FunctionAnalysisManagerModuleProxy>();
		PA.preserveSet<CFGAnalyses>();
		PA.preserve<LazyValueAnalysis>();
		return PA;
	}

	static bool isRequired() { return true; }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
	return {
		LLVM_PLUGIN_API_VERSION,
		"bpf_scan_ir",
		"1.0",
		[](PassBuilder &PB) {
			PB.registerOptimizerLastEPCallback(
				[](ModulePassManager &MPM, OptimizationLevel, auto...) {
					MPM.addPass(BpfScanIRPass());
				   }
			);
		}
	};
}
