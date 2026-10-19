// SPDX-License-Identifier: GPL-2.0-only
/* Emit references to functions with a clean path to a Linux errno return. */

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include <string>

using namespace llvm;

namespace {

constexpr unsigned MaxErrno = 4095;
constexpr unsigned MaxValueDepth = 64;

static bool isErrnoRange(const ConstantRange &Range)
{
	unsigned Width = Range.getBitWidth();

	if (Width != 32 && Width != 64)
		return false;
	ConstantRange Errnos(APInt(Width, 0) - APInt(Width, MaxErrno),
			     APInt(Width, 0));

	return !Range.isEmptySet() && Errnos.contains(Range);
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

static const Value *convertedPointer(const Value *V)
{
	for (unsigned Depth = 0; V && Depth < MaxValueDepth; Depth++) {
		if (auto *C = dyn_cast<PtrToIntInst>(V))
			return C->getPointerOperand();
		if (auto *C = dyn_cast<CastInst>(V)) {
			V = C->getOperand(0);
			continue;
		}
		break;
	}
	return nullptr;
}

static bool matchesPointer(const Value *V, const Value *Pointer)
{
	return V == Pointer || convertedPointer(V) == Pointer;
}

static const ConstantInt *comparisonThreshold(const Value *V)
{
	if (auto *C = dyn_cast<ConstantInt>(V))
		return C;
	if (auto *Expr = dyn_cast<ConstantExpr>(V))
		if (Expr->getOpcode() == Instruction::IntToPtr)
			return dyn_cast<ConstantInt>(Expr->getOperand(0));
	return nullptr;
}

static bool conditionImpliesIsErr(Value *Condition, bool Truth,
				  const Value *Pointer)
{
	auto *Cmp = dyn_cast<ICmpInst>(Condition);
	CmpInst::Predicate Pred;
	const Value *Integer;
	const ConstantInt *Threshold;
	APInt Limit;

	if (!Cmp)
		return false;
	Pred = Cmp->getPredicate();
	Integer = Cmp->getOperand(0);
	Threshold = comparisonThreshold(Cmp->getOperand(1));
	if (!matchesPointer(Integer, Pointer)) {
		Integer = Cmp->getOperand(1);
		Threshold = comparisonThreshold(Cmp->getOperand(0));
		Pred = CmpInst::getSwappedPredicate(Pred);
	}
	if (!Threshold || !matchesPointer(Integer, Pointer))
		return false;
	if (Threshold->getBitWidth() != 32 && Threshold->getBitWidth() != 64)
		return false;
	if (!Truth)
		Pred = CmpInst::getInversePredicate(Pred);
	if (Pred != CmpInst::ICMP_UGE && Pred != CmpInst::ICMP_UGT)
		return false;

	Limit = APInt(Threshold->getBitWidth(), 0) -
		APInt(Threshold->getBitWidth(), MaxErrno);
	if (Pred == CmpInst::ICMP_UGT)
		--Limit;
	return Threshold->getValue().uge(Limit);
}

static bool dominatedByIsErr(const Value *V, BasicBlock *BB,
			     DominatorTree &DT)
{
	const Value *Pointer = convertedPointer(V);

	if (!Pointer)
		return false;
	while (BB) {
		BasicBlock *Dom = DT.getNode(BB)->getIDom() ?
			DT.getNode(BB)->getIDom()->getBlock() : nullptr;
		auto *Branch = Dom ? dyn_cast<BranchInst>(Dom->getTerminator()) :
				     nullptr;
		bool TruePath, FalsePath;

		if (!Dom)
			break;
		if (!Branch || !Branch->isConditional()) {
			BB = Dom;
			continue;
		}
		TruePath = DT.dominates(Branch->getSuccessor(0), BB);
		FalsePath = DT.dominates(Branch->getSuccessor(1), BB);
		if (TruePath != FalsePath &&
		    conditionImpliesIsErr(Branch->getCondition(), TruePath,
					  Pointer))
			return true;
		BB = Dom;
	}
	return false;
}

static bool rangeAtUseIsErrno(const Use &U, LazyValueInfo &LVI)
{
	Value *V = U.get();

	return V->getType()->isIntegerTy() &&
	       isErrnoRange(LVI.getConstantRangeAtUse(U, false));
}

static bool valueMayBeErrno(Value *V, BasicBlock *BB, LazyValueInfo &LVI,
			    DominatorTree &DT,
			    const SmallPtrSetImpl<BasicBlock *> &CleanExits,
			    SmallPtrSetImpl<const Value *> &Seen,
			    unsigned Depth)
{
	if (!V || Depth == MaxValueDepth)
		return false;
	if (isErrnoConstant(V) || dominatedByIsErr(V, BB, DT))
		return true;
	if (!Seen.insert(V).second)
		return false;

	if (auto *Phi = dyn_cast<PHINode>(V)) {
		for (unsigned I = 0; I < Phi->getNumIncomingValues(); I++) {
			Value *Incoming = Phi->getIncomingValue(I);
			BasicBlock *Pred = Phi->getIncomingBlock(I);

			if (!CleanExits.contains(Pred))
				continue;
			if (Incoming->getType()->isIntegerTy() &&
			    isErrnoRange(LVI.getConstantRangeOnEdge(
				Incoming, Pred, Phi->getParent())))
				return true;
			if (valueMayBeErrno(Incoming, Pred, LVI, DT, CleanExits,
					    Seen, Depth + 1))
				return true;
		}
	} else if (auto *Cast = dyn_cast<CastInst>(V)) {
		/* Zero extension does not preserve a negative bit pattern. */
		if (!isa<ZExtInst>(Cast) &&
		    (rangeAtUseIsErrno(Cast->getOperandUse(0), LVI) ||
		     valueMayBeErrno(Cast->getOperand(0), BB, LVI, DT,
				     CleanExits, Seen, Depth + 1)))
			return true;
	}
	Seen.erase(V);
	return false;
}

static bool isCleanInstruction(const Instruction &I)
{
	/* Control flow and return do not change the caller-visible state. */
	if (isa<BranchInst, SwitchInst, ReturnInst>(I))
		return true;
	if (isa<DbgInfoIntrinsic>(I))
		return true;
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

static bool functionHasCleanErrnoPath(Function &F, LazyValueInfo &LVI,
				      DominatorTree &DT)
{
	SmallPtrSet<BasicBlock *, 32> CleanEntries;
	SmallPtrSet<BasicBlock *, 32> CleanExits;
	SmallVector<BasicBlock *, 32> Worklist;

	CleanEntries.insert(&F.getEntryBlock());
	Worklist.push_back(&F.getEntryBlock());
	while (!Worklist.empty()) {
		BasicBlock *BB = Worklist.pop_back_val();
		bool Clean = true;

		for (Instruction &I : *BB) {
			if (!isCleanInstruction(I)) {
				Clean = false;
				break;
			}
		}
		if (!Clean)
			continue;
		CleanExits.insert(BB);
		for (BasicBlock *Successor : successors(BB))
			if (CleanEntries.insert(Successor).second)
				Worklist.push_back(Successor);
	}

	for (BasicBlock &BB : F) {
		auto *Return = dyn_cast<ReturnInst>(BB.getTerminator());
		SmallPtrSet<const Value *, 32> Seen;

		if (!CleanExits.contains(&BB) || !Return ||
		    !Return->getReturnValue())
			continue;
		if (rangeAtUseIsErrno(Return->getOperandUse(0), LVI) ||
		    valueMayBeErrno(Return->getReturnValue(), &BB, LVI, DT,
				    CleanExits, Seen, 0))
			return true;
	}
	return false;
}

static void emitCandidate(Function &F)
{
	unsigned Bytes = F.getParent()->getDataLayout().getPointerSize();
	std::string Asm = ".pushsection .BTF_fmodret_candidates,\"\"\n"
			  ".balign " + std::to_string(Bytes) + "\n" +
			  (Bytes == 8 ? ".quad " : ".long ") +
			  "${0:c}\n.popsection";
	auto *Ty = FunctionType::get(Type::getVoidTy(F.getContext()),
				     {F.getType()}, false);
	auto *IA = InlineAsm::get(Ty, Asm, "s", true);
	IRBuilder<> Builder(&*F.getEntryBlock().getFirstInsertionPt());

	Builder.CreateCall(IA, {&F});
}

class FmodretCandidatesPass : public PassInfoMixin<FmodretCandidatesPass> {
public:
	PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM)
	{
		SmallVector<Function *, 32> Candidates;
		auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M)
				    .getManager();

		for (Function &F : M) {
			unsigned Width;

			if (F.isDeclaration() ||
			    F.hasFnAttribute("fmodret-candidate-emitted") ||
			    !F.getReturnType()->isIntegerTy())
				continue;
			Width = F.getReturnType()->getIntegerBitWidth();
			if (Width != 32 && Width != 64)
				continue;
			auto &LVI = FAM.getResult<LazyValueAnalysis>(F);
			auto &DT = FAM.getResult<DominatorTreeAnalysis>(F);

			if (functionHasCleanErrnoPath(F, LVI, DT))
				Candidates.push_back(&F);
		}
		if (Candidates.empty())
			return PreservedAnalyses::all();
		for (Function *F : Candidates) {
			emitCandidate(*F);
			F->addFnAttr("fmodret-candidate-emitted");
		}
		return PreservedAnalyses::none();
	}
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
	return {LLVM_PLUGIN_API_VERSION, "fmodret-candidates", "1.0",
		[](PassBuilder &PB) {
			PB.registerOptimizerLastEPCallback(
				[](ModulePassManager &MPM, OptimizationLevel,
				   ThinOrFullLTOPhase) {
					MPM.addPass(FmodretCandidatesPass());
				});
		}};
}
