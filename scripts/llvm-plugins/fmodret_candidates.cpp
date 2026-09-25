// SPDX-License-Identifier: GPL-2.0-only
/* Emit references to functions which may return a Linux errno. */

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
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

			if (Incoming->getType()->isIntegerTy() &&
			    isErrnoRange(LVI.getConstantRangeOnEdge(
				Incoming, Pred, Phi->getParent())))
				return true;
			if (valueMayBeErrno(Incoming, Pred, LVI, DT, Seen,
					    Depth + 1))
				return true;
		}
	} else if (auto *Select = dyn_cast<SelectInst>(V)) {
		for (unsigned I = 1; I <= 2; I++) {
			const Value *Pointer =
				convertedPointer(Select->getOperand(I));

			if (Pointer && conditionImpliesIsErr(
					       Select->getCondition(), I == 1, Pointer))
				return true;
			if (rangeAtUseIsErrno(Select->getOperandUse(I), LVI) ||
			    valueMayBeErrno(Select->getOperand(I), BB, LVI, DT,
					    Seen, Depth + 1))
				return true;
		}
	} else if (auto *Cast = dyn_cast<CastInst>(V)) {
		/* Zero extension does not preserve a negative bit pattern. */
		if (isa<ZExtInst>(Cast)) {
			Seen.erase(V);
			return false;
		}
		if (rangeAtUseIsErrno(Cast->getOperandUse(0), LVI) ||
		    valueMayBeErrno(Cast->getOperand(0), BB, LVI, DT,
				    Seen, Depth + 1))
			return true;
	}
	Seen.erase(V);
	return false;
}

static bool functionMayReturnErrno(Function &F, LazyValueInfo &LVI,
				   DominatorTree &DT)
{
	for (BasicBlock &BB : F) {
		auto *Return = dyn_cast<ReturnInst>(BB.getTerminator());
		SmallPtrSet<const Value *, 32> Seen;

		if (!Return || !Return->getReturnValue())
			continue;
		if (rangeAtUseIsErrno(Return->getOperandUse(0), LVI) ||
		    valueMayBeErrno(Return->getReturnValue(), &BB, LVI, DT,
				    Seen, 0))
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
	PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM)
	{
		unsigned Width;

		if (F.isDeclaration() || F.hasFnAttribute("fmodret-candidate-emitted") ||
		    !F.getReturnType()->isIntegerTy())
			return PreservedAnalyses::all();
		Width = F.getReturnType()->getIntegerBitWidth();
		if (Width != 32 && Width != 64)
			return PreservedAnalyses::all();
		auto &LVI = FAM.getResult<LazyValueAnalysis>(F);
		auto &DT = FAM.getResult<DominatorTreeAnalysis>(F);

		if (!functionMayReturnErrno(F, LVI, DT))
			return PreservedAnalyses::all();
		emitCandidate(F);
		F.addFnAttr("fmodret-candidate-emitted");
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
					MPM.addPass(createModuleToFunctionPassAdaptor(
						FmodretCandidatesPass()));
				});
		}};
}
