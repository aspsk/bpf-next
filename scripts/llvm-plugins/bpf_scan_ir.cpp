// SPDX-License-Identifier: GPL-2.0-only
/* bpf_scan_ir: optimizer-last LLVM IR analysis for BPF. */

#include "fmodret_metadata.h"

#include <algorithm>
#include <memory>
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR >= 19
#include "llvm/IR/Analysis.h"
#endif
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InlineAsm.h"
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
static constexpr unsigned MaxValueDepth = 64;

static bool preservesErrnoCast(unsigned Opcode, Type *Src, Type *Dst,
			       const DataLayout &DL);

static bool isErrorPointerType(Type *Ty, const DataLayout &DL)
{
	return Ty->isPointerTy() && !DL.isNonIntegralPointerType(Ty) &&
	       (DL.getPointerTypeSizeInBits(Ty) == 32 ||
		DL.getPointerTypeSizeInBits(Ty) == 64);
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

static bool matchesPointer(const Value *V, const Value *Pointer,
			   const DataLayout &DL)
{
	if (V == Pointer)
		return true;
	auto *Cast = dyn_cast<PtrToIntInst>(V);

	// A comparison of only the low pointer bits cannot establish IS_ERR.
	return Cast && Cast->getPointerOperand() == Pointer &&
	       Cast->getType()->getIntegerBitWidth() ==
		DL.getPointerTypeSizeInBits(Pointer->getType());
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

static bool conditionImpliesIsErr(Value *Condition, bool Truth, const Value *Pointer,
				  const DataLayout &DL)
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
	if (!matchesPointer(Integer, Pointer, DL)) {
		Integer = Cmp->getOperand(1);
		Threshold = comparisonThreshold(Cmp->getOperand(0));
		Pred = CmpInst::getSwappedPredicate(Pred);
	}
	if (!Threshold || !matchesPointer(Integer, Pointer, DL))
		return false;
	if (Threshold->getBitWidth() != DL.getPointerTypeSizeInBits(Pointer->getType()))
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

static bool dominatedByIsErr(const Value *V, BasicBlock *BB, DominatorTree &DT)
{
	const DataLayout &DL = BB->getModule()->getDataLayout();
	const Value *Pointer = V->getType()->isPointerTy() ? V : convertedPointer(V);

	if (!Pointer || !isErrorPointerType(Pointer->getType(), DL))
		return false;

	while (BB) {
		BasicBlock *Dom = DT.getNode(BB)->getIDom() ?
			DT.getNode(BB)->getIDom()->getBlock() : nullptr;
#if LLVM_VERSION_MAJOR >= 23
		auto *Branch = Dom ? dyn_cast<CondBrInst>(Dom->getTerminator()) : nullptr;
#else
		auto *Branch = Dom ? dyn_cast<BranchInst>(Dom->getTerminator()) : nullptr;
#endif
		bool TruePath, FalsePath;

		if (!Dom)
			break;
		if (!Branch || Branch->getNumSuccessors() != 2 ||
		    Branch->getSuccessor(0) == Branch->getSuccessor(1)) {
			BB = Dom;
			continue;
		}
		TruePath = DT.dominates(BasicBlockEdge(Dom, Branch->getSuccessor(0)), BB);
		FalsePath = DT.dominates(BasicBlockEdge(Dom, Branch->getSuccessor(1)), BB);
		if (TruePath != FalsePath &&
		    conditionImpliesIsErr(Branch->getCondition(), TruePath, Pointer, DL))
			return true;
		BB = Dom;
	}
	return false;
}

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

static bool isErrnoConstant(const Value *V, const DataLayout &DL)
{
	if (auto *Expr = dyn_cast<ConstantExpr>(V);
	    Expr && Expr->getOpcode() == Instruction::IntToPtr &&
	    isErrorPointerType(Expr->getType(), DL)) {
		auto *C = dyn_cast<ConstantInt>(Expr->getOperand(0));

		if (!C)
			return false;
		unsigned Width = DL.getPointerTypeSizeInBits(Expr->getType());
		APInt Bits = C->getValue().zextOrTrunc(Width);

		return Bits.uge(APInt(Width, 0) - APInt(Width, MaxErrno));
	}
	auto *C = dyn_cast<ConstantInt>(V);
	int64_t N;

	if (!C || (C->getBitWidth() != 32 && C->getBitWidth() != 64))
		return false;

	N = C->getSExtValue();
	return N >= -MaxErrno && N < 0;
}

using BooleanFacts = DenseMap<const Value *, bool>;

static bool knownBoolean(const Value *V, const BooleanFacts &Facts, bool &Truth,
			 unsigned Depth = 0, const Value *Ignore = nullptr)
{
	if (Depth >= MaxValueDepth)
		return false;
	if (auto *C = dyn_cast<ConstantInt>(V)) {
		Truth = !C->isZero();
		return true;
	}
	auto It = Facts.find(V);
	if (V != Ignore && It != Facts.end()) {
		Truth = It->second;
		return true;
	}
	if (auto *B = dyn_cast<BinaryOperator>(V); B && B->getType()->isIntegerTy(1)) {
		bool L = false, R = false;
		bool KL = knownBoolean(B->getOperand(0), Facts, L, Depth + 1, Ignore);
		bool KR = knownBoolean(B->getOperand(1), Facts, R, Depth + 1, Ignore);

		if (B->getOpcode() == Instruction::And && ((KL && !L) || (KR && !R)))
			Truth = false;
		else if (B->getOpcode() == Instruction::Or && ((KL && L) || (KR && R)))
			Truth = true;
		else if (KL && KR && (B->getOpcode() == Instruction::And ||
			 B->getOpcode() == Instruction::Or || B->getOpcode() == Instruction::Xor))
			Truth = B->getOpcode() == Instruction::And ? L && R :
				B->getOpcode() == Instruction::Or ? L || R : L != R;
		else
			return false;
		return true;
	}
	if (auto *C = dyn_cast<ICmpInst>(V);
	    C && C->isEquality() && C->getOperand(0)->getType()->isIntegerTy(1)) {
		bool L, R;
		if (knownBoolean(C->getOperand(0), Facts, L, Depth + 1, Ignore) &&
		    knownBoolean(C->getOperand(1), Facts, R, Depth + 1, Ignore)) {
			Truth = C->getPredicate() == CmpInst::ICMP_EQ ? L == R : L != R;
			return true;
		}
	}
	return false;
}

static bool assumeBoolean(const Value *V, bool Truth, BooleanFacts &Facts,
			  unsigned Depth = 0)
{
	if (Depth >= MaxValueDepth || Facts.size() >= MaxValueDepth)
		return false;
	bool Known;
	if (knownBoolean(V, Facts, Known))
		return Known == Truth;
	Facts[V] = Truth;
	if (auto *B = dyn_cast<BinaryOperator>(V); B && B->getType()->isIntegerTy(1)) {
		if ((B->getOpcode() == Instruction::And && Truth) ||
		    (B->getOpcode() == Instruction::Or && !Truth))
			return assumeBoolean(B->getOperand(0), Truth, Facts, Depth + 1) &&
			       assumeBoolean(B->getOperand(1), Truth, Facts, Depth + 1);
		if (B->getOpcode() == Instruction::Xor) {
			for (unsigned I = 0; I < 2; I++)
				if (auto *C = dyn_cast<ConstantInt>(B->getOperand(I)))
					return assumeBoolean(B->getOperand(1 - I),
						Truth != !C->isZero(), Facts, Depth + 1);
		}
	}
	if (auto *C = dyn_cast<ICmpInst>(V);
	    C && C->isEquality() && C->getOperand(0)->getType()->isIntegerTy(1)) {
		for (unsigned I = 0; I < 2; I++)
			if (auto *K = dyn_cast<ConstantInt>(C->getOperand(I)))
				return assumeBoolean(C->getOperand(1 - I),
					(Truth == (C->getPredicate() == CmpInst::ICMP_EQ)) ==
					!K->isZero(), Facts, Depth + 1);
	}
	return true;
}

using UnsignedInterval = std::pair<APInt, APInt>;
using UnsignedIntervals = SmallVector<UnsignedInterval, 4>;

static UnsignedIntervals rangeIntervals(const ConstantRange &Range)
{
	unsigned Width = Range.getBitWidth();
	APInt Zero(Width, 0), Last = APInt::getAllOnes(Width);
	if (Range.isEmptySet())
		return {};
	if (Range.isFullSet())
		return {{Zero, Last}};
	if (Range.getLower().ult(Range.getUpper()))
		return {{Range.getLower(), Range.getUpper() - 1}};
	UnsignedIntervals Parts{{Range.getLower(), Last}};
	if (!Range.getUpper().isZero())
		Parts.emplace_back(Zero, Range.getUpper() - 1);
	return Parts;
}

static bool conditionsConsistent(const BooleanFacts &Facts, const DataLayout &DL,
				 LazyValueInfo *LVI = nullptr, Instruction *Context = nullptr)
{
	DenseMap<const Value *, UnsignedIntervals> Ranges;
	for (const auto &Fact : Facts) {
		bool Known;
		if (knownBoolean(Fact.first, Facts, Known, 0, Fact.first) && Known != Fact.second)
			return false;
		auto *Cmp = dyn_cast<ICmpInst>(Fact.first);
		if (!Cmp)
			continue;
		const Value *V = Cmp->getOperand(0), *K = Cmp->getOperand(1);
		auto Pred = Cmp->getPredicate();
		if (isa<Constant>(V) && !isa<Constant>(K)) {
			std::swap(V, K);
			Pred = CmpInst::getSwappedPredicate(Pred);
		}
		unsigned Width = V->getType()->isIntegerTy() ?
			V->getType()->getIntegerBitWidth() :
			isErrorPointerType(V->getType(), DL) ? DL.getPointerTypeSizeInBits(V->getType()) : 0;
		if (!Width || Width > 64)
			continue;
		APInt Bits(Width, 0);
		if (auto *C = dyn_cast<ConstantInt>(K))
			Bits = C->getValue();
		else if (auto *E = dyn_cast<ConstantExpr>(K);
			 E && E->getOpcode() == Instruction::IntToPtr &&
			 isa<ConstantInt>(E->getOperand(0)))
			Bits = cast<ConstantInt>(E->getOperand(0))->getValue().zextOrTrunc(Width);
		else if (!isa<ConstantPointerNull>(K))
			continue;
		if (!Fact.second)
			Pred = CmpInst::getInversePredicate(Pred);
		ConstantRange Region = ConstantRange::makeExactICmpRegion(Pred, Bits);
		if (auto *Cast = dyn_cast<PtrToIntInst>(V);
		    Cast && isErrorPointerType(Cast->getPointerOperand()->getType(), DL) &&
		    Width == DL.getPointerTypeSizeInBits(Cast->getPointerOperand()->getType()))
			V = Cast->getPointerOperand();
		auto It = Ranges.find(V);
		UnsignedIntervals Allowed = It == Ranges.end() ?
			rangeIntervals(LVI && isa<Argument>(V) && V->getType()->isIntegerTy() ?
				LVI->getConstantRange(const_cast<Value *>(V), Context, false) :
				ConstantRange::getFull(Width)) : It->second;
		UnsignedIntervals Intersection;
		for (const auto &A : Allowed)
			for (const auto &B : rangeIntervals(Region)) {
				APInt Low = A.first.ugt(B.first) ? A.first : B.first;
				APInt High = A.second.ult(B.second) ? A.second : B.second;
				if (Low.ule(High))
					Intersection.emplace_back(std::move(Low), std::move(High));
			}
		if (Intersection.empty())
			return false;
		Ranges.insert_or_assign(V, std::move(Intersection));
	}
	return true;
}

// Unknown select choices need an actual witness for the supported condition
// language. Unsupported relations and exhausted searches do not establish one.
static bool collectConditionAtoms(const Value *V, SmallPtrSetImpl<const Value *> &Atoms,
				  unsigned Depth = 0)
{
	if (Depth >= MaxValueDepth || Atoms.size() > 12)
		return false;
	if (isa<ConstantInt>(V))
		return V->getType()->isIntegerTy(1);
	if (isa<Argument>(V) && V->getType()->isIntegerTy(1)) {
		Atoms.insert(V);
		return true;
	}
	if (auto *B = dyn_cast<BinaryOperator>(V);
	    B && B->getType()->isIntegerTy(1) &&
	    (B->getOpcode() == Instruction::And || B->getOpcode() == Instruction::Or ||
	     B->getOpcode() == Instruction::Xor))
		return collectConditionAtoms(B->getOperand(0), Atoms, Depth + 1) &&
		       collectConditionAtoms(B->getOperand(1), Atoms, Depth + 1);
	auto *Cmp = dyn_cast<ICmpInst>(V);
	if (!Cmp)
		return false;
	if (Cmp->isEquality() && Cmp->getOperand(0)->getType()->isIntegerTy(1))
		return collectConditionAtoms(Cmp->getOperand(0), Atoms, Depth + 1) &&
		       collectConditionAtoms(Cmp->getOperand(1), Atoms, Depth + 1);
	const Value *A = Cmp->getOperand(0), *B = Cmp->getOperand(1);
	if (isa<ConstantInt>(A))
		std::swap(A, B);
	if (!isa<Argument>(A) || !isa<ConstantInt>(B) ||
	    !A->getType()->isIntegerTy() || A->getType()->getIntegerBitWidth() > 64)
		return false;
	Atoms.insert(V);
	return true;
}

static bool conditionWitness(ArrayRef<const Value *> Atoms, unsigned Index,
			      const BooleanFacts &Facts, LazyValueInfo &LVI,
			      DominatorTree &DT, Instruction *Context, unsigned &Budget)
{
	if (!Budget)
		return false;
	Budget--;
	if (!conditionsConsistent(Facts, Context->getModule()->getDataLayout(), &LVI, Context))
		return false;
	if (Index == Atoms.size())
		return true;
	auto *Atom = const_cast<Value *>(Atoms[Index]);
	auto *Definition = dyn_cast<Instruction>(Atom);
	ConstantRange Possible = !Definition || DT.dominates(Definition, Context) ?
		LVI.getConstantRange(Atom, Context, false) : ConstantRange::getFull(1);
	bool Truth;
	if (knownBoolean(Atom, Facts, Truth))
		return Possible.contains(APInt(1, Truth)) &&
		       conditionWitness(Atoms, Index + 1, Facts, LVI, DT, Context, Budget);
	for (unsigned Choice = 0; Choice < 2 && Budget; Choice++) {
		if (!Possible.contains(APInt(1, Choice)))
			continue;
		BooleanFacts Assigned = Facts;
		if (assumeBoolean(Atom, Choice, Assigned) &&
		    conditionWitness(Atoms, Index + 1, Assigned, LVI, DT, Context, Budget))
			return true;
	}
	return false;
}

static bool selectConditionsFeasible(const BooleanFacts &Facts, LazyValueInfo &LVI,
				     DominatorTree &DT, Instruction *Context)
{
	SmallPtrSet<const Value *, 16> Unique;
	for (const auto &Fact : Facts)
		if (!collectConditionAtoms(Fact.first, Unique))
			return false;
	if (Unique.size() > 12)
		return false;
	// Stable IR order makes the bounded search independent of pointer hashes.
	SmallVector<const Value *, 16> Atoms;
	for (const Argument &A : Context->getFunction()->args())
		if (Unique.contains(&A))
			Atoms.push_back(&A);
	for (const BasicBlock &BB : *Context->getFunction())
		for (const Instruction &I : BB)
			if (Unique.contains(&I))
				Atoms.push_back(&I);
	unsigned Budget = 256;
	return conditionWitness(Atoms, 0, Facts, LVI, DT, Context, Budget);
}

static bool assumeEdge(BasicBlock *From, BasicBlock *To, BooleanFacts &Facts)
{
#if LLVM_VERSION_MAJOR >= 23
	auto *Branch = dyn_cast<CondBrInst>(From->getTerminator());
#else
	auto *Branch = dyn_cast<BranchInst>(From->getTerminator());
#endif
	if (!Branch || Branch->getNumSuccessors() != 2 ||
	    Branch->getSuccessor(0) == Branch->getSuccessor(1))
		return true;
	return assumeBoolean(Branch->getCondition(), Branch->getSuccessor(0) == To, Facts);
}

static bool blockConditions(BasicBlock *BB, DominatorTree &DT, BooleanFacts &Facts)
{
	BasicBlock *Target = BB;
	for (unsigned Depth = 0; BB && Depth < MaxValueDepth; Depth++) {
		for (Instruction &I : *BB)
			if (auto *Assume = dyn_cast<AssumeInst>(&I))
				if (!assumeBoolean(Assume->getArgOperand(0), true, Facts))
					return false;
		auto *Node = DT.getNode(BB);
		if (!Node || !Node->getIDom())
			return true;
		BasicBlock *Dom = Node->getIDom()->getBlock();
#if LLVM_VERSION_MAJOR >= 23
		auto *Branch = dyn_cast<CondBrInst>(Dom->getTerminator());
#else
		auto *Branch = dyn_cast<BranchInst>(Dom->getTerminator());
#endif
		if (Branch && Branch->getNumSuccessors() == 2 &&
		    Branch->getSuccessor(0) != Branch->getSuccessor(1)) {
			bool T = DT.dominates(BasicBlockEdge(Dom, Branch->getSuccessor(0)), Target);
			bool F = DT.dominates(BasicBlockEdge(Dom, Branch->getSuccessor(1)), Target);

			if (T != F && !assumeBoolean(Branch->getCondition(), T, Facts))
				return false;
		}
		BB = Dom;
	}
	return false;
}

static bool valueMayBeErrno(Value *V,
			    BasicBlock *BB,
			    LazyValueInfo &LVI,
			    DominatorTree &DT,
			    const SmallPtrSetImpl<BasicBlock *> &CleanBBs,
			    SmallPtrSetImpl<const Value *> &Seen,
			    const BooleanFacts &Facts,
			    bool RequireWitness,
			    unsigned Depth)
{
	if (!V || Depth == MaxValueDepth)
		return false;

	const DataLayout &DL = BB->getModule()->getDataLayout();

	if (isErrnoConstant(V, DL) || dominatedByIsErr(V, BB, DT))
		return true;

	if (!Seen.insert(V).second)
		return false;

	if (auto *Phi = dyn_cast<PHINode>(V)) {
		for (unsigned i = 0; i < Phi->getNumIncomingValues(); i++) {
			Value *Incoming = Phi->getIncomingValue(i);
			BasicBlock *Pred = Phi->getIncomingBlock(i);

			if (!CleanBBs.contains(Pred))
				continue;
			BooleanFacts IncomingFacts = Facts;
			if (!blockConditions(Pred, DT, IncomingFacts) ||
			    !assumeEdge(Pred, Phi->getParent(), IncomingFacts) ||
			    !conditionsConsistent(IncomingFacts, DL) ||
			    (RequireWitness && !selectConditionsFeasible(IncomingFacts, LVI, DT,
								  Pred->getTerminator())))
				continue;

			if (Incoming->getType()->isIntegerTy() &&
			    isErrnoRange(LVI.getConstantRangeOnEdge(Incoming, Pred, Phi->getParent()))) // why do we know the range here? Because of isIntegerTy()?
				return true;

			if (valueMayBeErrno(Incoming, Pred, LVI, DT, CleanBBs, Seen,
					    IncomingFacts, RequireWitness, Depth + 1))
				return true;
		}
	} else if (auto *Cast = dyn_cast<CastInst>(V)) {
		if (preservesErrnoCast(Cast->getOpcode(), Cast->getSrcTy(),
				       Cast->getDestTy(), DL) &&
		    (rangeAtUseIsErrno(Cast->getOperandUse(0), LVI) ||
		     valueMayBeErrno(Cast->getOperand(0), BB, LVI, DT, CleanBBs, Seen,
				     Facts, RequireWitness, Depth + 1)))
			return true;
	} else if (auto *Select = dyn_cast<SelectInst>(V)) {
		Value *Condition = Select->getCondition();
		ConstantRange Possible = LVI.getConstantRange(Condition, BB->getTerminator(), false);
		bool Known = false, Truth = false;

		Known = knownBoolean(Condition, Facts, Truth);
		if (Known || Possible.isSingleElement()) {
			if (!Known)
				Truth = !Possible.getSingleElement()->isZero();
			if (!Possible.contains(APInt(1, Truth))) {
				Seen.erase(V);
				return false;
			}
			bool Error = valueMayBeErrno(Select->getOperand(Truth ? 1 : 2), BB, LVI,
						DT, CleanBBs, Seen, Facts, RequireWitness, Depth + 1);
			Seen.erase(V);
			return Error;
		}
		for (unsigned Choice = 0; Choice < 2; Choice++) {
			bool TakeTrue = Choice == 0;
			if ((Known && Truth != TakeTrue) || !Possible.contains(APInt(1, TakeTrue)))
				continue;
			BooleanFacts SelectedFacts = Facts;
			if (!assumeBoolean(Condition, TakeTrue, SelectedFacts) ||
			    !selectConditionsFeasible(SelectedFacts, LVI, DT, BB->getTerminator()))
				continue;
			if (valueMayBeErrno(Select->getOperand(TakeTrue ? 1 : 2), BB, LVI,
					    DT, CleanBBs, Seen, SelectedFacts, true, Depth + 1))
				return true;
		}
	}
	Seen.erase(V);
	return false;
}


class CleanInstructions {
	DominatorTree &DT;
	DenseMap<const Instruction *, bool> PrivateWrites;

	bool privateDestination(const Value *Pointer, const Instruction &I)
	{
		auto It = PrivateWrites.find(&I);
		if (It != PrivateWrites.end())
			return It->second;
		auto *Allocation = dyn_cast<AllocaInst>(getUnderlyingObject(Pointer));
		bool Private = false;

		if (Allocation && Allocation->getFunction() == I.getFunction()) {
			// A later call may receive the initialized object. Only captures
			// that can precede this write make the write externally visible.
#if LLVM_VERSION_MAJOR >= 21
			Private = !PointerMayBeCapturedBefore(Allocation, true, &I, &DT,
							     true, 256);
#else
			Private = !PointerMayBeCapturedBefore(Allocation, true, true, &I,
								     &DT, true, 256);
#endif
		}
		PrivateWrites[&I] = Private;
		return Private;
	}

public:
	explicit CleanInstructions(DominatorTree &DT) : DT(DT) {}

	bool isClean(const Instruction &I)
	{
		if (auto *Store = dyn_cast<StoreInst>(&I))
			return !Store->isVolatile() && !Store->isAtomic() &&
			       privateDestination(Store->getPointerOperand(), I);
		if (auto *Memory = dyn_cast<MemIntrinsic>(&I))
			return !Memory->isVolatile() &&
			       privateDestination(Memory->getRawDest(), I);
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
};

static bool cleanBB(BasicBlock *BB, CleanInstructions &Clean)
{
	for (Instruction &I : *BB) {
		if (!Clean.isClean(I))
			return false;
	}
	return true;
}

static bool functionHasCleanErrnoPath(Function &F, LazyValueInfo &LVI,
				     DominatorTree &DT, CleanInstructions &Clean)
{
	SmallPtrSet<BasicBlock *, 32> CleanEntries;
	SmallPtrSet<BasicBlock *, 32> CleanBBs;
	SmallVector<BasicBlock *, 32> Worklist;

	// build the list of "clean" BBs
	CleanEntries.insert(&F.getEntryBlock());
	Worklist.push_back(&F.getEntryBlock());
	while (!Worklist.empty()) {
		BasicBlock *BB = Worklist.pop_back_val();
		if (!cleanBB(BB, Clean))
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

		SmallPtrSet<const Value *, 32> Seen;
		BooleanFacts Facts;
		if (!blockConditions(BB, DT, Facts) ||
		    !conditionsConsistent(Facts, F.getParent()->getDataLayout()))
			continue;
		if (rangeAtUseIsErrno(Return->getOperandUse(0), LVI) ||
		    valueMayBeErrno(Return->getReturnValue(), BB, LVI, DT, CleanBBs, Seen, Facts, false, 0))
			return true;
	}
	return false;
}

// Propagation deliberately ignores cleanup side effects. Only returned values
// and explicit error reports matter here; prefix cleanliness is independent.
struct ErrorMap {
	unsigned Kind = FMODRET_ERROR_UNKNOWN;
	int Replacement = 0;

	bool operator==(const ErrorMap &Other) const
	{
		return Kind == Other.Kind && Replacement == Other.Replacement;
	}
};

struct ErrorCase {
	int First, Last;
	ErrorMap Map;
};

struct CallbackBinding {
	Function *Fn;
	unsigned Argument, SourceParam;
};

struct CallDescription {
	Function *Callee;
	unsigned Flags;
	SmallVector<ErrorCase, 4> Cases;
	unsigned CalleeParam;
	SmallVector<CallbackBinding, 2> Bindings;
};

struct FunctionDescription {
	Function *Fn;
	unsigned Flags;
	SmallVector<CallDescription, 8> Calls;
	SmallVector<unsigned, 8> Params;
};

using Predecessors = DenseMap<const BasicBlock *, const BasicBlock *>;

static ErrorMap evaluateValue(const Value *V, const CallBase &Call, int Error,
			      const Predecessors &Preds, unsigned Depth = 0);

static bool preservesErrnoCast(unsigned Opcode, Type *Src, Type *Dst,
			       const DataLayout &DL)
{
	if (Src->isIntegerTy() && Dst->isIntegerTy())
		return (Opcode == Instruction::SExt || Opcode == Instruction::Trunc ||
			Opcode == Instruction::BitCast) &&
		       Src->getIntegerBitWidth() >= 32 && Dst->getIntegerBitWidth() >= 32;
	if (Opcode == Instruction::IntToPtr && Src->isIntegerTy() &&
	    Dst->isPointerTy() && !DL.isNonIntegralPointerType(Dst)) {
		unsigned Bits = DL.getPointerTypeSizeInBits(Dst);

		// inttoptr zero-extends a narrower integer, losing a negative errno.
		return Bits >= 32 && Src->getIntegerBitWidth() >= Bits;
	}
	if (Opcode == Instruction::PtrToInt && Src->isPointerTy() &&
	    Dst->isIntegerTy() && !DL.isNonIntegralPointerType(Src)) {
		unsigned Bits = Dst->getIntegerBitWidth();

		return Bits >= 32 && Bits <= DL.getPointerTypeSizeInBits(Src);
	}
	return Opcode == Instruction::BitCast && Src->isPointerTy() &&
	       Dst->isPointerTy() && Src == Dst;
}

static bool evaluateCondition(const Value *V, const CallBase &Call, int Error,
			      const Predecessors &Preds, bool &Truth,
			      unsigned Depth)
{
	if (auto *C = dyn_cast<ConstantInt>(V)) {
		Truth = !C->isZero();
		return true;
	}
	auto *Cmp = dyn_cast<ICmpInst>(V);
	if (Depth >= MaxValueDepth)
		return false;
	if (auto *Op = dyn_cast<BinaryOperator>(V); Op && Op->getType()->isIntegerTy(1)) {
		unsigned Opcode = Op->getOpcode();
		if (Opcode == Instruction::And || Opcode == Instruction::Or ||
		    Opcode == Instruction::Xor) {
			bool L = false, R = false;
			bool KnownL = evaluateCondition(Op->getOperand(0), Call, Error,
						Preds, L, Depth + 1);
			bool KnownR = evaluateCondition(Op->getOperand(1), Call, Error,
						Preds, R, Depth + 1);

			if (Opcode == Instruction::Or && ((KnownL && L) || (KnownR && R))) {
				Truth = true;
				return true;
			}
			if (Opcode == Instruction::And && ((KnownL && !L) || (KnownR && !R))) {
				Truth = false;
				return true;
			}
			if (KnownL && KnownR) {
				Truth = Opcode == Instruction::Or ? L || R :
					Opcode == Instruction::And ? L && R : L != R;
				return true;
			}
			return false;
		}
	}
	if (!Cmp) {
		// Cleanup can use a boolean PHI/select to choose return or loop.
		// Resolve it on this path before considering both successors.
		auto Map = evaluateValue(V, Call, Error, Preds, Depth + 1);
		if (Map.Kind != FMODRET_ERROR_CONSTANT)
			return false;
		Truth = Map.Replacement != 0;
		return true;
	}
	Type *Ty = Cmp->getOperand(0)->getType();
	const DataLayout &DL = Call.getModule()->getDataLayout();
	if (!Ty->isIntegerTy() &&
	    (!Ty->isPointerTy() || DL.isNonIntegralPointerType(Ty)))
		return false;
	auto L = evaluateValue(Cmp->getOperand(0), Call, Error, Preds, Depth + 1);
	auto R = evaluateValue(Cmp->getOperand(1), Call, Error, Preds, Depth + 1);
	if (!L.Kind || !R.Kind)
		return false;
	unsigned Width = Ty->isPointerTy() ? DL.getPointerTypeSizeInBits(Ty) :
					   Ty->getIntegerBitWidth();
	if (Width != 32 && Width != 64)
		return false;
	APInt Left(Width, L.Kind == FMODRET_ERROR_IDENTITY ? Error : L.Replacement, true);
	APInt Right(Width, R.Kind == FMODRET_ERROR_IDENTITY ? Error : R.Replacement, true);
	Truth = ICmpInst::compare(Left, Right, Cmp->getPredicate());
	return true;
}

static ErrorMap evaluateValue(const Value *V, const CallBase &Call, int Error,
			      const Predecessors &Preds, unsigned Depth)
{
	if (!V || Depth >= MaxValueDepth)
		return {};
	if (V == &Call)
		return {FMODRET_ERROR_IDENTITY, 0};
	if (isa<ConstantPointerNull>(V))
		return {FMODRET_ERROR_CONSTANT, 0};
	if (auto *C = dyn_cast<ConstantInt>(V)) {
		if (C->getBitWidth() <= 64 && C->getValue().isSignedIntN(32))
			return {FMODRET_ERROR_CONSTANT, (int)C->getSExtValue()};
		return {};
	}
	if (auto *Cast = dyn_cast<CastInst>(V)) {
		if (preservesErrnoCast(Cast->getOpcode(), Cast->getSrcTy(), Cast->getDestTy(),
				       Call.getModule()->getDataLayout()))
			return evaluateValue(Cast->getOperand(0), Call, Error, Preds, Depth + 1);
		return {};
	}
	if (auto *Expr = dyn_cast<ConstantExpr>(V); Expr && Expr->isCast()) {
		if (preservesErrnoCast(Expr->getOpcode(), Expr->getOperand(0)->getType(),
				       Expr->getType(), Call.getModule()->getDataLayout()))
			return evaluateValue(Expr->getOperand(0), Call, Error, Preds, Depth + 1);
		return {};
	}
	if (auto *Phi = dyn_cast<PHINode>(V)) {
		auto It = Preds.find(Phi->getParent());
		if (It == Preds.end())
			return {};
		int I = Phi->getBasicBlockIndex(It->second);
		return I < 0 ? ErrorMap{} :
			evaluateValue(Phi->getIncomingValue(I), Call, Error, Preds, Depth + 1);
	}
	if (auto *Select = dyn_cast<SelectInst>(V)) {
		bool Truth;
		if (evaluateCondition(Select->getCondition(), Call, Error, Preds, Truth, Depth + 1))
			return evaluateValue(Select->getOperand(Truth ? 1 : 2), Call, Error,
					     Preds, Depth + 1);
		auto L = evaluateValue(Select->getTrueValue(), Call, Error, Preds, Depth + 1);
		auto R = evaluateValue(Select->getFalseValue(), Call, Error, Preds, Depth + 1);
		return L == R ? L : ErrorMap{};
	}
	return {};
}

static ErrorMap traceError(const CallBase &Call, int Error)
{
	struct Path {
		const BasicBlock *BB;
		Predecessors Preds;
	};
	SmallVector<Path, 8> Work;
	Path Initial;
	Initial.BB = Call.getParent();
	Work.push_back(std::move(Initial));
	ErrorMap Result;
	bool HaveResult = false;
	unsigned Budget = 256;

	while (!Work.empty()) {
		if (!Budget--)
			return {};
		auto P = Work.pop_back_val();
		const Instruction *Term = P.BB->getTerminator();
		if (auto *Ret = dyn_cast<ReturnInst>(Term)) {
			auto Map = evaluateValue(Ret->getReturnValue(), Call, Error, P.Preds);
			if (Map.Kind == FMODRET_ERROR_CONSTANT &&
			    (Map.Replacement >= 0 || Map.Replacement < -MaxErrno))
				return {};
			if (!Map.Kind || (HaveResult && !(Result == Map)))
				return {};
			Result = Map;
			HaveResult = true;
			continue;
		}
		SmallVector<const BasicBlock *, 4> Next;
#if LLVM_VERSION_MAJOR >= 23
		if (auto *Br = dyn_cast<CondBrInst>(Term)) {
#else
		if (auto *Br = dyn_cast<BranchInst>(Term); Br && Br->isConditional()) {
#endif
			bool Truth;
			if (evaluateCondition(Br->getCondition(), Call, Error, P.Preds, Truth, 0))
				Next.push_back(Br->getSuccessor(Truth ? 0 : 1));
			else {
				Next.push_back(Br->getSuccessor(0));
				Next.push_back(Br->getSuccessor(1));
			}
		} else if (auto *Sw = dyn_cast<SwitchInst>(Term)) {
			auto Map = evaluateValue(Sw->getCondition(), Call, Error, P.Preds);
			if (Map.Kind) {
				int N = Map.Kind == FMODRET_ERROR_IDENTITY ? Error : Map.Replacement;
				const BasicBlock *Dest = Sw->getDefaultDest();
				for (auto C : Sw->cases())
					if (C.getCaseValue()->getValue() == APInt(Sw->getCondition()->getType()->getIntegerBitWidth(), N, true))
						Dest = C.getCaseSuccessor();
				Next.push_back(Dest);
			} else {
				for (const BasicBlock *Succ : successors(P.BB))
					Next.push_back(Succ);
			}
#if LLVM_VERSION_MAJOR >= 23
		} else if (isa<UncondBrInst>(Term)) {
#else
		} else if (isa<BranchInst>(Term) && Term->getNumSuccessors() == 1) {
#endif
			Next.push_back(Term->getSuccessor(0));
		} else if (isa<CallBrInst>(Term)) {
			// asm goto may take the fallthrough or any declared label.
			for (const BasicBlock *Succ : successors(P.BB))
				Next.push_back(Succ);
		} else {
			// Includes unreachable, exceptional exits and indirect branches.
			return {};
		}
		for (const BasicBlock *Succ : Next) {
			if (Succ == Call.getParent() || P.Preds.count(Succ))
				return {}; // No proof of termination for a cycle.
			auto Q = P;
			Q.Preds[Succ] = P.BB;
			Q.BB = Succ;
			Work.push_back(std::move(Q));
		}
	}
	return HaveResult ? Result : ErrorMap{};
}

static SmallVector<ErrorCase, 4> describeErrors(const CallBase &Call)
{
	SmallVector<ErrorCase, 4> Cases;
	SmallVector<int, 16> Cuts = {-MaxErrno, 0};
	Type *Ty = Call.getType();
	const DataLayout &DL = Call.getModule()->getDataLayout();
	bool Pointer = Ty->isPointerTy() && !DL.isNonIntegralPointerType(Ty) &&
		(DL.getPointerTypeSizeInBits(Ty) == 32 || DL.getPointerTypeSizeInBits(Ty) == 64);
	if (!Ty->isIntegerTy(32) && !Ty->isIntegerTy(64) && !Pointer)
		return {{-MaxErrno, -1, {}}};
	// Only identity and constant expressions are evaluated. Splitting at every
	// comparison/switch constant makes their truth invariant in each interval.
	auto AddCut = [&](const ConstantInt *C) {
		if (!C || C->getBitWidth() > 64 || !C->getValue().isSignedIntN(32))
			return;
		int64_t N = C->getSExtValue();
		if (N >= -MaxErrno && N < 0) {
			Cuts.push_back(N);
			Cuts.push_back(N + 1);
		}
	};
	// Include constants feeding PHIs/selects too: a comparison threshold
	// need not occur directly as an ICmp operand.
	for (const BasicBlock &BB : *Call.getFunction())
		for (const Instruction &I : BB) {
			for (const Use &U : I.operands())
				AddCut(comparisonThreshold(U.get()));
		}
	llvm::sort(Cuts);
	Cuts.erase(std::unique(Cuts.begin(), Cuts.end()), Cuts.end());
	if (Cuts.size() > 128)
		return {{-MaxErrno, -1, {}}};
	for (unsigned I = 1; I < Cuts.size(); I++) {
		ErrorCase C{Cuts[I - 1], Cuts[I] - 1,
			    traceError(Call, Cuts[I - 1])};
		if (!Cases.empty() && Cases.back().Map == C.Map)
			Cases.back().Last = C.Last;
		else
			Cases.push_back(C);
	}
	return Cases;
}

static bool isDispatchTable(StringRef Name)
{
	return Name == "sys_call_table" || Name == "compat_sys_call_table" ||
	       Name == "ia32_sys_call_table" || Name == "x32_sys_call_table";
}

static bool assemblyReferences(StringRef Assembly, StringRef Name)
{
	if (Name.empty())
		return false;
	auto SymbolChar = [](char C) {
		return (C >= 'a' && C <= 'z') || (C >= 'A' && C <= 'Z') ||
		       (C >= '0' && C <= '9') || C == '_' || C == '.' || C == '$';
	};
	for (size_t Pos = Assembly.find(Name); Pos != StringRef::npos;
	     Pos = Assembly.find(Name, Pos + Name.size())) {
		size_t End = Pos + Name.size();

		if ((!Pos || !SymbolChar(Assembly[Pos - 1])) &&
		    (End == Assembly.size() || !SymbolChar(Assembly[End])))
			return true;
	}
	return false;
}

// EXPORT_SYMBOL() emits a record in ".export_symbol" which names the function.
// It describes the export and is not a use of the address: remember the name
// and take the record out of the text searched for references. A record of an
// unknown shape stays, and its reference counts.
static void takeExports(std::string &Assembly, StringSet<> &Exported)
{
	static constexpr StringLiteral Section = "\".export_symbol\"";
	static constexpr StringLiteral Label = "__export_symbol_";
	static constexpr StringLiteral End = ".previous";
	size_t Pos = 0;

	while ((Pos = Assembly.find(Section, Pos)) != std::string::npos) {
		size_t Begin = Assembly.rfind(".section", Pos);
		size_t Stop = Assembly.find(End, Pos);
		size_t Name = StringRef::npos, Colon = StringRef::npos;
		StringRef Record;

		if (Begin != std::string::npos && Stop != std::string::npos) {
			Stop += End.size();
			Record = StringRef(Assembly).slice(Begin, Stop);
			Name = Record.find(Label);
			if (Name != StringRef::npos)
				Colon = Record.find(':', Name);
		}
		if (Colon == StringRef::npos) {
			Pos += Section.size();
			continue;
		}
		Exported.insert(Record.slice(Name + Label.size(), Colon));
		Assembly.erase(Begin, Stop - Begin);
		Pos = Begin;
	}
}

static const Value *callbackValue(const Value *V)
{
	for (unsigned Depth = 0; Depth < MaxValueDepth; Depth++) {
		if (auto *Cast = dyn_cast<BitCastInst>(V)) {
			V = Cast->getOperand(0);
			continue;
		}
		if (auto *Expr = dyn_cast<ConstantExpr>(V);
		    Expr && Expr->getOpcode() == Instruction::BitCast) {
			V = Expr->getOperand(0);
			continue;
		}
		return V;
	}
	return nullptr;
}

static bool modelledCallbackArgument(const Use &U)
{
	auto *Call = dyn_cast<CallInst>(U.getUser());
	if (!Call || !Call->isArgOperand(&U))
		return false;
	auto *Callee = dyn_cast_or_null<Function>(callbackValue(Call->getCalledOperand()));
	const Value *V = callbackValue(U.get());
	unsigned Index = Call->getArgOperandNo(&U);
	return Callee && !Callee->isIntrinsic() && Index < Callee->arg_size() &&
	       Callee->getArg(Index)->getType()->isPointerTy() && V &&
	       (isa<Function>(V) || (isa<Argument>(V) && V->getType()->isPointerTy()));
}

static bool closedCallbackParameter(const Value *V,
				    SmallPtrSetImpl<const Value *> &Seen,
				    unsigned Depth = 0)
{
	if (Depth >= MaxValueDepth)
		return false;
	if (!Seen.insert(V).second)
		return true;
	for (const Use &U : V->uses()) {
		const User *User = U.getUser();
		if (auto *Call = dyn_cast<CallInst>(User)) {
			if ((&U == &Call->getCalledOperandUse() &&
			     isa_and_nonnull<Argument>(callbackValue(U.get()))) ||
			    modelledCallbackArgument(U))
				continue;
			return false;
		}
		if (isa<BitCastInst>(User)) {
			if (!closedCallbackParameter(User, Seen, Depth + 1))
				return false;
			continue;
		}
		if (auto *Cmp = dyn_cast<ICmpInst>(User)) {
			if (Cmp->isEquality() &&
			    isa<ConstantPointerNull>(Cmp->getOperand(1 - U.getOperandNo())))
				continue;
		}
		return false;
	}
	return true;
}

static bool addressEscapes(const Value *V, SmallPtrSetImpl<const Value *> &Seen)
{
	if (!Seen.insert(V).second)
		return false;
	for (const Use &U : V->uses()) {
		const User *User = U.getUser();
		if (auto *Call = dyn_cast<CallBase>(User)) {
			if (&U == &Call->getCalledOperandUse())
				continue;
			if (modelledCallbackArgument(U))
				continue;
			return true;
		}
		if (auto *GV = dyn_cast<GlobalVariable>(User)) {
			// These references describe the function rather than calling it.
			if (isDispatchTable(GV->getName()) ||
			    GV->getSection() == "_error_injection_whitelist" ||
			    GV->getName() == "llvm.used" ||
			    GV->getName() == "llvm.compiler.used" ||
			    GV->getSection() == ".discard.addressable" ||
			    GV->getSection() == ".discard.gendwarfksyms")
				continue;
			return true;
		}
		if ((isa<Constant>(User) && !isa<GlobalValue>(User)) || isa<BitCastInst>(User)) {
			if (addressEscapes(User, Seen))
				return true;
			continue;
		}
		return true;
	}
	return false;
}

// Trusted resource-failure contracts, not a claim that allocator tracing and
// accounting are side-effect-free. NULL leaves no allocation owned by the caller.
static bool nullFailureAllocator(const CallBase &Call, const Function *F)
{
	const DataLayout &DL = Call.getModule()->getDataLayout();
	if (!F || !isa<CallInst>(Call) || !F->hasExternalLinkage() ||
	    F->isWeakForLinker() || F->isVarArg() ||
	    !isErrorPointerType(F->getReturnType(), DL) ||
	    Call.hasRetAttr(Attribute::NonNull))
		return false;
	auto *Ty = F->getFunctionType();
	unsigned N = Ty->getNumParams();
	unsigned Word = DL.getPointerTypeSizeInBits(F->getReturnType());
	auto Size = [&](unsigned I) { return I < N && Ty->getParamType(I)->isIntegerTy(Word); };
	auto Int = [&](unsigned I) { return I < N && Ty->getParamType(I)->isIntegerTy(32); };
	auto Ptr = [&](unsigned I) { return I < N && Ty->getParamType(I)->isPointerTy(); };
	StringRef Name = F->getName();

	if (Call.arg_size() != N || Call.getType() != Ty->getReturnType())
		return false;
	for (unsigned I = 0; I < N; I++)
		if (Call.getArgOperand(I)->getType() != Ty->getParamType(I))
			return false;
	if (Name == "__kmalloc_cache_noprof")
		return N == 3 && Ptr(0) && Int(1) && Size(2);
	if (Name == "__kmalloc_cache_node_noprof")
		return N == 4 && Ptr(0) && Int(1) && Int(2) && Size(3);
	if (Name == "__kmalloc_large_noprof")
		return N == 2 && Size(0) && Int(1);
	if (Name == "__kmalloc_large_node_noprof")
		return N == 3 && Size(0) && Int(1) && Int(2);
	if (Name == "kmem_cache_alloc_noprof")
		return N == 2 && Ptr(0) && Int(1);
	if (Name == "kmem_cache_alloc_node_noprof")
		return N == 3 && Ptr(0) && Int(1) && Int(2);

	unsigned Tail;
	bool Buckets;
	if (Name == "__kmalloc_noprof") {
		Tail = 1;
		Buckets = false;
	} else if (Name == "__kmalloc_node_noprof") {
		Tail = 2;
		Buckets = true;
	} else if (Name == "__kvmalloc_node_noprof") {
		Tail = 3;
		Buckets = true;
	} else {
		return false;
	}
	if (N < 1 + Tail || N > 3 + Tail || !Size(0))
		return false;
	if (!Int(N - (Tail == 1 ? 1 : 2)) ||
	    (Tail >= 2 && !Int(N - 1)) || (Tail == 3 && !Size(N - 3)))
		return false;
	unsigned I = 1, End = N - Tail;
	if (I < End && Buckets && Ptr(I))
		I++;
	// Optional kmalloc partition token, lowered to one target word by the ABI.
	if (I < End && Size(I))
		I++;
	return I == End;
}

static CallDescription describeCall(CallBase &Call, bool CleanPrefix)
{
	auto *Callee = dyn_cast<Function>(Call.getCalledOperand()->stripPointerCasts());
	if (Callee && Callee->isIntrinsic())
		Callee = nullptr;
	auto *Param = dyn_cast_or_null<Argument>(callbackValue(Call.getCalledOperand()));
	unsigned Index = Param ? Param->getArgNo() : FMODRET_NO_PARAM;
	CallDescription D{Callee, CleanPrefix ? FMODRET_CALL_CLEAN_PREFIX : 0U,
			  describeErrors(Call), Index, {}};
	if (Call.getType()->isIntegerTy(32))
		D.Flags |= FMODRET_CALL_RESULT32;
	else if (Call.getType()->isIntegerTy(64))
		D.Flags |= FMODRET_CALL_RESULT64;
	else if (Call.getType()->isPointerTy())
		D.Flags |= FMODRET_CALL_RESULT_PTR;
	if (nullFailureAllocator(Call, Callee)) {
		D.Flags |= FMODRET_CALL_NULL_ALLOCATOR;
		ErrorMap Null = traceError(Call, 0);

		if (Null.Kind == FMODRET_ERROR_CONSTANT &&
		    Null.Replacement >= -MaxErrno && Null.Replacement < 0)
			D.Flags |= FMODRET_CALL_NULL_ERROR;
	}
	for (unsigned I = 0; I < Call.arg_size(); I++) {
		if (!modelledCallbackArgument(Call.getArgOperandUse(I)))
			continue;
		const Value *V = callbackValue(Call.getArgOperand(I));
		if (auto *F = dyn_cast_or_null<Function>(V))
			D.Bindings.push_back({const_cast<Function *>(F), I, FMODRET_NO_PARAM});
		else if (auto *A = dyn_cast_or_null<Argument>(V); A && A->getType()->isPointerTy())
			D.Bindings.push_back({nullptr, I, A->getArgNo()});
	}
	return D;
}

static void findCleanPrefixes(Function &F, SmallPtrSetImpl<const CallBase *> &Prefixes,
			      CleanInstructions &Clean)
{
	SmallPtrSet<BasicBlock *, 32> Seen;
	SmallVector<BasicBlock *, 16> Work{&F.getEntryBlock()};
	Seen.insert(&F.getEntryBlock());
	while (!Work.empty()) {
		BasicBlock *BB = Work.pop_back_val();
		bool Dirty = false;
		for (Instruction &I : *BB) {
			if (auto *Call = dyn_cast<CallBase>(&I))
				Prefixes.insert(Call);
			if (!Clean.isClean(I)) {
				Dirty = true;
				break;
			}
		}
		if (!Dirty)
			for (BasicBlock *Succ : successors(BB))
				if (Seen.insert(Succ).second)
					Work.push_back(Succ);
	}
}

static void emitDescriptions(Module &M, ArrayRef<FunctionDescription> Functions)
{
	LLVMContext &C = M.getContext();
	auto *I32 = Type::getInt32Ty(C);
	auto *Ptr = PointerType::getUnqual(C);
	auto N = [&](unsigned V) -> Constant * { return ConstantInt::get(I32, V); };
	auto Struct = [&](ArrayRef<Constant *> Fields) -> Constant * {
		return ConstantStruct::getAnon(C, Fields, true);
	};
	unsigned PtrSize = M.getDataLayout().getPointerSize();
	for (const auto &F : Functions) {
		SmallVector<Constant *, 16> Calls;
		SmallVector<Constant *, 8> Params;
		for (unsigned Flags : F.Params)
			Params.push_back(Struct({N(Flags), N(0)}));
		unsigned Size = FMODRET_META_HEADER_SIZE(PtrSize) +
			       Params.size() * FMODRET_META_PARAM_SIZE;
		for (const auto &Call : F.Calls) {
			SmallVector<Constant *, 8> Cases;
			SmallVector<Constant *, 4> Bindings;
			for (const auto &E : Call.Cases)
				Cases.push_back(Struct({N(E.First), N(E.Last), N(E.Map.Kind), N(E.Map.Replacement)}));
			Constant *Callee = Call.Callee ? (Constant *)Call.Callee : ConstantPointerNull::get(Ptr);
			for (const auto &B : Call.Bindings) {
				Constant *Fn = B.Fn ? (Constant *)B.Fn : ConstantPointerNull::get(Ptr);
				Bindings.push_back(Struct({Fn, N(B.Argument), N(B.SourceParam)}));
			}
			Calls.push_back(Struct({Callee, N(Call.Flags), N(Cases.size()),
				N(Call.CalleeParam), N(Bindings.size()), Struct(Cases), Struct(Bindings)}));
			Size += FMODRET_META_CALL_SIZE(PtrSize) + Cases.size() * FMODRET_META_CASE_SIZE +
				Bindings.size() * FMODRET_META_BINDING_SIZE(PtrSize);
		}
		Constant *Record = Struct({N(FMODRET_META_MAGIC), N(FMODRET_META_VERSION),
			N(Size), N(F.Flags), F.Fn, N(Calls.size()), N(Params.size()),
			Struct(Params), Struct(Calls)});
		auto *GV = new GlobalVariable(M, Record->getType(), true, GlobalValue::PrivateLinkage,
					      Record, "fmodret.function." + F.Fn->getName());
		GV->setSection(".BTF_fmodret_candidates");
		GV->setAlignment(M.getDataLayout().getPointerABIAlignment(0));
		appendToUsed(M, {GV});
	}
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

		std::string Assembly;
#if LLVM_VERSION_MAJOR >= 23
		for (const auto &Fragment : M.getModuleInlineAsm())
			Assembly += Fragment.Asm;
#else
		Assembly = M.getModuleInlineAsm();
#endif
		for (Function &F : M)
			for (BasicBlock &BB : F)
				for (Instruction &I : BB)
					if (auto *Call = dyn_cast<CallBase>(&I))
						if (auto *Asm = dyn_cast<InlineAsm>(Call->getCalledOperand()))
							Assembly += (Twine("\n") + Asm->getAsmString()).str();
		StringSet<> Exported;
		takeExports(Assembly, Exported);
		SmallVector<FunctionDescription, 32> Descriptions;
		auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

		// Finish collecting every fact before introducing metadata references.
		for (Function &F : M) {
			if (F.isIntrinsic() || F.hasAvailableExternallyLinkage() ||
			    (F.isDeclaration() && F.use_empty()))
				continue;
			bool Defined = !F.isDeclaration();
			SmallPtrSet<const Value *, 32> Seen;
			unsigned Flags = Defined ? FMODRET_FN_DEFINED : 0;
			if (F.hasAddressTaken())
				Flags |= FMODRET_FN_ADDRESS_TAKEN;
			if (addressEscapes(&F, Seen) || assemblyReferences(Assembly, F.getName()))
				Flags |= FMODRET_FN_ESCAPED;
			if (!Defined && !(Flags & (FMODRET_FN_ESCAPED | FMODRET_FN_ADDRESS_TAKEN)))
				continue;
			if (Defined && Exported.contains(F.getName()))
				Flags |= FMODRET_FN_EXPORTED;
			if (F.hasLocalLinkage())
				Flags |= FMODRET_FN_LOCAL;
			if (F.isWeakForLinker())
				Flags |= FMODRET_FN_WEAK;
			if (F.getReturnType()->isIntegerTy(64))
				Flags |= FMODRET_FN_RET64;
			if (F.getReturnType()->isIntegerTy(32) || F.getReturnType()->isIntegerTy(64))
				Flags |= FMODRET_FN_INTEGER;
			if (isErrorPointerType(F.getReturnType(), M.getDataLayout()))
				Flags |= FMODRET_FN_ERRPTR;
			std::unique_ptr<CleanInstructions> Clean;
			if (Defined)
				Clean = std::make_unique<CleanInstructions>(
					FAM.getResult<DominatorTreeAnalysis>(F));
			if (Defined && (Flags & (FMODRET_FN_INTEGER | FMODRET_FN_ERRPTR))) {
				auto &LVI = FAM.getResult<LazyValueAnalysis>(F);
				auto &DT = FAM.getResult<DominatorTreeAnalysis>(F);

				if (functionHasCleanErrnoPath(F, LVI, DT, *Clean))
					Flags |= FMODRET_FN_CLEAN_SEED;
			}
			FunctionDescription D{&F, Flags, {}, {}};
			if (Defined) {
				for (Argument &A : F.args()) {
					SmallPtrSet<const Value *, 32> Uses;
					D.Params.push_back(A.getType()->isPointerTy() &&
						closedCallbackParameter(&A, Uses) ? FMODRET_PARAM_CLOSED : 0U);
				}
				SmallPtrSet<const CallBase *, 32> Prefixes;
				findCleanPrefixes(F, Prefixes, *Clean);
				for (BasicBlock &BB : F)
					for (Instruction &I : BB)
						if (auto *Call = dyn_cast<CallBase>(&I)) {
							D.Calls.push_back(describeCall(*Call, Prefixes.contains(Call)));
						}
			}
			Descriptions.push_back(std::move(D));
		}
		if (Descriptions.empty())
			return PreservedAnalyses::all();
		emitDescriptions(M, Descriptions);
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
