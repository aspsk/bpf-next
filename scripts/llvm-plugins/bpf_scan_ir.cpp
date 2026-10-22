// SPDX-License-Identifier: GPL-2.0-only
/* bpf_scan_ir: optimizer-last LLVM IR analysis for BPF. */

#include "fmodret_metadata.h"

#include <algorithm>
#include "llvm/ADT/DenseMap.h"
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

static bool conditionImpliesIsErr(Value *Condition, bool Truth, const Value *Pointer)
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

static bool dominatedByIsErr(const Value *V, BasicBlock *BB, DominatorTree &DT)
{
	const Value *Pointer = convertedPointer(V);

	if (!Pointer)
		return false;

	while (BB) {
		BasicBlock *Dom = DT.getNode(BB)->getIDom() ?
			DT.getNode(BB)->getIDom()->getBlock() : nullptr;
#if LLVM_VERSION_MAJOR >= 24
		auto *Branch = Dom ? dyn_cast<CondBrInst>(Dom->getTerminator()) : nullptr;
#else
		auto *Branch = Dom ? dyn_cast<BranchInst>(Dom->getTerminator()) : nullptr;
#endif
		bool TruePath, FalsePath;

		if (!Dom)
			break;
		if (!Branch || Branch->getNumSuccessors() != 2) {
			BB = Dom;
			continue;
		}
		TruePath = DT.dominates(Branch->getSuccessor(0), BB);
		FalsePath = DT.dominates(Branch->getSuccessor(1), BB);
		if (TruePath != FalsePath &&
		    conditionImpliesIsErr(Branch->getCondition(), TruePath, Pointer))
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

static bool isErrnoConstant(const Value *V)
{
	auto *C = dyn_cast<ConstantInt>(V);
	int64_t N;

	if (!C || (C->getBitWidth() != 32 && C->getBitWidth() != 64))
		return false;

	N = C->getSExtValue();
	return N >= -MaxErrno && N < 0;
}

static bool valueMayBeErrno(Value *V,
			    BasicBlock *BB,
			    LazyValueInfo &LVI,
			    DominatorTree &DT,
			    const SmallPtrSetImpl<BasicBlock *> &CleanBBs,
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
		for (unsigned i = 0; i < Phi->getNumIncomingValues(); i++) {
			Value *Incoming = Phi->getIncomingValue(i);
			BasicBlock *Pred = Phi->getIncomingBlock(i);

			if (!CleanBBs.contains(Pred))
				continue;

			if (Incoming->getType()->isIntegerTy() &&
			    isErrnoRange(LVI.getConstantRangeOnEdge(Incoming, Pred, Phi->getParent()))) // why do we know the range here? Because of isIntegerTy()?
				return true;

			if (valueMayBeErrno(Incoming, Pred, LVI, DT, CleanBBs, Seen, Depth + 1))
				return true;
		}
	} else if (auto *Cast = dyn_cast<CastInst>(V)) {
		// Zero extension does not preserve a negative bit pattern
		if (!isa<ZExtInst>(Cast) &&
		    (rangeAtUseIsErrno(Cast->getOperandUse(0), LVI) ||
		     valueMayBeErrno(Cast->getOperand(0), BB, LVI, DT, CleanBBs, Seen, Depth + 1)))
			return true;
	}
	Seen.erase(V);
	return false;
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

static bool functionHasCleanErrnoPath(Function &F, LazyValueInfo &LVI, DominatorTree &DT)
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

		SmallPtrSet<const Value *, 32> Seen;
		if (rangeAtUseIsErrno(Return->getOperandUse(0), LVI) ||
		    valueMayBeErrno(Return->getReturnValue(), BB, LVI, DT, CleanBBs, Seen, 0))
			return true;
	}
	return false;
}

// Propagation deliberately ignores cleanup side effects. Only returned values
// and control flow matter here; prefix cleanliness is collected independently.
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

struct CallDescription {
	Function *Callee;
	unsigned Flags;
	SmallVector<ErrorCase, 4> Cases;
};

struct FunctionDescription {
	Function *Fn;
	unsigned Flags;
	SmallVector<CallDescription, 8> Calls;
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
#if LLVM_VERSION_MAJOR >= 24
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
		} else if (Term->getNumSuccessors() == 1 &&
			   Term->getOpcode() == Instruction::Br) {
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
		for (const Instruction &I : BB)
			for (const Use &U : I.operands())
				AddCut(comparisonThreshold(U.get()));
	llvm::sort(Cuts);
	Cuts.erase(std::unique(Cuts.begin(), Cuts.end()), Cuts.end());
	if (Cuts.size() > 128)
		return {{-MaxErrno, -1, {}}};
	for (unsigned I = 1; I < Cuts.size(); I++) {
		ErrorCase C{Cuts[I - 1], Cuts[I] - 1, traceError(Call, Cuts[I - 1])};
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

static bool addressEscapes(const Value *V, SmallPtrSetImpl<const Value *> &Seen)
{
	if (!Seen.insert(V).second)
		return false;
	for (const Use &U : V->uses()) {
		const User *User = U.getUser();
		if (auto *Call = dyn_cast<CallBase>(User)) {
			if (&U == &Call->getCalledOperandUse())
				continue;
			return true;
		}
		if (auto *GV = dyn_cast<GlobalVariable>(User)) {
			// These references describe the function rather than calling it.
			if (isDispatchTable(GV->getName()) ||
			    GV->getSection() == "_error_injection_whitelist")
				continue;
			return true;
		}
		if (isa<Constant>(User) && !isa<GlobalValue>(User)) {
			if (addressEscapes(User, Seen))
				return true;
			continue;
		}
		return true;
	}
	return false;
}

static void findCleanPrefixes(Function &F, SmallPtrSetImpl<const CallBase *> &Clean)
{
	SmallPtrSet<BasicBlock *, 32> Seen;
	SmallVector<BasicBlock *, 16> Work{&F.getEntryBlock()};
	Seen.insert(&F.getEntryBlock());
	while (!Work.empty()) {
		BasicBlock *BB = Work.pop_back_val();
		bool Dirty = false;
		for (Instruction &I : *BB) {
			if (auto *Call = dyn_cast<CallBase>(&I))
				Clean.insert(Call);
			if (!isCleanInstruction(I)) {
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
		unsigned Size = FMODRET_META_HEADER_SIZE(PtrSize);
		for (const auto &Call : F.Calls) {
			SmallVector<Constant *, 8> Cases;
			for (const auto &E : Call.Cases)
				Cases.push_back(Struct({N(E.First), N(E.Last), N(E.Map.Kind), N(E.Map.Replacement)}));
			Constant *Callee = Call.Callee ? (Constant *)Call.Callee : ConstantPointerNull::get(Ptr);
			Calls.push_back(Struct({Callee, N(Call.Flags), N(Cases.size()), Struct(Cases)}));
			Size += FMODRET_META_CALL_SIZE(PtrSize) + Cases.size() * FMODRET_META_CASE_SIZE;
		}
		Constant *Record = Struct({N(FMODRET_META_MAGIC), N(FMODRET_META_VERSION),
			N(Size), N(F.Flags), F.Fn, N(Calls.size()), N(0), Struct(Calls)});
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

		std::string Assembly = M.getModuleInlineAsm();
		for (Function &F : M)
			for (BasicBlock &BB : F)
				for (Instruction &I : BB)
					if (auto *Call = dyn_cast<CallBase>(&I))
						if (auto *Asm = dyn_cast<InlineAsm>(Call->getCalledOperand()))
							Assembly += "\n" + Asm->getAsmString();
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
			if (addressEscapes(&F, Seen) || assemblyReferences(Assembly, F.getName()))
				Flags |= FMODRET_FN_ESCAPED;
			if (!Defined && !(Flags & FMODRET_FN_ESCAPED))
				continue;
			if (F.hasLocalLinkage())
				Flags |= FMODRET_FN_LOCAL;
			if (F.isWeakForLinker())
				Flags |= FMODRET_FN_WEAK;
			if (F.getReturnType()->isIntegerTy(32) || F.getReturnType()->isIntegerTy(64)) {
				Flags |= FMODRET_FN_INTEGER;
				if (Defined) {
					auto &LVI = FAM.getResult<LazyValueAnalysis>(F);
					auto &DT = FAM.getResult<DominatorTreeAnalysis>(F);
					if (functionHasCleanErrnoPath(F, LVI, DT))
						Flags |= FMODRET_FN_CLEAN_SEED;
				}
			}
			if (F.getReturnType()->isPointerTy() &&
			    !M.getDataLayout().isNonIntegralPointerType(F.getReturnType()) &&
			    (M.getDataLayout().getPointerTypeSizeInBits(F.getReturnType()) == 32 ||
			     M.getDataLayout().getPointerTypeSizeInBits(F.getReturnType()) == 64))
				Flags |= FMODRET_FN_ERRPTR;
			FunctionDescription D{&F, Flags, {}};
			if (Defined) {
				SmallPtrSet<const CallBase *, 32> Prefixes;
				findCleanPrefixes(F, Prefixes);
				for (BasicBlock &BB : F)
					for (Instruction &I : BB)
						if (auto *Call = dyn_cast<CallBase>(&I)) {
							auto *Callee = dyn_cast<Function>(Call->getCalledOperand()->stripPointerCasts());
							if (Callee && Callee->isIntrinsic())
								Callee = nullptr;
							D.Calls.push_back({Callee, Prefixes.contains(Call) ?
								FMODRET_CALL_CLEAN_PREFIX : 0U, describeErrors(*Call)});
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
