// SPDX-License-Identifier: GPL-2.0-only
/* Preserve pre-inlining locking semantics independently of bpf_scan_ir. */
#include "bpf_context_metadata.h"
#include "bpf_scan_ast_metadata.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace llvm;
namespace json = llvm::json;

namespace {

static std::string str(const json::Object &O, StringRef K)
{
	return O.getString(K).value_or("").str();
}

static bool symbolName(StringRef S)
{
	return !S.empty() && llvm::all_of(S, [](unsigned char C) {
		return (C >= 'a' && C <= 'z') || (C >= 'A' && C <= 'Z') ||
			(C >= '0' && C <= '9') || C == '_' || C == '.' || C == '$';
	});
}

static std::string add(std::string Base, int64_t Offset)
{
	if (Base.empty() || !Offset)
		return Base;
	return "add(" + Base + "," + std::to_string(Offset) + ")";
}

/* The ARM64 sysreg helpers construct assembler-local register-number constants,
 * then emit exactly one system-register instruction. They do not construct C
 * symbol references. Keep their body effects opaque; this only closes the
 * unrelated functions' caller sets.
 */
static bool localRegisterAsm(StringRef Text)
{
	std::string Compact;
	for (unsigned char C : Text)
		if (C != ' ' && C != '\t' && C != '\r' && C != '\n')
			Compact.push_back(C);
	StringRef S(Compact);
	if (!S.consume_front(
		".irpnum,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30"
		".equ.L__gpr_num_x\\num,\\num.equ.L__gpr_num_w\\num,\\num.endr"
		".equ.L__gpr_num_xzr,31.equ.L__gpr_num_wzr,31"))
		return false;
	if (S.consume_front(".macromrs_s,rt,sreg.inst(0xd5200000|(\\sreg)|(.L__gpr_num_\\rt)).endm")) {
		if (!S.consume_front("mrs_s$0,") || !S.consume_back(".purgemmrs_s"))
			return false;
	} else if (S.consume_front(".macromsr_s,sreg,rt.inst(0xd5000000|(\\sreg)|(.L__gpr_num_\\rt)).endm")) {
		if (!S.consume_front("msr_s") || !S.consume_back(".purgemmsr_s"))
			return false;
		size_t Comma = S.rfind(',');
		if (Comma == StringRef::npos)
			return false;
		StringRef Reg = S.substr(Comma + 1);
		if (Reg != "xzr" && Reg != "$0" && Reg != "${0:x}")
			return false;
		S = S.take_front(Comma);
	} else {
		return false;
	}
	return !S.empty() && llvm::all_of(S, [](unsigned char C) {
		return (C >= '0' && C <= '9') || (C >= 'a' && C <= 'f') ||
			(C >= 'A' && C <= 'F') || C == 'x' || C == 'X' || C == '(' ||
			C == ')' || C == '<' || C == '>' || C == '|' || C == '&' ||
			C == '^' || C == '~' || C == '+' || C == '-';
	});
}

/* These exact instructions neither write lock storage nor call code. A
 * compiler memory clobber orders accesses; it is not an ownership change.
 */
static bool preservesOwnershipAsm(const CallBase &Call)
{
	const auto *Asm = dyn_cast<InlineAsm>(Call.getCalledOperand());
	if (!Asm || !isa<CallInst>(Call))
		return false;
	StringRef Text = StringRef(Asm->getAsmString()).trim();
	if (Text.empty())
		return true;
	Triple Target(Call.getModule()->getTargetTriple());
	if (Target.isAArch64()) {
		if (!Call.arg_size() && Asm->getConstraintString() == "=r" &&
		    (Text == "mrs $0, sp_el0" || Text == "mrs $0, tpidr_el1"))
			return true;
		if (Call.arg_empty() && Call.getType()->isVoidTy() &&
		    Asm->getConstraintString() == "~{memory}" &&
		    (Text == "dmb ish" || Text == "dmb ishld" || Text == "dmb ishst" ||
		     Text == "dsb ish" || Text == "dsb ishld" || Text == "dsb ishst"))
			return true;
	}
	if (Target.isX86() && Call.arg_empty() && Call.getType()->isVoidTy() &&
	    (Text == "lfence" || Text == "sfence" || Text == "mfence") &&
	    Asm->getConstraintString() == "~{memory},~{dirflag},~{fpsr},~{flags}")
		return true;
	return false;
}

/* Assembly references close only the affected functions' C caller sets.
 * Keep an opaque fallback for directives which can manufacture symbol names
 * or import text that is absent from the IR module.
 */
struct AssemblyReferences {
	StringSet<> Symbols;
	bool Opaque = false;

	void collect(StringRef Text)
	{
		std::string Directives;
		for (unsigned char C : Text)
			if (C != ' ' && C != '\t' && C != '\r' && C != '\n')
				Directives.push_back(C);
		/* ARM64 exception-table entries also emit these definitions. The
		 * exact repeat body manufactures assembler-local constants only;
		 * the surrounding instructions and references remain opaque here.
		 */
		StringRef Registers =
			".irpnum,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30"
			".equ.L__gpr_num_x\\num,\\num.equ.L__gpr_num_w\\num,\\num.endr"
			".equ.L__gpr_num_xzr,31.equ.L__gpr_num_wzr,31";
		for (size_t P; (P = Directives.find(Registers.str())) != std::string::npos;)
			Directives.erase(P, Registers.size());
		StringRef Rest(Directives);
		if ((Rest.contains(".include") || Rest.contains(".incbin") ||
		     Rest.contains(".macro") || Rest.contains(".altmacro") ||
		     Rest.contains(".irp")) && !localRegisterAsm(Text))
			Opaque = true;
		while (!Text.empty()) {
			auto IsSymbol = [](unsigned char C) {
				return (C >= 'a' && C <= 'z') || (C >= 'A' && C <= 'Z') ||
					(C >= '0' && C <= '9') || C == '_' || C == '.' || C == '$';
			};
			Text = Text.drop_until(IsSymbol);
			StringRef Symbol = Text.take_while(IsSymbol);
			if (!Symbol.empty())
				Symbols.insert(Symbol);
			Text = Text.drop_front(Symbol.size());
		}
	}

	explicit AssemblyReferences(const Module &M)
	{
		for (const auto &Fragment : M.getModuleInlineAsm())
			collect(Fragment.Asm);
		for (const Function &F : M)
			for (const BasicBlock &B : F)
				for (const Instruction &I : B)
					if (const auto *C = dyn_cast<CallBase>(&I))
						if (const auto *A = dyn_cast<InlineAsm>(C->getCalledOperand()))
							collect(A->getAsmString());
	}

	bool references(const Function &F) const
	{
		return Opaque || Symbols.contains(F.getName()) ||
			F.getName().starts_with(".L__gpr_num_") ||
			llvm::any_of(F.users(), [](const User *U) { return isa<BlockAddress>(U); });
	}
};

static bool callTargets(const Value *V, SmallPtrSetImpl<const Value *> &Active,
			SmallVectorImpl<Function *> &Targets, unsigned Depth = 0)
{
	V = V->stripPointerCasts();
	if (const auto *F = dyn_cast<Function>(V)) {
		if (!llvm::is_contained(Targets, F))
			Targets.push_back(const_cast<Function *>(F));
		return Targets.size() <= 8;
	}
	if (Depth > 24 || !Active.insert(V).second)
		return false;
	scope_exit Erase([&] { Active.erase(V); });
	if (const auto *S = dyn_cast<SelectInst>(V))
		return callTargets(S->getTrueValue(), Active, Targets, Depth + 1) &&
			callTargets(S->getFalseValue(), Active, Targets, Depth + 1);
	if (const auto *P = dyn_cast<PHINode>(V)) {
		for (const Value *I : P->incoming_values())
			if (!callTargets(I, Active, Targets, Depth + 1))
				return false;
		return true;
	}
	return false;
}

/* Expand a fully bounded selector in the analysis copy only. The executable
 * module, target addresses and native function identities are unchanged.
 */
static void resolveCallSelectors(Module &M)
{
	SmallVector<CallInst *, 16> Calls;

	for (Function &F : M)
		for (BasicBlock &B : F)
			for (Instruction &I : B)
				if (auto *C = dyn_cast<CallInst>(&I))
					if (!C->getCalledFunction() && !C->isInlineAsm() && !C->isMustTailCall())
						Calls.push_back(C);
	for (CallInst *C : Calls) {
		SmallPtrSet<const Value *, 16> Active;
		SmallVector<Function *, 4> Targets;
		Value *Operand = C->getCalledOperand();

		if (!callTargets(Operand, Active, Targets) || Targets.empty() ||
		    llvm::any_of(Targets, [&](Function *F) { return F->getFunctionType() != C->getFunctionType(); }))
			continue;
		BasicBlock *Check = C->getParent();
		Function *Caller = Check->getParent();
		BasicBlock *Tail = Check->splitBasicBlock(C, "context.call.join");
		PHINode *Result = C->getType()->isVoidTy() ? nullptr :
			PHINode::Create(C->getType(), Targets.size(), "context.call.result", C->getIterator());

		Check->getTerminator()->eraseFromParent();
		for (unsigned I = 0; I < Targets.size(); ++I) {
			BasicBlock *Body = BasicBlock::Create(M.getContext(), "context.call.target", Caller, Tail);
			auto *Direct = cast<CallInst>(C->clone());

			Direct->setCalledFunction(Targets[I]);
			Direct->setTailCallKind(CallInst::TCK_None);
			IRBuilder<> BodyBuilder(Body);
			BodyBuilder.Insert(Direct);
			BodyBuilder.CreateBr(Tail);
			if (Result)
				Result->addIncoming(Direct, Body);
			IRBuilder<> Branch(Check);
			if (I + 1 == Targets.size()) {
				Branch.CreateBr(Body);
			} else {
				BasicBlock *Next = BasicBlock::Create(M.getContext(), "context.call.check", Caller, Tail);

				Branch.CreateCondBr(Branch.CreateICmpEQ(Operand, Targets[I]), Body, Next);
				Check = Next;
			}
		}
		if (Result)
			C->replaceAllUsesWith(Result);
		C->eraseFromParent();
		if (auto *I = dyn_cast<Instruction>(Operand))
			RecursivelyDeleteTriviallyDeadInstructions(I);
	}
}

static bool addressEscapes(const Function &F, const Value *V, SmallPtrSetImpl<const Value *> &Seen)
{
	if (!Seen.insert(V).second)
		return false;
	for (const User *U : V->users()) {
		if (const auto *C = dyn_cast<CallBase>(U)) {
			if (C->getCalledFunction() != &F ||
			    llvm::any_of(C->args(), [&](const Use &A) { return A.get() == V; }))
				return true;
		} else if (isa<SelectInst>(U) || isa<PHINode>(U) || isa<ConstantExpr>(U)) {
			if (const auto *E = dyn_cast<ConstantExpr>(U))
				if (!E->isCast())
					return true;
			if (addressEscapes(F, U, Seen))
				return true;
		} else if (!isa<ICmpInst>(U)) {
			return true;
		}
	}
	return false;
}

/* AST lvalues denote addresses; parameter roots denote incoming pointer values. */
static std::string astExpr(const json::Object &O, unsigned Depth = 0, bool Address = false)
{
	if (Depth > 24)
		return "";
	auto Child = [&](StringRef K, bool A = false) {
		const auto *V = O.getObject(K);
		return V ? astExpr(*V, Depth + 1, A) : std::string();
	};
	std::string Kind = str(O, "kind");
	bool Pointer = O.getBoolean("pointer_value").value_or(StringRef(str(O, "type")).ends_with("*"));
	if (Kind == "parameter") {
		auto N = O.getInteger("index");
		return !Address && Pointer && N && *N >= 0 ? "arg(" + std::to_string(*N) + ")" : "";
	}
	if (Kind == "token") {
		std::string Name = str(O, "symbol");
		return Pointer && !Address && symbolName(Name) ? "token(" + Name + ")" : "";
	}
	if (Kind == "global") {
		std::string Name = str(O, "symbol");
		if (!symbolName(Name))
			return "";
		std::string E = "global(" + Name + ")";
		return Pointer && !Address ? "load(" + E + ")" : E;
	}
	if (Kind == "member") {
		const auto *F = O.getObject("field");
		auto Offset = F ? F->getInteger("offset_bits") : std::nullopt;
		if (!Offset || *Offset % 8)
			return "";
		std::string E = add(Child("base", !O.getBoolean("arrow").value_or(false)), *Offset / 8);
		return Pointer && !Address && !E.empty() ? "load(" + E + ")" : E;
	}
	if (Kind == "cast") {
		return Child("value", str(O, "cast") == "LValueToRValue" ? false : Address);
	}
	if (Kind == "unary") {
		std::string Op = str(O, "op");
		if (Op == "&")
			return Child("value", true);
		if (Op == "*") {
			std::string E = Child("value");
			return Pointer && !Address && !E.empty() ? "load(" + E + ")" : E;
		}
	}
	return "";
}

static std::optional<int64_t> astInteger(const json::Object *O)
{
	if (!O)
		return std::nullopt;
	if (str(*O, "kind") == "cast")
		return astInteger(O->getObject("value"));
	int64_t N;
	if (str(*O, "kind") == "integer" && !StringRef(str(*O, "value")).getAsInteger(10, N))
		return N;
	return std::nullopt;
}

static json::Array contracts(const json::Object *F, bool &Complete)
{
	json::Array Out;
	if (!F)
		return Out;
	const auto *A = F->getArray("contracts");
	if (!A)
		return Out;
	for (const auto &V : *A) {
		const auto *C = V.getAsObject();
		if (!C)
			continue;
		std::string Op = str(*C, "op"), Cond = "always";
		if (Op == "analysis_disabled")
			continue;
		/* An assertion observes ownership; it does not acquire it. Ignore
		 * that assumption and analyze the body normally, so empty compiler
		 * assertion helpers preserve existing ownership without inventing it.
		 */
		if (Op == "assert")
			continue;
		if (Op == "returns_lock") {
			Complete = false;
			continue;
		}
		if (Op == "try_acquire") {
			auto N = astInteger(C->getObject("success"));
			if (!N) {
				Complete = false;
				continue;
			}
			Cond = *N ? "ret_ne(0)" : "ret_eq(0)";
			Op = "acquire";
		}
		const auto *Locks = C->getArray("locks");
		if (!Locks || Locks->empty() || C->getBoolean("unresolved").value_or(true)) {
			Complete = false;
			continue;
		}
		for (const auto &L : *Locks) {
			const auto *E = L.getAsObject();
			std::string Expr = E ? astExpr(*E) : "";
			if (Expr.empty()) {
				Complete = false;
				continue;
			}
			Out.push_back(json::Object{{"op", Op}, {"mode", str(*C, "mode")},
				{"lock", Expr}, {"condition", Cond}});
		}
	}
	return Out;
}

class DescribeModule {
	const DataLayout &DL;
	DenseMap<const Function *, unsigned> Functions;
	DenseMap<const CallBase *, unsigned> Calls;
	DenseMap<const BasicBlock *, unsigned> Blocks;
	DenseMap<const AllocaInst *, unsigned> Locals;
	SmallPtrSet<const Value *, 32> ActiveValues;
	StringSet<> Tokens;
	DenseMap<const Function *, std::string> PointerReturns;
	SmallPtrSet<const Function *, 8> ActivePointerReturns;
	DenseMap<const Value *, unsigned> Snapshots;
	std::vector<std::string> SnapshotPaths;
	unsigned ValueBudget = 0;

	/* Summarize local, read-only getters before inlining. All returns must
	 * describe the same pointer path; never import effects from an opaque call.
	 */
	std::string pointerReturn(const Function *F)
	{
		if (!F || !F->hasLocalLinkage() || F->isDeclaration())
			return "";
		if (auto I = PointerReturns.find(F); I != PointerReturns.end())
			return I->second;
		if (ActivePointerReturns.size() >= 24 || !ActivePointerReturns.insert(F).second)
			return "";
		scope_exit Erase([&] { ActivePointerReturns.erase(F); });
		std::string Result;
		unsigned Count = 0;
		for (const BasicBlock &B : *F)
			for (const Instruction &I : B) {
				if (++Count > 128 || I.mayWriteToMemory())
					return PointerReturns[F] = "";
				if (const auto *C = dyn_cast<CallBase>(&I)) {
					if (isa<DbgInfoIntrinsic>(C))
						continue;
					if (!isa<CallInst>(C) || C->isInlineAsm() ||
					    pointerReturn(C->getCalledFunction()).empty())
						return PointerReturns[F] = "";
				}
				if (const auto *R = dyn_cast<ReturnInst>(&I)) {
					std::string E = R->getReturnValue() && R->getReturnValue()->getType()->isPointerTy() ?
						expression(R->getReturnValue(), 0, nullptr, false) : "";

					if (E.empty() || E.find("local(") != std::string::npos ||
					    (!Result.empty() && Result != E))
						return PointerReturns[F] = "";
					Result = std::move(E);
				}
			}
		return PointerReturns[F] = Result;
	}

	std::string expression(const Value *V, unsigned Depth = 0,
			       const BasicBlock *Pred = nullptr, bool Capture = true)
	{
		if (Depth > 24)
			return "";
		if (const auto *A = dyn_cast<Argument>(V))
			return A->getType()->isPointerTy() ? "arg(" + std::to_string(A->getArgNo()) + ")" : "";
		if (const auto *G = dyn_cast<GlobalVariable>(V))
			return symbolName(G->getName()) ? "global(" + G->getName().str() + ")" : "";
		if (const auto *A = dyn_cast<AllocaInst>(V))
			return "local(" + std::to_string(Locals.try_emplace(A, Locals.size()).first->second) + ")";
		if (const auto *G = dyn_cast<GEPOperator>(V)) {
			APInt Offset(DL.getIndexSizeInBits(G->getPointerAddressSpace()), 0);
			if (!G->accumulateConstantOffset(DL, Offset) || !Offset.isSignedIntN(64))
				return "";
			return add(expression(G->getPointerOperand(), Depth + 1, Pred, Capture), Offset.getSExtValue());
		}
		if (const auto *L = dyn_cast<LoadInst>(V)) {
			if (const auto *G = dyn_cast<GlobalVariable>(L->getPointerOperand()->stripPointerCasts()))
				if (Tokens.contains(G->getName()))
					return "token(" + G->getName().str() + ")";
			if (Capture && L->getType()->isPointerTy())
				return snapshot(L, expression(L, Depth + 1, Pred, false));
			std::string E = expression(L->getPointerOperand(), Depth + 1, Pred, Capture);
			return E.empty() ? "" : "load(" + E + ")";
		}
		if (const auto *C = dyn_cast<CallBase>(V)) {
			std::string Summary = pointerReturn(C->getCalledFunction()), Result;
			StringRef Rest(Summary);

			if (Summary.empty())
				return "";
			if (Capture && Summary.find("load(") != std::string::npos)
				return snapshot(C, expression(C, Depth + 1, Pred, false));
			while (Rest.contains("arg(")) {
				size_t Pos = Rest.find("arg("), Close = Rest.find(')', Pos + 4);
				unsigned Arg;

				if (Close == StringRef::npos ||
				    Rest.slice(Pos + 4, Close).getAsInteger(10, Arg) || Arg >= C->arg_size())
					return "";
				std::string E = expression(C->getArgOperand(Arg), Depth + 1, Pred, Capture);

				if (E.empty())
					return "";
				Result += Rest.take_front(Pos).str() + E;
				Rest = Rest.drop_front(Close + 1);
				if (Result.size() > 1024)
					return "";
			}
			Result += Rest.str();
			return Result.size() <= 1024 ? Result : "";
		}
		if (const auto *P = dyn_cast<PHINode>(V)) {
			if (Pred)
				return expression(P->getIncomingValueForBlock(Pred), Depth + 1, nullptr, Capture);
			std::string E;
			for (const Value *I : P->incoming_values()) {
				std::string Next = expression(I, Depth + 1, nullptr, Capture);
				if (Next.empty() || (!E.empty() && Next != E))
					return "";
				E = Next;
			}
			return E;
		}
		if (const auto *C = dyn_cast<Operator>(V))
			if (C->getOpcode() == Instruction::BitCast || C->getOpcode() == Instruction::AddrSpaceCast)
				return expression(C->getOperand(0), Depth + 1, Pred, Capture);
		return "";
	}

	std::string snapshot(const Value *V, std::string Path)
	{
		if (Path.empty())
			return "";
		auto [I, Added] = Snapshots.try_emplace(V, SnapshotPaths.size());

		if (Added)
			SnapshotPaths.push_back(std::move(Path));
		return "snapshot(" + std::to_string(I->second) + ")";
	}

	json::Object value(const Value *V, const BasicBlock *Pred = nullptr, unsigned Depth = 0)
	{
		if (!Depth) {
			ActiveValues.clear();
			ValueBudget = 128;
		}
		if (!V || Depth > 16 || !ValueBudget || !ActiveValues.insert(V).second)
			return json::Object{{"kind", "unknown"}};
		--ValueBudget;
		scope_exit Erase([&] { ActiveValues.erase(V); });
		if (isa<ConstantPointerNull>(V))
			return json::Object{{"kind", "integer"}, {"value", 0}};
		if (const auto *I = dyn_cast<ConstantInt>(V))
			if (I->getBitWidth() <= 64)
				return json::Object{{"kind", "integer"}, {"value", I->getSExtValue()}};
		if (const auto *C = dyn_cast<CallBase>(V))
			return json::Object{{"kind", "call"}, {"call", Calls.lookup(C)}};
		if (const auto *P = dyn_cast<PHINode>(V)) {
			json::Array Incoming;
			for (unsigned I = 0; I < P->getNumIncomingValues(); I++)
				Incoming.push_back(json::Object{{"block", Blocks.lookup(P->getIncomingBlock(I))},
					{"value", value(P->getIncomingValue(I), nullptr, Depth + 1)}});
			return json::Object{{"kind", "phi"}, {"incoming", std::move(Incoming)}};
		}
		if (const auto *C = dyn_cast<CastInst>(V))
			if (C->getOpcode() == Instruction::ZExt || C->getOpcode() == Instruction::SExt)
				return value(C->getOperand(0), Pred, Depth + 1);
		if (const auto *I = dyn_cast<ICmpInst>(V)) {
			if (I->getPredicate() != ICmpInst::ICMP_EQ && I->getPredicate() != ICmpInst::ICMP_NE)
				return json::Object{{"kind", "unknown"}};
			const Value *L = I->getOperand(0), *R = I->getOperand(1);
			if (isa<ConstantInt>(L))
				std::swap(L, R);
			return json::Object{{"kind", "test"},
				{"predicate", I->getPredicate() == ICmpInst::ICMP_EQ ? "eq" : "ne"},
				{"left", value(L, Pred, Depth + 1)}, {"right", value(R, Pred, Depth + 1)}};
		}
		return json::Object{{"kind", "unknown"}};
	}

public:
	explicit DescribeModule(Module &M, const json::Array *TokenDecls) : DL(M.getDataLayout())
	{
		if (TokenDecls)
			for (const auto &V : *TokenDecls)
				if (const auto *T = V.getAsObject())
					Tokens.insert(str(*T, "name"));
		for (const Function &F : M)
			Functions[&F] = Functions.size();
	}

	json::Object function(Function &F, const json::Object *AST, bool Covered)
	{
		SmallPtrSet<const Value *, 16> AddressUses;
		Calls.clear(); Blocks.clear(); Locals.clear(); Snapshots.clear(); SnapshotPaths.clear();
		bool ContractComplete = Covered;
		json::Array Contracts = contracts(AST, ContractComplete);
		bool Complete = Covered && !F.isDeclaration() && ContractComplete;
		bool MemoryCovered = Covered && ContractComplete;
		if (AST)
			if (const auto *A = AST->getArray("contracts"))
				for (const auto &V : *A)
					if (const auto *C = V.getAsObject())
						if (str(*C, "op") == "analysis_disabled")
							Complete = MemoryCovered = false;
		for (const BasicBlock &B : F) {
			Blocks[&B] = Blocks.size();
			for (const Instruction &I : B)
				if (const auto *C = dyn_cast<CallBase>(&I))
					Calls[C] = Calls.size();
		}
		json::Array CFG;
		for (const BasicBlock &B : F) {
			json::Array Sites, Edges;
			for (const Instruction &I : B) {
				const auto *C = dyn_cast<CallBase>(&I);
				if (!C) {
					if (const auto *L = dyn_cast<LoadInst>(&I))
						if (L->getType()->isPointerTy()) {
							expression(L);
							if (Snapshots.count(L))
								Sites.push_back(json::Object{{"id", -1}, {"callee", -1},
									{"kind", "capture"}, {"snapshot", Snapshots.lookup(L)},
									{"arguments", json::Array()}});
						}
					if (isa<StoreInst>(I) || isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I)) {
						const Value *Address;
						Type *Stored;

						if (const auto *S = dyn_cast<StoreInst>(&I)) {
							Address = S->getPointerOperand();
							Stored = S->getValueOperand()->getType();
						} else if (const auto *R = dyn_cast<AtomicRMWInst>(&I)) {
							Address = R->getPointerOperand();
							Stored = R->getValOperand()->getType();
						} else {
							const auto *X = cast<AtomicCmpXchgInst>(&I);

							Address = X->getPointerOperand();
							Stored = X->getCompareOperand()->getType();
						}
						TypeSize Width = DL.getTypeStoreSize(Stored);

						Complete = false;
						Sites.push_back(json::Object{{"id", -1}, {"callee", -1},
							{"kind", "write"}, {"address", expression(Address)},
							{"width", Width.isScalable() ? 0 : Width.getFixedValue()},
							{"arguments", json::Array()}});
					}
					continue;
				}
				if (isa<DbgInfoIntrinsic>(C))
					continue;
				if (preservesOwnershipAsm(*C))
					continue;
				if (const auto *Memory = dyn_cast<MemIntrinsic>(C)) {
					const auto *Length = dyn_cast<ConstantInt>(Memory->getLength());
					uint64_t Width = Length && Length->getValue().getActiveBits() <= 32 ?
						Length->getZExtValue() : 0;

					if (Length && Length->isZero())
						continue;
					Sites.push_back(json::Object{{"id", Calls.lookup(C)}, {"callee", -1},
						{"kind", "write"}, {"address", expression(Memory->getRawDest())},
						{"width", Width}, {"arguments", json::Array()}});
					Complete = false;
					continue;
				}
				if (const auto *Intr = dyn_cast<IntrinsicInst>(C)) {
					/* These intrinsics cannot acquire or release a native lock. */
					switch (Intr->getIntrinsicID()) {
					case Intrinsic::lifetime_start: case Intrinsic::lifetime_end:
					case Intrinsic::assume: case Intrinsic::expect:
						continue;
					default: break;
					}
				}
				const Function *Callee = dyn_cast<Function>(C->getCalledOperand()->stripPointerCasts());
				json::Array Args;
				for (const Use &A : C->args())
					Args.push_back(expression(A.get()));
				Sites.push_back(json::Object{{"id", Calls.lookup(C)},
					{"callee", Callee ? static_cast<int64_t>(Functions.lookup(Callee)) : -1},
					{"arguments", std::move(Args)}});
				if (C->getType()->isPointerTy()) {
					expression(C);
					if (Snapshots.count(C))
						Sites.push_back(json::Object{{"id", -1}, {"callee", -1},
							{"kind", "capture"}, {"snapshot", Snapshots.lookup(C)},
							{"arguments", json::Array()}});
				}
				if (C->isInlineAsm() || isa<InvokeInst>(C) || isa<CallBrInst>(C))
					Complete = false;
			}
			json::Object Block{{"id", Blocks.lookup(&B)}, {"calls", std::move(Sites)}};
			const Instruction *Term = B.getTerminator();
			if (const auto *R = dyn_cast<ReturnInst>(Term))
				Block["return"] = value(R->getReturnValue());
			else if (isa<CondBrInst>(Term) || isa<UncondBrInst>(Term)) {
				for (unsigned I = 0; I < Term->getNumSuccessors(); I++) {
					json::Object E{{"block", Blocks.lookup(Term->getSuccessor(I))}};
					if (const auto *Br = dyn_cast<CondBrInst>(Term)) {
						E["test"] = value(Br->getCondition());
						E["true"] = I == 0;
					}
					Edges.push_back(std::move(E));
				}
			} else {
				Complete = false;
				for (unsigned I = 0; I < Term->getNumSuccessors(); I++)
					Edges.push_back(json::Object{{"block", Blocks.lookup(Term->getSuccessor(I))}});
			}
			Block["edges"] = std::move(Edges);
			CFG.push_back(std::move(Block));
		}
		json::Array SnapshotRecords;
		for (const std::string &Path : SnapshotPaths)
			SnapshotRecords.push_back(Path);
		return json::Object{{"id", Functions.lookup(&F)}, {"symbol", F.getName().str()},
			{"local", F.hasLocalLinkage()}, {"weak", F.isWeakForLinker()},
			{"defined", !F.isDeclaration()}, {"escaped", addressEscapes(F, &F, AddressUses)},
			{"covered", Covered}, {"complete", Complete}, {"nargs", F.arg_size()},
			{"contract_complete", ContractComplete},
			{"memory_covered", MemoryCovered},
			{"snapshots", std::move(SnapshotRecords)},
			{"contracts", std::move(Contracts)}, {"blocks", std::move(CFG)}};
	}
};

#if LLVM_VERSION_MAJOR >= 24
class ImportContext : public RequiredPassInfoMixin<ImportContext>
#else
class ImportContext : public PassInfoMixin<ImportContext>
#endif
{
public:
	static bool isRequired() { return true; }
	PreservedAnalyses run(Module &M, ModuleAnalysisManager &)
	{
		if (M.getNamedMetadata(BPF_CONTEXT_IR_METADATA))
			return PreservedAnalyses::all();
		json::Object AST;
		if (const GlobalVariable *G = M.getGlobalVariable("__bpf_scan_ast_locks", true)) {
			if (G->hasInitializer())
				if (const auto *D = dyn_cast<ConstantDataSequential>(G->getInitializer())) {
					auto Parsed = json::parse(D->getAsCString());
					if (!Parsed)
						report_fatal_error("bpf_context_ir: invalid AST locking document");
					if (auto *O = Parsed->getAsObject())
						AST = std::move(*O);
				}
		}
		bool Covered = AST.getBoolean("annotations_enabled").value_or(false);
		if (Covered && (AST.getInteger("version").value_or(-1) != BPF_SCAN_LOCK_VERSION ||
			str(AST, "format") != BPF_SCAN_LOCK_FORMAT || AST.getInteger("char_bits").value_or(0) != 8))
			report_fatal_error("bpf_context_ir: unsupported AST locking format");
		std::map<std::string, const json::Object *> Decls;
		if (const auto *A = AST.getArray("functions"))
			for (const auto &V : *A)
				if (const auto *F = V.getAsObject())
					Decls[str(*F, "symbol")] = F;

		/* Promote locals in an analysis copy, never mutate the compiled body. */
		auto Copy = CloneModule(M);
		for (Function &F : *Copy) {
			if (F.isDeclaration())
				continue;
			DominatorTree DT(F);
			SmallVector<AllocaInst *> Allocas;
			for (Instruction &I : F.getEntryBlock())
				if (auto *A = dyn_cast<AllocaInst>(&I))
					if (isAllocaPromotable(A))
						Allocas.push_back(A);
			if (!Allocas.empty())
				PromoteMemToReg(Allocas, DT);
		}
		resolveCallSelectors(*Copy);
		DescribeModule Describe(*Copy, AST.getArray("tokens"));
		json::Array Functions;
		AssemblyReferences Assembly(*Copy);
		for (Function &F : *Copy) {
			auto Record = Describe.function(F, Decls[F.getName().str()], Covered);
			Record["asm_referenced"] = Assembly.references(F);
			Record["asm_opaque"] = Assembly.Opaque;
			if (Assembly.references(F))
				Record["escaped"] = true;
			Functions.push_back(std::move(Record));
		}
		json::Array Types, Tokens;
		if (auto *T = AST.getArray("tokens"))
			Tokens = std::move(*T);
		if (auto *T = AST.getArray("types"))
			Types = std::move(*T);
		json::Object Out{{"format", BPF_CONTEXT_FORMAT}, {"version", BPF_CONTEXT_VERSION},
			{"unit", M.getSourceFileName()}, {"functions", std::move(Functions)},
			{"types", std::move(Types)}, {"tokens", std::move(Tokens)}};
		std::string Data;
		raw_string_ostream OS(Data);
		OS << json::Value(std::move(Out));
		M.getOrInsertNamedMetadata(BPF_CONTEXT_IR_METADATA)->addOperand(
			MDNode::get(M.getContext(), MDString::get(M.getContext(), Data)));
		return PreservedAnalyses::all();
	}
};

#if LLVM_VERSION_MAJOR >= 24
class ExportContext : public RequiredPassInfoMixin<ExportContext>
#else
class ExportContext : public PassInfoMixin<ExportContext>
#endif
{
public:
	static bool isRequired() { return true; }
	PreservedAnalyses run(Module &M, ModuleAnalysisManager &)
	{
		const NamedMDNode *N = M.getNamedMetadata(BPF_CONTEXT_IR_METADATA);
		if (!N)
			return PreservedAnalyses::all();
		std::string Data;
		for (const MDNode *Node : N->operands()) {
			auto Parsed = json::parse(cast<MDString>(Node->getOperand(0))->getString());
			if (!Parsed)
				report_fatal_error("bpf_context_ir: invalid imported locking document");
			auto *O = Parsed->getAsObject();
			for (auto &V : *O->getArray("functions")) {
				auto *F = V.getAsObject();
				const Function *Live = M.getFunction(str(*F, "symbol"));
				(*F)["live"] = Live && !Live->isDeclaration();
			}
			raw_string_ostream OS(Data);
			OS << *Parsed;
			Data.push_back('\0');
		}
		auto *Init = ConstantDataArray::getString(M.getContext(), Data, false);
		auto *G = new GlobalVariable(M, Init->getType(), true, GlobalValue::PrivateLinkage,
			Init, "__bpf_context_ir_data");
		G->setSection(BPF_CONTEXT_SECTION);
		G->setAlignment(Align(1));
		appendToCompilerUsed(M, {G});
		return PreservedAnalyses::none();
	}
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
	return {LLVM_PLUGIN_API_VERSION, "bpf_context_ir", LLVM_VERSION_STRING,
		[](PassBuilder &PB) {
			PB.registerPipelineStartEPCallback([](ModulePassManager &PM, OptimizationLevel, auto...) {
				PM.addPass(ImportContext());
			});
			PB.registerOptimizerLastEPCallback([](ModulePassManager &PM, OptimizationLevel, auto...) {
				PM.addPass(ExportContext());
			});
		}};
}
