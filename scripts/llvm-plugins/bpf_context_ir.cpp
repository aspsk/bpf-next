// SPDX-License-Identifier: GPL-2.0-only
/* Preserve pre-inlining locking semantics independently of bpf_scan_ir. */
#include "bpf_context_metadata.h"
#include "bpf_scan_ast_metadata.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringExtras.h"
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

static std::string signature(const FunctionType *Type)
{
	std::string Text;
	raw_string_ostream OS(Text);
	Type->print(OS);
	return Text;
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
	if (!Asm)
		return false;
	StringRef Text = StringRef(Asm->getAsmString()).trim();
	if (const auto *Goto = dyn_cast<CallBrInst>(&Call)) {
		std::string Compact;
		for (unsigned char C : Text)
			if (C != ' ' && C != '\t' && C != '\r' && C != '\n')
				Compact.push_back(C);
		StringRef Body(Compact);
		StringRef Table = ".pushsection__jump_table,\"aw\".align3.long1b-.,${1:l}-..quad${0:c}-..popsection";

		/* Only the native ARM64 nop/branch and its exact data-only jump
		 * table are accepted. Both successors retain ownership.
		 */
		if (Triple(Call.getModule()->getTargetTriple()).isAArch64() &&
		    Goto->getNumIndirectDests() == 1 && Call.arg_size() == 1 &&
		    Call.getType()->isVoidTy() && Asm->getConstraintString() == "i,!i") {
			if (Body.consume_front("1:nop") || Body.consume_front("1:b${1:l}"))
				return Body == Table;
		}
		if (Triple(Call.getModule()->getTargetTriple()).getArch() == Triple::x86_64 &&
		    Goto->getNumIndirectDests() == 1 && Call.arg_size() == 2 &&
		    Call.getType()->isVoidTy() &&
		    Asm->getConstraintString() == "i,i,!i,~{dirflag},~{fpsr},~{flags}") {
			bool Hack = Body.consume_front("1:jmp${2:l}#objtoolNOPsthis");
			if (!Hack && !Body.consume_front("1:jmp${2:l}") &&
			    !Body.consume_front("1:.byte0x0f,0x1f,0x44,0x00,0x00"))
				return false;
			if (!Body.consume_front(".pushsection__jump_table,\"aw\".balign8"))
				return false;
			Body.consume_front("912:.pushsection.discard.annotate_data,\"M\",@progbits,8;.long912b-.,1;.popsection");
			if (!Body.consume_front(".long1b-..long${2:l}-..quad${0:c}+${1:c}"))
				return false;
			if (Hack && !Body.consume_front("+2"))
				return false;
			return Body == "-..popsection";
		}
		return false;
	}
	if (!isa<CallInst>(Call))
		return false;
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
	if (Target.getArch() == Triple::x86_64 && Call.arg_size() == 1 &&
	    Call.getType()->isIntegerTy(64) &&
	    Text == "movq %gs:${1:a}, $0" &&
	    Asm->getConstraintString() == "=r,i,~{dirflag},~{fpsr},~{flags}")
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
		std::string Clean = Text.str();
		/* The exact LSM null trampoline defines a dispatch endpoint. It
		 * does not introduce an unseen caller of that endpoint. Keep any
		 * other reference to the symbol visible to escape analysis.
		 */
		for (size_t Search = 0, Start; (Start = Clean.find(".pushsection .static_call.text", Search)) != std::string::npos;) {
			size_t End = Start, Depth = 0;
			do {
				size_t Push = Clean.find(".pushsection", End), Pop = Clean.find(".popsection", End);
				if (Pop == std::string::npos) { End = Clean.size(); break; }
				if (Push < Pop) { ++Depth; End = Push + 12; }
				else { --Depth; End = Pop + 11; }
			} while (Depth);
			StringRef Raw = StringRef(Clean).slice(Start, End);
			StringRef Name = Raw.split(".globl").second.trim().take_while([](unsigned char C) {
				return llvm::isAlnum(C) || C == '_';
			});
			std::string Compact;
			for (unsigned char C : Raw)
				if (!llvm::isSpace(C)) Compact.push_back(C);
			std::string Prefix = ".pushsection.static_call.text,\"ax\".align4.globl" + Name.str() + Name.str() + ":";
			std::string Suffix = ".byte0x0f,0xb9,0xcc.type" + Name.str() + ",@function.size" + Name.str() + ",.-" + Name.str() + ".popsection";
			StringRef Body(Compact);
			bool Known = Name.starts_with("__SCT__lsm_static_call_") && Body.consume_front(Prefix);
			if (Known) {
				Body.consume_front("911:.pushsection.discard.annotate_insn,\"M\",@progbits,8;.long911b-.,1;.popsection");
				if (Body.consume_front("ret;int3;nop;nop;nop"))
					Known = Body == Suffix;
				else if (Body.consume_front("jmp__x86_return_thunk")) {
					Known = Body == Suffix;
					if (Known) Symbols.insert("__x86_return_thunk");
				} else Known = false;
			}
			if (Known) Clean.erase(Start, End - Start);
			else Search = End;
		}
		Text = Clean;
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

/* Recover the framework's actual callback registration and static-call keys.
 * This describes executable call edges, never locking contracts by hook name.
 */
class NativeDispatch {
	const DataLayout &DL;
	struct Binding {
		std::string Holder, Target, Table;
		uint64_t Address, Offset, Size;
	};
	struct Key { std::string Name, Table; uint64_t Offset, Address, Size; int64_t Trampoline; bool Closed; };
	std::vector<Binding> Bindings;
	std::vector<Key> Keys;
	SmallPtrSet<const GlobalVariable *, 8> RegistrationGlobals;

	const GlobalVariable *baseGlobal(const Value *V, int64_t &Offset) const
	{
		const Value *Base = GetPointerBaseWithConstantOffset(V, Offset, DL);
		return dyn_cast<GlobalVariable>(Base->stripPointerCasts());
	}

	void registration(const Constant *C, const GlobalVariable &GV, uint64_t Offset)
	{
		if (const auto *S = dyn_cast<ConstantStruct>(C)) {
			auto *Type = S->getType();
			const auto *Layout = DL.getStructLayout(Type);

			if (Type->hasName() && Type->getName() == "struct.security_hook_list") {
				const Function *Target = nullptr;
				const GlobalVariable *Table = nullptr;
				uint64_t Address = 0, Field = 0;
				for (unsigned I = 0; I < S->getNumOperands(); ++I) {
					const Value *V = S->getOperand(I)->stripPointerCasts();
					if (const auto *U = dyn_cast<ConstantStruct>(V))
						if (U->getNumOperands() == 1)
							V = U->getOperand(0)->stripPointerCasts();
					if (const auto *F = dyn_cast<Function>(V)) {
						if (Target) return;
						Target = F;
						Address = Offset + Layout->getElementOffset(I);
					} else if (V->getType()->isPointerTy()) {
						int64_t N = 0;
						if (const auto *G = baseGlobal(V, N))
							if (G->getName() == "static_calls_table" && N >= 0) {
								if (Table) return;
								Table = G;
								Field = N;
							}
					}
				}
				if (Target && Table && symbolName(Target->getName()) && symbolName(GV.getName())) {
					Bindings.push_back({GV.getName().str(), Target->getName().str(), Table->getName().str(), Address, Field, DL.getTypeAllocSize(GV.getValueType())});
					RegistrationGlobals.insert(&GV);
				}
				return;
			}
			for (unsigned I = 0; I < S->getNumOperands(); ++I)
				registration(cast<Constant>(S->getOperand(I)), GV, Offset + Layout->getElementOffset(I));
		} else if (const auto *A = dyn_cast<ConstantArray>(C)) {
			uint64_t Size = DL.getTypeAllocSize(A->getType()->getElementType());
			for (unsigned I = 0; I < A->getNumOperands(); ++I)
				registration(cast<Constant>(A->getOperand(I)), GV, Offset + I * Size);
		}
	}

	bool keyUses(const Value *V, SmallPtrSetImpl<const Value *> &Seen) const
	{
		if (!Seen.insert(V).second)
			return true;
		for (const User *U : V->users()) {
			if (const auto *G = dyn_cast<GlobalVariable>(U)) {
				if (G->getName() == "static_calls_table" || G->getName() == "llvm.compiler.used")
					continue;
				if (G->getSection() == ".discard.addressable" && G->hasInitializer() &&
				    G->getInitializer()->stripPointerCasts() == V &&
				    llvm::all_of(G->users(), [](const User *Use) {
					if (const auto *A = dyn_cast<ConstantArray>(Use))
						return llvm::all_of(A->users(), [](const User *P) {
							const auto *Used = dyn_cast<GlobalVariable>(P);
							return Used && Used->getName() == "llvm.compiler.used";
						});
					return false;
				    }))
					continue;
				return false;
			}
			if (const auto *L = dyn_cast<LoadInst>(U)) {
				if (L->getPointerOperand() != V)
					return false;
				for (const User *ValueUse : L->users()) {
					if (const auto *Call = dyn_cast<CallBase>(ValueUse)) {
						if (Call->getCalledOperand() == L && llvm::none_of(Call->args(),
							[&](const Use &A) { return A.get() == L; }))
							continue;
					} else if (const auto *Cmp = dyn_cast<ICmpInst>(ValueUse)) {
						if (Cmp->isEquality() && (isa<ConstantPointerNull>(Cmp->getOperand(0)) ||
						    isa<ConstantPointerNull>(Cmp->getOperand(1))))
							continue;
					}
					return false;
				}
				continue;
			}
			if (!isa<Constant>(U) || !keyUses(U, Seen))
				return false;
		}
		return true;
	}

	void keys(const Constant *C, const GlobalVariable &Table, uint64_t Field, uint64_t Address,
		  int64_t Trampoline = -1)
	{
		const Value *V = C->stripPointerCasts();
		if (const auto *G = dyn_cast<GlobalVariable>(V)) {
			SmallPtrSet<const Value *, 16> Seen;

			if (G->getName().starts_with("__SCK__lsm_static_call_"))
				Keys.push_back({G->getName().str(), Table.getName().str(), Field, Address,
					DL.getTypeAllocSize(Table.getValueType()), Trampoline, keyUses(G, Seen)});
			return;
		}
		if (const auto *S = dyn_cast<ConstantStruct>(C)) {
			const auto *Layout = DL.getStructLayout(S->getType());
			const GlobalVariable *Key = nullptr;
			for (const Use &U : S->operands())
				if (const auto *G = dyn_cast<GlobalVariable>(U->stripPointerCasts()))
					if (G->getName().starts_with("__SCK__lsm_static_call_")) Key = G;
			if (Key)
				for (unsigned I = 0; I < S->getNumOperands(); ++I)
					if (const auto *F = dyn_cast<Function>(S->getOperand(I)->stripPointerCasts()))
						if (F->getName() == "__SCT__" + Key->getName().drop_front(7).str())
							Trampoline = Address + Layout->getElementOffset(I);
			for (unsigned I = 0; I < S->getNumOperands(); ++I)
				keys(cast<Constant>(S->getOperand(I)), Table, Field, Address + Layout->getElementOffset(I), Trampoline);
		} else if (const auto *A = dyn_cast<ConstantArray>(C)) {
			uint64_t Size = DL.getTypeAllocSize(A->getType()->getElementType());
			for (unsigned I = 0; I < A->getNumOperands(); ++I)
				keys(cast<Constant>(A->getOperand(I)), Table, Field, Address + I * Size);
		}
	}

	unsigned functionReferences(const Constant *C, const Function &F, unsigned Depth = 0) const
	{
		if (Depth > 24)
			return 1000000;
		if (C->stripPointerCasts() == &F)
			return 1;
		if (isa<GlobalValue>(C))
			return 0;
		unsigned Count = 0;
		for (const Use &U : C->operands())
			if (const auto *Child = dyn_cast<Constant>(U.get()))
				Count += functionReferences(Child, F, Depth + 1);
		return Count;
	}

public:
	explicit NativeDispatch(Module &M) : DL(M.getDataLayout())
	{
		for (const GlobalVariable &GV : M.globals()) {
			if (!GV.hasInitializer())
				continue;
			registration(GV.getInitializer(), GV, 0);
			if (GV.getName() == "static_calls_table")
				if (const auto *S = dyn_cast<ConstantStruct>(GV.getInitializer())) {
					const auto *Layout = DL.getStructLayout(S->getType());
					for (unsigned I = 0; I < S->getNumOperands(); ++I)
						keys(cast<Constant>(S->getOperand(I)), GV, Layout->getElementOffset(I), Layout->getElementOffset(I));
				}
		}
	}

	std::string key(const CallBase &Call) const
	{
		const Value *V = Call.getCalledOperand()->stripPointerCasts();
		if (const auto *L = dyn_cast<LoadInst>(V)) {
			int64_t Offset = 0;
			if (const auto *G = baseGlobal(L->getPointerOperand(), Offset))
				if (!Offset && G->getName().starts_with("__SCK__lsm_static_call_"))
					return G->getName().str();
		}
		if (const auto *F = dyn_cast<Function>(V)) {
			StringRef Name = F->getName();
			if (Name.consume_front("__SCT__lsm_static_call_"))
				return "__SCK__lsm_static_call_" + Name.str();
		}
		return "";
	}

	bool registeredOnly(const Function &F, const Value *V, SmallPtrSetImpl<const Value *> &Seen) const
	{
		if (!Seen.insert(V).second)
			return true;
		for (const User *U : V->users()) {
			if (const auto *C = dyn_cast<CallBase>(U)) {
				if (C->getCalledOperand() == V && llvm::none_of(C->args(),
					[&](const Use &Arg) { return Arg.get() == V; }))
					continue;
				return false;
			}
			if (const auto *G = dyn_cast<GlobalVariable>(U)) {
				if (RegistrationGlobals.contains(G)) {
					unsigned Count = 0;
					for (const auto &B : Bindings)
						Count += B.Holder == G->getName() && B.Target == F.getName();
					if (Count && G->hasInitializer() && functionReferences(G->getInitializer(), F) == Count)
						continue;
				}
				if (G->getName() == "llvm.used" || G->getName() == "llvm.compiler.used")
					continue;
				return false;
			}
			if (!isa<Constant>(U) || !registeredOnly(F, U, Seen))
				return false;
		}
		return true;
	}

	void validateAssembly(const AssemblyReferences &Assembly)
	{
		for (auto &K : Keys) {
			StringRef Name(K.Name);
			Name.consume_front("__SCK__");
			K.Closed &= !Assembly.Opaque && !Assembly.Symbols.contains(K.Name) &&
				!Assembly.Symbols.contains("__SCT__" + Name.str());
		}
	}

	json::Array bindings() const
	{
		json::Array Out;
		for (const auto &B : Bindings)
			Out.push_back(json::Object{{"holder", B.Holder}, {"target", B.Target},
				{"address", B.Address}, {"table", B.Table}, {"offset", B.Offset}, {"size", B.Size}});
		return Out;
	}
	json::Array keys() const
	{
		json::Array Out;
		for (const auto &K : Keys)
			Out.push_back(json::Object{{"name", K.Name}, {"table", K.Table}, {"offset", K.Offset},
				{"address", K.Address}, {"size", K.Size}, {"trampoline_address", K.Trampoline}, {"closed", K.Closed}});
		return Out;
	}
};

class DescribeModule {
	const DataLayout &DL;
	const NativeDispatch &Dispatch;
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
		if (const auto *L = dyn_cast<LoadInst>(V))
			if (L->getType()->isIntegerTy() && L->getType()->getIntegerBitWidth() <= 64)
				return json::Object{{"kind", "scalar_load"}, {"address", expression(L->getPointerOperand())},
					{"bits", L->getType()->getIntegerBitWidth()}};
		if (const auto *B = dyn_cast<BinaryOperator>(V))
			if (B->getOpcode() == Instruction::And)
				return json::Object{{"kind", "and"}, {"left", value(B->getOperand(0), Pred, Depth + 1)},
					{"right", value(B->getOperand(1), Pred, Depth + 1)}};
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

	/* A read is validated by the branch certificate before entering its
	 * successor. Other reads cannot be silently assumed to be valid inputs.
	 */
	bool guardUsesLoad(const Value *V, const LoadInst *Load, unsigned Depth = 0)
	{
		if (V == Load)
			return true;
		if (!V || Depth > 16)
			return false;
		if (const auto *I = dyn_cast<Instruction>(V))
			if (isa<ICmpInst>(I) || isa<CastInst>(I) ||
			    (isa<BinaryOperator>(I) && I->getOpcode() == Instruction::And))
				for (const Use &U : I->operands())
					if (guardUsesLoad(U.get(), Load, Depth + 1))
						return true;
		return false;
	}

public:
	explicit DescribeModule(Module &M, const json::Array *TokenDecls, const NativeDispatch &Dispatch)
		: DL(M.getDataLayout()), Dispatch(Dispatch)
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
			bool WitnessPrefixSafe = true, WitnessUnvalidatedRead = false;
			for (const Instruction &I : B) {
				const auto *C = dyn_cast<CallBase>(&I);
				bool PrefixSafe = isa<LoadInst>(I) || isa<GetElementPtrInst>(I) ||
					isa<CastInst>(I) || isa<ICmpInst>(I) || isa<CondBrInst>(I) || isa<UncondBrInst>(I) ||
					isa<ReturnInst>(I) || isa<PHINode>(I) || isa<AllocaInst>(I) ||
					(isa<BinaryOperator>(I) && I.getOpcode() == Instruction::And);

				if (const auto *L = dyn_cast<LoadInst>(&I)) {
					const auto *Br = dyn_cast<CondBrInst>(B.getTerminator());

					WitnessUnvalidatedRead = true;
					if (!L->getType()->isIntegerTy() || !Br || !guardUsesLoad(Br->getCondition(), L))
						PrefixSafe = false;
				}
				/* This certificate is independent of ownership/effect coverage. */
				if (!C && !PrefixSafe)
					WitnessPrefixSafe = false;
				if (const auto *Intr = dyn_cast_or_null<IntrinsicInst>(C))
					if (Intr->getIntrinsicID() == Intrinsic::assume)
						WitnessPrefixSafe = false;
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
					{"dispatch_key", Dispatch.key(*C)}, {"signature", signature(C->getFunctionType())},
					{"witness_prefix_safe", WitnessPrefixSafe && !WitnessUnvalidatedRead}, {"arguments", std::move(Args)}});
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
			json::Object Block{{"id", Blocks.lookup(&B)}, {"calls", std::move(Sites)},
				{"witness_tail_safe", WitnessPrefixSafe}};
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
			{"signature", signature(F.getFunctionType())},
			{"covered", Covered}, {"complete", Complete}, {"nargs", F.arg_size()},
			{"contract_complete", ContractComplete},
			{"memory_covered", MemoryCovered}, {"witness_covered", MemoryCovered},
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
		NativeDispatch Dispatch(*Copy);
		DescribeModule Describe(*Copy, AST.getArray("tokens"), Dispatch);
		json::Array Functions;
		AssemblyReferences Assembly(*Copy);
		Dispatch.validateAssembly(Assembly);
		for (Function &F : *Copy) {
			auto Record = Describe.function(F, Decls[F.getName().str()], Covered);
			SmallPtrSet<const Value *, 16> RegistrationUses;
			if (Dispatch.registeredOnly(F, &F, RegistrationUses))
				Record["escaped"] = false;
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
			{"types", std::move(Types)}, {"tokens", std::move(Tokens)},
			{"dispatch_bindings", Dispatch.bindings()}, {"dispatch_keys", Dispatch.keys()}};
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
