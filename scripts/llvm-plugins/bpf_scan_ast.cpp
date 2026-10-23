// SPDX-License-Identifier: GPL-2.0-only
/* bpf_scan_ast: preserve source locking facts before Clang emits LLVM IR. */

#include "bpf_scan_ast_metadata.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclGroup.h"
#include "clang/AST/Expr.h"
#include "clang/AST/GlobalDecl.h"
#include "clang/AST/Mangle.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/Lex/Preprocessor.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>

#if CLANG_VERSION_MAJOR < 23
#error "bpf_scan_ast requires Clang 23 or later"
#endif

using namespace clang;
using llvm::StringRef;
namespace json = llvm::json;

namespace {

constexpr unsigned MaxExprDepth = 32;

static bool isLockContract(const Attr *A)
{
	return llvm::isa<AcquireCapabilityAttr, ReleaseCapabilityAttr,
		TryAcquireCapabilityAttr, RequiresCapabilityAttr, LocksExcludedAttr,
		AssertCapabilityAttr, LockReturnedAttr, NoThreadSafetyAnalysisAttr>(A);
}

static bool hasLockContract(const FunctionDecl *F)
{
	for (const FunctionDecl *D : F->redecls())
		for (const Attr *A : D->attrs())
			if (isLockContract(A))
				return true;
	return false;
}

class LockCollector : public RecursiveASTVisitor<LockCollector> {
	ASTContext &Ctx;
	SourceManager &SM;
	std::unique_ptr<MangleContext> Mangler;
	const FunctionDecl *Current = nullptr;
	std::vector<const FunctionDecl *> Functions;
	llvm::DenseMap<const FunctionDecl *, unsigned> FunctionIDs;
	llvm::DenseMap<const ValueDecl *, unsigned> LocalIDs;
	std::set<const Decl *> SeenTypes, SeenTokens;
	json::Array Types, Tokens, Guarded, Calls, Cleanups;

	json::Object fileLocation(SourceLocation L) const
	{
		if (L.isInvalid())
			return json::Object{{"valid", false}};
		return json::Object{{"valid", true}, {"file", SM.getFilename(L).str()},
			{"offset", static_cast<int64_t>(SM.getFileOffset(L))},
			{"line", static_cast<int64_t>(SM.getSpellingLineNumber(L))},
			{"column", static_cast<int64_t>(SM.getSpellingColumnNumber(L))}};
	}

	json::Object location(SourceLocation L) const
	{
		return json::Object{{"expansion", fileLocation(SM.getExpansionLoc(L))},
			{"spelling", fileLocation(SM.getSpellingLoc(L))}};
	}

	std::string symbol(const NamedDecl *D)
	{
		if (const auto *A = D->getAttr<AsmLabelAttr>())
			return A->getLabel().str();
		if (!Mangler->shouldMangleDeclName(D))
			return D->getNameAsString();
		std::string Name;
		llvm::raw_string_ostream OS(Name);
		Mangler->mangleName(GlobalDecl(D), OS);
		return Name;
	}

	unsigned needFunction(const FunctionDecl *F)
	{
		F = F->getCanonicalDecl();
		auto It = FunctionIDs.find(F);
		if (It != FunctionIDs.end())
			return It->second;
		unsigned ID = Functions.size();
		FunctionIDs[F] = ID;
		Functions.push_back(F);
		return ID;
	}

	/* token_context_lock[_instance] declares an extern pointer to an empty
	 * capability whose reserved type name starts with __ctx_lock_. There is
	 * deliberately no runtime object or pointer value to resolve.
	 */
	const RecordDecl *tokenType(const VarDecl *V) const
	{
		if (!V->hasExternalStorage() || V->hasInit() || !V->getType()->isPointerType())
			return nullptr;
		const auto *T = V->getType()->getPointeeType()->getAs<RecordType>();
		const RecordDecl *R = T ? T->getDecl()->getDefinition() : nullptr;
		if (!R || !R->getName().starts_with("__ctx_lock_") || !R->field_empty() ||
		    !R->hasAttr<CapabilityAttr>())
			return nullptr;
		return R;
	}

	json::Object declaration(const ValueDecl *D)
	{
		json::Object O{{"name", D->getNameAsString()},
			{"type", D->getType().getCanonicalType().getAsString()},
			{"location", location(D->getLocation())}};
		if (const auto *V = llvm::dyn_cast<VarDecl>(D)) {
			if (V->isFileVarDecl() || V->hasExternalStorage()) {
				O["kind"] = tokenType(V) ? "token" : "global";
				O["symbol"] = symbol(V);
				O["local_linkage"] = !V->isExternallyVisible();
				return O;
			}
			const auto *Owner = llvm::dyn_cast<FunctionDecl>(V->getDeclContext());
			O["kind"] = "local";
			O["id"] = static_cast<int64_t>(LocalIDs.try_emplace(D, LocalIDs.size()).first->second);
			O["static_storage"] = V->isStaticLocal();
			if (Owner)
				O["function"] = static_cast<int64_t>(needFunction(Owner));
			return O;
		}
		O["kind"] = "field";
		return O;
	}

	json::Object field(const FieldDecl *F)
	{
		const RecordDecl *R = F->getParent();
		json::Object O{{"name", F->getNameAsString()},
			{"type", F->getType().getCanonicalType().getAsString()},
			{"record", R->getQualifiedNameAsString()},
			{"record_location", location(R->getLocation())},
			{"index", static_cast<int64_t>(F->getFieldIndex())},
			{"bitfield", F->isBitField()}, {"union", R->isUnion()}};
		if (R->isCompleteDefinition() && !R->isInvalidDecl() && !R->isDependentContext()) {
			uint64_t Offset = Ctx.getASTRecordLayout(R).getFieldOffset(F->getFieldIndex());
			O["offset_bits"] = static_cast<int64_t>(Offset);
		}
		return O;
	}

	json::Object unknown(const Expr *E, StringRef Reason) const
	{
		json::Object O{{"kind", "unknown"}, {"reason", Reason.str()}};
		if (E) {
			O["ast"] = E->getStmtClassName();
			O["location"] = location(E->getExprLoc());
		}
		return O;
	}

	json::Object expression(const Expr *E, const FunctionDecl *Scope,
				unsigned Depth = 0)
	{
		auto O = expressionImpl(E, Scope, Depth);
		if (E) {
			O["type"] = E->getType().getCanonicalType().getAsString();
			O["pointer_value"] = E->getType()->isPointerType();
		}
		return O;
	}

	json::Object expressionImpl(const Expr *E, const FunctionDecl *Scope,
				    unsigned Depth)
	{
		if (!E || Depth >= MaxExprDepth)
			return unknown(E, E ? "depth_limit" : "missing_expression");
		E = E->IgnoreParens();
		auto Child = [&](const Expr *V) { return expression(V, Scope, Depth + 1); };
		if (const auto *R = llvm::dyn_cast<DeclRefExpr>(E)) {
			const ValueDecl *D = R->getDecl();
			if (const auto *P = llvm::dyn_cast<ParmVarDecl>(D)) {
				const auto *Owner = llvm::dyn_cast<FunctionDecl>(P->getDeclContext());
				if (!Owner || !Scope || Owner->getCanonicalDecl() != Scope->getCanonicalDecl())
					return unknown(E, "foreign_parameter");
				return json::Object{{"kind", "parameter"},
					{"index", static_cast<int64_t>(P->getFunctionScopeIndex())}};
			}
			if (const auto *F = llvm::dyn_cast<FieldDecl>(D))
				return json::Object{{"kind", "implicit_member"}, {"field", field(F)}};
			if (llvm::isa<VarDecl>(D))
				return declaration(D);
			if (const auto *C = llvm::dyn_cast<EnumConstantDecl>(D)) {
				llvm::SmallString<32> Value;
				C->getInitVal().toString(Value, 10);
				return json::Object{{"kind", "integer"}, {"value", Value.str().str()},
					{"bits", static_cast<int64_t>(C->getInitVal().getBitWidth())},
					{"signed", C->getInitVal().isSigned()}};
			}
		}
		if (const auto *M = llvm::dyn_cast<MemberExpr>(E)) {
			if (const auto *F = llvm::dyn_cast<FieldDecl>(M->getMemberDecl()))
				return json::Object{{"kind", "member"}, {"base", Child(M->getBase())},
					{"arrow", M->isArrow()}, {"field", field(F)}};
		}
		if (const auto *U = llvm::dyn_cast<UnaryOperator>(E))
			return json::Object{{"kind", "unary"},
				{"op", UnaryOperator::getOpcodeStr(U->getOpcode()).str()},
				{"value", Child(U->getSubExpr())}};
		if (const auto *C = llvm::dyn_cast<CastExpr>(E))
			return json::Object{{"kind", "cast"}, {"cast", C->getCastKindName()},
				{"type", C->getType().getCanonicalType().getAsString()},
				{"value", Child(C->getSubExpr())}};
		if (const auto *I = llvm::dyn_cast<IntegerLiteral>(E)) {
			llvm::SmallString<32> Value;
			I->getValue().toString(Value, 10, false);
			return json::Object{{"kind", "integer"}, {"value", Value.str().str()},
				{"bits", static_cast<int64_t>(I->getValue().getBitWidth())},
				{"signed", I->getType()->isSignedIntegerType()}};
		}
		if (const auto *S = llvm::dyn_cast<ArraySubscriptExpr>(E))
			return json::Object{{"kind", "subscript"}, {"base", Child(S->getBase())},
				{"index", Child(S->getIdx())}};
		if (const auto *B = llvm::dyn_cast<BinaryOperator>(E))
			return json::Object{{"kind", "binary"}, {"op", B->getOpcodeStr().str()},
				{"left", Child(B->getLHS())}, {"right", Child(B->getRHS())}};
		if (const auto *C = llvm::dyn_cast<ConditionalOperator>(E))
			return json::Object{{"kind", "conditional"}, {"condition", Child(C->getCond())},
				{"true", Child(C->getTrueExpr())}, {"false", Child(C->getFalseExpr())}};
		if (const auto *Call = llvm::dyn_cast<CallExpr>(E)) {
			if (const FunctionDecl *F = Call->getDirectCallee()) {
				json::Array Args;
				for (const Expr *Arg : Call->arguments())
					Args.push_back(Child(Arg));
				return json::Object{{"kind", "call"},
					{"function", static_cast<int64_t>(needFunction(F))},
					{"arguments", std::move(Args)}};
			}
		}
		return unknown(E, "unsupported_expression");
	}

	template <typename T>
	json::Object lockArguments(const T *A, StringRef Op, StringRef Mode,
				 const FunctionDecl *F)
	{
		json::Array Locks;
		for (const Expr *E : A->args())
			Locks.push_back(expression(E, F));
		return json::Object{{"op", Op.str()}, {"mode", Mode.str()},
			{"locks", std::move(Locks)}, {"implicit_lock", A->args_size() == 0},
			{"unresolved", A->delayedArgs_size() != 0}};
	}

	json::Object contract(const Attr *A, const FunctionDecl *F)
	{
		if (const auto *L = llvm::dyn_cast<AcquireCapabilityAttr>(A))
			return lockArguments(L, "acquire", L->isShared() ? "shared" : "exclusive", F);
		if (const auto *L = llvm::dyn_cast<ReleaseCapabilityAttr>(A))
			return lockArguments(L, "release", L->isGeneric() ? "generic" :
					     L->isShared() ? "shared" : "exclusive", F);
		if (const auto *L = llvm::dyn_cast<TryAcquireCapabilityAttr>(A)) {
			auto O = lockArguments(L, "try_acquire", L->isShared() ? "shared" : "exclusive", F);
			O["success"] = expression(L->getSuccessValue(), F);
			return O;
		}
		if (const auto *L = llvm::dyn_cast<RequiresCapabilityAttr>(A))
			return lockArguments(L, "require", L->isShared() ? "shared" : "exclusive", F);
		if (const auto *L = llvm::dyn_cast<LocksExcludedAttr>(A))
			return lockArguments(L, "exclude", "generic", F);
		if (const auto *L = llvm::dyn_cast<AssertCapabilityAttr>(A))
			return lockArguments(L, "assert", L->isShared() ? "shared" : "exclusive", F);
		if (const auto *L = llvm::dyn_cast<LockReturnedAttr>(A))
			return json::Object{{"op", "returns_lock"}, {"lock", expression(L->getArg(), F)}};
		return json::Object{{"op", "analysis_disabled"}};
	}

	json::Object function(const FunctionDecl *F, unsigned ID)
	{
		const FunctionDecl *Definition = nullptr;
		bool Defined = F->hasBody(Definition);
		const FunctionDecl *D = Defined ? Definition : F->getMostRecentDecl();
		json::Array Contracts, Parameters;
		std::set<std::string> Seen;
		for (const FunctionDecl *R : F->redecls()) {
			for (const Attr *A : R->attrs()) {
				if (!isLockContract(A))
					continue;
				json::Value C(contract(A, R));
				std::string Key;
				llvm::raw_string_ostream OS(Key);
				OS << C;
				if (!Seen.insert(Key).second)
					continue;
				(*C.getAsObject())["location"] = location(A->getLocation());
				(*C.getAsObject())["spelling"] = A->getSpelling();
				Contracts.push_back(std::move(C));
			}
		}
		for (const ParmVarDecl *P : D->parameters())
			Parameters.push_back(json::Object{{"name", P->getNameAsString()},
				{"type", P->getType().getCanonicalType().getAsString()}});
		return json::Object{{"id", static_cast<int64_t>(ID)}, {"symbol", symbol(D)},
			{"asm_label", D->hasAttr<AsmLabelAttr>()},
			{"local_linkage", !D->isExternallyVisible()},
			{"weak", D->hasAttr<WeakAttr>()},
			{"defined", Defined}, {"location", location(D->getLocation())},
			{"variadic", D->isVariadic()},
			{"return_type", D->getReturnType().getCanonicalType().getAsString()},
			{"parameters", std::move(Parameters)}, {"contracts", std::move(Contracts)}};
	}

	void guardedDeclaration(const ValueDecl *D)
	{
		json::Array Annotations;
		for (const Attr *A : D->attrs()) {
			json::Array Locks;
			StringRef Op;
			if (const auto *G = llvm::dyn_cast<GuardedByAttr>(A)) {
				Op = "guarded_by";
				for (const Expr *E : G->args())
					Locks.push_back(expression(E, Current));
			} else if (const auto *G = llvm::dyn_cast<PtGuardedByAttr>(A)) {
				Op = "pt_guarded_by";
				for (const Expr *E : G->args())
					Locks.push_back(expression(E, Current));
			} else if (llvm::isa<GuardedVarAttr>(A)) {
				Op = "guarded_var";
			} else if (llvm::isa<PtGuardedVarAttr>(A)) {
				Op = "pt_guarded_var";
			} else {
				continue;
			}
			Annotations.push_back(json::Object{{"op", Op.str()},
				{"locks", std::move(Locks)}, {"location", location(A->getLocation())}});
		}
		if (Annotations.empty())
			return;
		auto O = declaration(D);
		if (const auto *F = llvm::dyn_cast<FieldDecl>(D))
			O["field"] = field(F);
		O["annotations"] = std::move(Annotations);
		Guarded.push_back(std::move(O));
	}

public:
	explicit LockCollector(ASTContext &Ctx)
		: Ctx(Ctx), SM(Ctx.getSourceManager()), Mangler(Ctx.createMangleContext()) {}

	bool TraverseFunctionDecl(FunctionDecl *F)
	{
		if (!F || F->isInvalidDecl())
			return true;
		if (hasLockContract(F))
			needFunction(F);
		if (!F->doesThisDeclarationHaveABody())
			return true;
		const FunctionDecl *Saved = Current;
		Current = F;
		// Do not mistake calls inside attribute expressions for executed calls.
		bool Result = TraverseStmt(F->getBody());
		Current = Saved;
		return Result;
	}

	bool VisitCallExpr(CallExpr *Call)
	{
		const FunctionDecl *Callee = Call->getDirectCallee();
		if (!Current || !Callee || !hasLockContract(Callee))
			return true;
		json::Array Args;
		for (const Expr *Arg : Call->arguments())
			Args.push_back(expression(Arg, Current));
		Calls.push_back(json::Object{{"caller", static_cast<int64_t>(needFunction(Current))},
			{"callee", static_cast<int64_t>(needFunction(Callee))},
			{"location", location(Call->getExprLoc())}, {"arguments", std::move(Args)}});
		return true;
	}

	bool VisitRecordDecl(RecordDecl *R)
	{
		const RecordDecl *D = R->getDefinition();
		if (!D)
			D = R->getMostRecentDecl();
		if (!D->hasAttr<CapabilityAttr>() && !D->hasAttr<ReentrantCapabilityAttr>() &&
		    !D->hasAttr<ScopedLockableAttr>())
			return true;
		if (!SeenTypes.insert(R->getCanonicalDecl()).second)
			return true;
		json::Object O{{"name", D->getQualifiedNameAsString()},
			{"location", location(D->getLocation())},
			{"reentrant", D->hasAttr<ReentrantCapabilityAttr>()},
			{"scoped", D->hasAttr<ScopedLockableAttr>()}};
		O["record_kind"] = D->isUnion() ? "union" : "struct";
		if (D->isCompleteDefinition() && !D->isInvalidDecl()) {
			O["size_bits"] = static_cast<int64_t>(Ctx.getASTRecordLayout(D).getSize().getQuantity()) *
				Ctx.getTargetInfo().getCharWidth();
			json::Array Fields;
			for (const FieldDecl *F : D->fields())
				Fields.push_back(field(F));
			O["fields"] = std::move(Fields);
		}
		if (const auto *A = D->getAttr<CapabilityAttr>()) {
			O["capability"] = A->getName().str();
			O["shared"] = A->isShared();
		}
		Types.push_back(std::move(O));
		return true;
	}

	bool VisitFieldDecl(FieldDecl *F)
	{
		guardedDeclaration(F);
		return true;
	}

	bool VisitVarDecl(VarDecl *V)
	{
		guardedDeclaration(V);
		if (const RecordDecl *R = tokenType(V))
			if (SeenTokens.insert(V->getCanonicalDecl()).second)
				Tokens.push_back(json::Object{{"name", symbol(V)},
					{"capability", R->getAttr<CapabilityAttr>()->getName().str()},
					{"reentrant", R->hasAttr<ReentrantCapabilityAttr>()}});
		if (Current)
			if (const auto *A = V->getAttr<CleanupAttr>())
				Cleanups.push_back(json::Object{
					{"caller", static_cast<int64_t>(needFunction(Current))},
					{"callee", static_cast<int64_t>(needFunction(A->getFunctionDecl()))},
					{"variable", declaration(V)}, {"location", location(V->getLocation())}});
		return true;
	}

	json::Object take(StringRef Unit, bool AnnotationsEnabled)
	{
		json::Array Descriptions;
		// Serializing a lock-returned expression can discover another function.
		for (unsigned I = 0; I < Functions.size(); I++)
			Descriptions.push_back(function(Functions[I], I));
		return json::Object{{"format", BPF_SCAN_LOCK_FORMAT}, {"version", BPF_SCAN_LOCK_VERSION},
			{"unit", Unit.str()}, {"target", Ctx.getTargetInfo().getTriple().str()},
			{"char_bits", static_cast<int64_t>(Ctx.getTargetInfo().getCharWidth())},
			{"pointer_bits", static_cast<int64_t>(Ctx.getTypeSize(Ctx.VoidPtrTy))},
			{"annotations_enabled", AnnotationsEnabled},
			{"functions", std::move(Descriptions)}, {"types", std::move(Types)},
			{"tokens", std::move(Tokens)},
			{"guarded", std::move(Guarded)}, {"calls", std::move(Calls)},
			{"cleanups", std::move(Cleanups)}};
	}
};

class LockConsumer : public ASTConsumer {
	CompilerInstance &CI;
	std::string Unit;

public:
	LockConsumer(CompilerInstance &CI, StringRef Unit) : CI(CI), Unit(Unit.str()) {}

	void HandleTranslationUnit(ASTContext &Ctx) override
	{
		if (CI.getDiagnostics().hasErrorOccurred())
			return;
		Preprocessor &PP = CI.getPreprocessor();
		bool Enabled = PP.isMacroDefined("WARN_CONTEXT_ANALYSIS") &&
			!PP.isMacroDefined("__CHECKER__") && !PP.isMacroDefined("__GENKSYMS__");
		LockCollector Collector(Ctx);
		if (Enabled)
			Collector.TraverseDecl(Ctx.getTranslationUnitDecl());
		std::string Data;
		llvm::raw_string_ostream OS(Data);
		OS << json::Value(Collector.take(Unit, Enabled));

		// Only synthesize a data declaration. Do not annotate or retain functions.
		SourceManager &SM = Ctx.getSourceManager();
		SourceLocation Loc = SM.getLocForStartOfFile(SM.getMainFileID());
		QualType Type = Ctx.getConstantArrayType(Ctx.CharTy.withConst(),
			llvm::APInt(64, Data.size() + 1), nullptr, ArraySizeModifier::Normal, 0);
		auto *D = VarDecl::Create(Ctx, Ctx.getTranslationUnitDecl(), Loc, Loc,
			&Ctx.Idents.get("__bpf_scan_ast_locks"), Type,
			Ctx.getTrivialTypeSourceInfo(Type), SC_Static);
		D->setImplicit();
		D->setInit(StringLiteral::Create(Ctx, Data, StringLiteralKind::Ordinary,
			false, Type, llvm::ArrayRef<SourceLocation>(Loc)));
		D->addAttr(UsedAttr::CreateImplicit(Ctx));
		D->addAttr(NoDebugAttr::CreateImplicit(Ctx));
		D->addAttr(SectionAttr::CreateImplicit(Ctx, BPF_SCAN_LOCK_SECTION));
		Ctx.getTranslationUnitDecl()->addDecl(D);
		// The main CodeGen consumer has not finalized its module yet. Deliver
		// the synthetic top-level declaration through the multiplexed consumer.
		CI.getASTConsumer().HandleTopLevelDecl(DeclGroupRef(D));
	}
};

class BpfScanASTAction : public PluginASTAction {
	std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
						    StringRef File) override
	{
		return std::make_unique<LockConsumer>(CI, File);
	}

	bool ParseArgs(const CompilerInstance &CI,
		       const std::vector<std::string> &Args) override
	{
		if (Args.empty() && !CI.getLangOpts().CPlusPlus)
			return true;
		unsigned ID = CI.getDiagnostics().getCustomDiagID(DiagnosticsEngine::Error,
			"bpf_scan_ast requires a C translation unit and accepts no plugin arguments");
		CI.getDiagnostics().Report(ID);
		return false;
	}

	ActionType getActionType() override { return AddBeforeMainAction; }
};

static FrontendPluginRegistry::Add<BpfScanASTAction>
	Register("bpf_scan_ast", "preserve locking annotations for BPF analysis");

} // namespace
