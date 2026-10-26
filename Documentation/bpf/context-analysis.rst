.. SPDX-License-Identifier: GPL-2.0-only

BPF Context Analysis
====================

This facility preserves declared locking contracts and derives locking facts
for native kernel functions. It does not change the verifier or attachment
permissions. Interrupt, preemption and scheduling contexts are outside version 1.

Enable ``CONFIG_CLANG_PLUGIN_BPF_CONTEXT_IR`` together with the AST collector
and BTF debug information. The first implementation requires non-LTO builds;
merged LTO documents and clones are not yet certified. Kernel and module BTF
generation automatically passes ``--context_analysis`` to resolve_btfids.

Data flow
---------

``bpf_scan_ast`` collects Clang capability annotations into ``.bpf_scan.lock``.
``bpf_context_ir`` imports them before inlining, describes the executable IR
control flow and calls, and exports summaries into ``.bpf_context`` after
optimization. ``resolve_btfids/context.c`` resolves the linked descriptions and
adds BTF declaration tags before BTF deduplication and finalization. Pahole
continues to generate ordinary BTF from DWARF; it needs no changes.

Both ELF sections are build-only INFO sections. Runtime tags distinguish declared/derived ownership, conservative acquisition
candidates and positive acquisition-path witnesses. Missing tags never establish
the absence of locking effects.
The fmodret scanner and resolver are independent of this pipeline.

Runtime format
--------------

All tags use ``BTF_KIND_DECL_TAG`` with ``component_idx = -1``. Function facts
refer to the native ``BTF_KIND_FUNC``; capability properties refer to the native
``BTF_KIND_STRUCT`` or ``BTF_KIND_UNION``, preserving existing typedef links.

Function tags have this exact grammar::

  bpf_context:v1:SOURCE:FACT:MODE:LOCK:CONDITION

``SOURCE`` is ``declared`` or ``derived``. Declared facts are trusted source
contracts, not a claim that the collector proved their implementations.
``FACT`` is ``requires``, ``excludes``, ``acquires``, ``releases``,
``may_acquire`` or ``entry_held``. ``MODE`` is ``exclusive``, ``shared`` or
``generic``; generic means mode independent, never unknown.

``LOCK`` is a symbolic expression::

  arg(N)             zero-based native function parameter
  add(EXPR,N)        address plus signed byte offset
  load(EXPR)         pointer loaded from that address
  global(NAME)       unique linked ELF symbol, relative to this BTF object
  token(NAME)        abstract named context, with no ELF object or address

Names contain only ASCII letters, digits, underscore, dot and dollar. A local
symbol whose name is ambiguous cannot be emitted. Local stack expressions are
retained only in build data. Native parameter/member types describe the lock
type, so function tags do not duplicate a lock-kind enumeration.

``CONDITION`` is ``always``, ``ret_eq(N)`` or ``ret_ne(N)``, with signed decimal
N. Conditional acquisition is an exit effect: the function returns holding the
lock on the specified return branch. ``may_acquire`` is a conservative internal-acquisition candidate, including locks
released before returning. Transitive propagation does not prove path feasibility; ``always`` imposes no
return-value restriction and does not assert that every execution acquires it.
``entry_held`` describes ownership inherited from every possible caller.

Positive acquisition paths use a separate function tag::

  bpf_context:v1:witness:MODE:LOCK:GUARD:VIA

``GUARD`` is ``always`` or ``bits_eq(ADDRESS,BITS,MASK,VALUE)``. It describes a
sufficient, consistent equality on a native integer input field: the field read
at ADDRESS, with width BITS, satisfies ``(field & MASK) == VALUE``. Supported
zero comparisons and one-bit inequalities are combined through direct calls;
conflicting masks on the same field reject the path. Constraints on multiple
unrelated fields, unknown predicates and integer extension ambiguities are not
proved. Native BTF validates the scalar width and physical lock path.

``VIA`` records ``function@call/function@call/primitive[declared]``. A witness
proves a supported path reaches a declared acquisition of the specified lock;
it does not claim every execution takes that path or that acquisition completes
when the lock is already held. The locking primitive's source contract is the
explicit trust boundary, not an independent proof of its implementation.

The initial proof language stops at the first ordinary call and permits only
pure supported prefixes before it. Writes, opaque calls, assumptions, unrelated
reads and unsupported instructions withhold the witness. A scalar guard read
must be checked on the branch before the acquisition; its address cannot itself
contain a pointer load. Captured, local and pointer-loaded lock identities are
not emitted as witnesses. Recursion, CFG and result budgets only reduce positive
coverage. No witness is inferred from the transitive ``may_acquire`` set.

Bpftool labels ordinary ``may_acquire`` candidates ``[unproven path]`` and
prints witnesses separately, with the scalar member name, bit mask and call
chain. JSON uses ``evidence: candidate`` versus ``evidence: path``. Absence of a
witness is unknown; it never certifies a lock-free function. Complete-summary
tags continue to describe the conservative candidate/effect summary, independently
of witnesses. Withholding a witness never upgrades completeness.


There is one additional positive function fact::

  bpf_context:v1:derived:lock_summary_complete

It certifies that the transitive locking summary is complete within the
version-1 locking model, including internal acquisitions. Only together with
this tag does an empty effect list establish the absence of locking effects.
Unresolved calls, inline assembly, unsupported expressions, unannotated
translation units and unresolved recursive summaries prevent completeness.
Function annotations do not by themselves certify a complete body summary.
As in Clang context analysis, a fully represented declared contract is trusted
for call-site ownership transitions. Exit-effect propagation is separate from
internal-effect completeness: a caller can derive that it returns holding a
lock even when an annotated callee's internal acquisitions are not fully known.
Such a caller does not receive a complete-summary tag.
For physical ``spinlock`` and ``raw_spinlock`` instances, ownership preservation
also uses complete direct-call interfaces collected with annotations enabled.
The Clang interface convention is no ownership transfer unless a release is
declared. A complete caller-side interface can therefore preserve incoming
spin ownership when the linked implementation did not opt in. This trusts the
interface contract; it does not independently verify that unchecked body or
certify its internal acquisitions. A missing external implementation, an
analysis-disabled interface and an unresolved indirect call remain unknown.
Bodies covered by analysis still contribute their writes and release effects,
so a possibly overlapping write or release invalidates definite ownership.
Raw memory writes also prevent completeness unless their semantics are supplied
by a declared callee contract; this pass does not infer locking from atomic
instruction patterns.

Type tags are::

  bpf_context:v1:capability:NAME
  bpf_context:v1:reentrant
  bpf_context:v1:scoped

NAME is the declared Clang capability name, not an invented lock class. The
native BTF type provides identity. Capability names do not establish sleeping,
IRQ or scheduling properties. Type matching checks record kind, layout and
members and omits ambiguous matches. Numeric BTF IDs are never embedded in tag
strings; normal BTF references survive deduplication, sorting and split BTF.

Example
-------

``atomic_dec_and_mutex_lock(cnt, lock)`` declares conditional exclusive
acquisition of its second argument on a nonzero return::

  bpf_context:v1:declared:acquires:exclusive:arg(1):ret_ne(0)

Its internal mutex acquisition is relevant even when a subsequent unlock
balances it::

  bpf_context:v1:derived:may_acquire:exclusive:arg(1):always

The native ``struct mutex`` carries ``bpf_context:v1:capability:mutex``.

Symbolic contexts and shared ownership
-------------------------------------

``token_context_lock()`` and ``token_context_lock_instance()`` declare symbolic
capabilities. Their extern pointer declarations identify context tokens rather
than mutable pointer loads. Preserve token names, capability classes and
reentrancy in the compiler transport. Conflicting declarations suppress the
corresponding token's runtime facts.

Runtime token identities use zero-sized ``BTF_KIND_STRUCT`` records named
``__bpf_context_token_NAME``. They describe abstract contexts, have no ELF
storage and carry ``bpf_context:v1:token:NAME``, a capability tag and, where
applicable, a reentrant tag. Split BTF reuses matching base token identities.
Function facts refer to them through ``token(NAME)``. Token names distinguish
instances even when they share a capability class.

The standard ``RCU``, ``RCU_BH`` and ``RCU_SCHED`` tokens are shared and
reentrant. The BH and scheduler reader APIs acquire both their flavor token
and ``RCU``. SRCU continues to use its physical ``srcu_struct`` lock identity.
Reader APIs without existing context annotations remain unmodelled.

Track per-path ownership depth and net acquisition/release balance. A nested
RCU unlock removes one level and preserves an outer read-side critical section.
Reentrant physical locks use matched BTF capability properties when available.
A release of one symbolic token preserves other tokens and physical locks;
physical releases cannot alias symbolic tokens. Unknown calls still invalidate
ownership. Assertion attributes establish no new ownership in this analysis;
empty compiler assertion helpers are analyzed as ordinary neutral bodies. Exit facts currently encode one level, so multi-level net exit
effects prevent an inferred complete exit summary.

At control-flow joins and across callers, exclusive ownership can satisfy a
shared requirement. Mixed shared/exclusive guarantees yield shared ownership.
Entry facts express a positive ownership guarantee, without a numeric depth.
For cyclic CFGs, a separate bounded must-ownership fixed point intersects all
reachable predecessors and retains the minimum common nesting depth. It can
prove call-site ownership without certifying complete exit effects for a loop.
If this analysis exceeds its budget, all of that function's site guarantees
are discarded.
An unresolved conditional acquisition is discarded if an intervening lock
operation can invalidate it. Conditional releases invalidate the possibly
released ownership immediately; deriving a complete exit summary for them
requires a richer correlated state.

Build-time identity and incompleteness
-------------------------------------

Three ``--verbose`` flags on resolve_btfids print the call, write or pointer
capture which removes a definite ownership fact. ``BPF_CONTEXT_TRACE=NAME``
restricts these ownership-loss diagnostics to one function. This diagnostic
does not weaken unknown effects or change the emitted facts.

The IR transport is versioned NUL-delimited JSON, one document per compilation
unit, with ``format``, ``version``, ``unit``, ``types``, ``tokens`` and
``functions``. Version 2 adds symbolic-token declarations. IR transport
version 3 adds write events (address and byte width) and memory-effect
coverage. Version 2 remains readable without the new preservation proofs.
Version 4 adds scalar-load/AND branch values, per-call safe-prefix flags,
per-block safe-tail flags and function-level witness coverage. Versions 2 and 3
remain readable but cannot supply new body-path certificates. Version 3 also records pointer snapshots and ordered capture events. Each
snapshot identifies one SSA pointer value from a load or a supported getter.
Repeated reads have distinct identities. A capture executed again in a loop
invalidates ownership tied to that definition's previous dynamic instance.
When the captured pointer is passed directly to a callee, its ownership can
be expressed relative to that callee's argument. Snapshot IDs never enter
runtime tags. Possible acquisition paths are expanded for display, while
entry paths requiring an unproved relation to a reloaded field are omitted.
Net exit effects containing a callee-local snapshot cannot be exported as
caller ownership. Incoming argument substitution may bind a caller's captured
value, but a callee's private snapshot number never denotes that value.
Function and call numbers are document local. Direct global calls resolve to
the selected strong/weak linked symbol. Local calls first resolve within their
compilation unit. Function records retain contracts, argument substitutions,
CFG edges, call-result tests and returns. Optimization survivors are marked
separately; deleted inline bodies may still describe calls made by surviving
functions. Unmatched clones are incomplete, not matched by name prefixes.

Ownership preservation is independent of complete acquisition/exit summaries.
A monotone fixed point collects possible invalidating writes and ownership
releases, including through loops and recursion. Trusted contracts describe
ownership changes across primitive calls. Opaque calls, missing body coverage
without a usable ownership interface, unrepresentable effects and analysis-budget
exhaustion prevent a preservation proof. Writes to fresh local stack storage cannot clobber a
caller's valid lock.

At each call or write, retain ownership only when its lock storage is provably
unaffected by all possible invalidations. Declared releases refer to lock
instance addresses. Distinct offsets from the same pointer identify distinct
instances, including an inner lock within an outer capability; equal addresses
remain potentially aliased wrapper instances. Raw writes affect byte ranges,
so a write inside an outer lock's storage still invalidates it without a
trusted contract. Byte ranges rooted in the same
pointer can be separated using native BTF capability sizes. Different pointer
arguments may alias and are not assumed disjoint. Linked ELF object ranges
separate distinct globals only when both accesses stay within their objects
and the section/range identities prove non-overlap. Symbol aliases and
ambiguous names remain potentially aliasing.
Raw stores conservatively invalidate symbolic contexts, whose implementation
storage is not described by a physical lock path. Preserving an incoming lock
does not certify a complete summary of locks acquired internally.

Build diagnostics retain reasons for missing proofs. No ``unknown`` fact is
loaded into the kernel. Use ``--verbose --verbose`` to report each entry
rejection and the incoming call sites where some ownership is available.
The output distinguishes caller closure, missing ownership at callers,
unrepresentable common locks, native identity failures and emission failures.
Acquisition budgets and propagated incompleteness are counted separately.
Without a closed caller set, no derived entry ownership
is emitted. In particular, externally callable functions cannot acquire an
entry guarantee merely because their observed C callers hold a lock.

For a global definition, Kbuild retains native relocations in the first linked
image and supplies the absolute symbol ``__bpf_context_native_calls=1`` to
record ``--emit-relocs`` coverage. The resolver requires that marker and
allocated text relocations before closing any global caller set. This is
supported for linked x86-64 and ARM64 images, including the relocatable ARM64
kernel. Relocatable object files and ordinary shared libraries retain open
global caller sets.

Every native entry reference must be a direct call or tail call accounted for
by a surviving, unambiguous selected IR caller. Additional assembly callers,
native function-pointer uses, exported addresses and declaration-side escapes
keep the set open. Known unwind and function-tracing metadata references do not
introduce callers. These checks are independent of the target body's effects;
its entry context is sampled before executing that body.

The analysis copy expands indirect calls whose complete target set is a
bounded selection or PHI of function constants with matching prototypes.
All alternatives contribute callers and effects. Comparisons of function
addresses alone do not open the caller set; passing, storing or returning an
address still does. Unknown function pointers and escaped callbacks remain
incomplete. This does not resolve mutable operations tables or external entry
paths, and does not establish closure for exported global functions.

The compiler follows simple local pointer getters whose bodies do not write
memory or call opaque functions and whose returns describe the same pointer
path. This preserves paths such as ``d_inode(dentry)`` before inlining.

``may_acquire`` facts can contain typed ``load`` expressions. For example,
``add(load(add(arg(0),48)),152)`` describes a lock reached by reading a pointer
field at offset 48, then taking the member at offset 152 in the pointed-to
object. BTF validates both the pointer field and the final capability type;
bpftool prints the corresponding member path. The offsets depend on the build.
Each load denotes a value read during the invocation, not a promise that a
later read yields the same object. Such facts identify possible acquisitions;
they do not establish held ownership, prove disjointness from another loaded
path, or certify a complete summary. Stable memory-version identities are
still required for those proofs.

The solver does not certify mutable ``load`` expressions in exit or entry
ownership facts, or propagate callee-local stack identities across calls.
Any fact that cannot resolve to a native capability type is omitted and
prevents a complete runtime summary. Assembly references make the
referenced functions' caller sets incomplete;
block addresses and function addresses passed to assembly also escape. Empty
inline-assembly templates, including compiler memory barriers, preserve lock
ownership. Exact ARM64 memory barriers and thread-register reads, and x86 memory
fences, preserve ownership too. Other assembly remains an opaque effect at its
own call site.
Assembly directives that import unseen text or construct symbol names retain a
conservative translation-unit escape fallback. The fixed ARM64 sysreg
register-number macros are recognized as local non-call templates for escape
analysis; their executed body effects remain opaque. These restrictions reduce
coverage without converting missing evidence into a no-lock assertion.

Recursive possible-acquisition propagation is bounded to 128 facts per
function, including at most eight pointer-derived paths, and a link-wide
budget of 262144 derived expressions. Budget exhaustion withholds complete
summaries; retained positive facts are not an exhaustive acquisition list.
The runtime-tag deduplication index grows with the number of emitted tags.

Typed writes and captured ownership
-----------------------------------

A write into a known aggregate's ordinary storage preserves a captured lock
when the native BTF layout proves that the written bytes contain no capability.
This rule is limited to complete aggregate roots that are not embedded by value
in another BTF aggregate. Pointer members do not embed their pointees. All union
alternatives and complete capability extents count as lock storage. Unknown
pointers, lengths, layouts, embedded roots and out-of-bounds ranges retain the
conservative alias result. Expanding a capture here recovers its historical
type; it never substitutes a newly loaded pointer for the captured identity.
