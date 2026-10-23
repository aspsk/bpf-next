.. SPDX-License-Identifier: GPL-2.0-only

bpf_scan_ast locking metadata
============================

``bpf_scan_ast`` is a Clang frontend plugin for kernel C. It collects
declarations and source expressions after parsing and semantic analysis, before LLVM IR
optimization can inline or remove the annotated helpers. It collects locking
facts; it does not infer balanced locking, caller lock states, execution
contexts, or BPF attachment permissions.

Enable ``CONFIG_WARN_CONTEXT_ANALYSIS`` and ``CONFIG_CLANG_PLUGIN_BPF_SCAN_AST``
with Clang 23 or later and matching Clang/LLVM development headers. The existing
plugin build rule builds ``bpf_scan_ast.so`` with ``HOSTCXX`` and the flags from
``LLVM_CONFIG``. The
compiler loads it with ``-fplugin=.../bpf_scan_ast.so``. This is independent of
the ``-fpass-plugin`` option used for ``bpf_scan_ir``.

The collector follows the existing context-analysis opt-ins. With
``CONFIG_WARN_CONTEXT_ANALYSIS_ALL`` disabled, only files selected through
``CONTEXT_ANALYSIS := y`` or ``CONTEXT_ANALYSIS_file.o := y`` retain locking
annotations. The context-analysis flags enable late attribute parsing for
those files. The plugin does not enable annotations in other files.

The plugin still emits a document for other translation units, with
``annotations_enabled: false`` and empty fact arrays. This represents unknown
locking coverage, not proof that the functions have no locking effects.
Tree-wide collection requires ``CONFIG_WARN_CONTEXT_ANALYSIS_ALL`` and source
declarations that support annotation parsing throughout the selected build.

Transport
---------

The plugin emits one implicit static ``const char[]`` named
``__bpf_scan_ast_locks`` per translation unit, with ``used``, ``nodebug`` and
``section(".bpf_scan.lock")`` attributes. Its initializer is a compact UTF-8
JSON document followed by a NUL byte. Clang's ordinary code generator emits
this declaration as an LLVM constant global. No references to the original
functions, locks or guarded objects are introduced. Collecting a declaration
therefore does not force its definition to be emitted or mark its address as
escaping. The carrier itself is retained through ``llvm.compiler.used``.

The frontend action runs before the main action. At the end of the translation
unit it delivers only the newly synthesized data declaration to the multiplexed
AST consumer, before the main CodeGen consumer finalizes its module. It does
not rewrite existing function bodies or attributes.

Both kernel and module linker scripts keep the section as non-allocating
``INFO`` data. Linked sections contain concatenated NUL-terminated documents;
there are no target-endian binary fields or relocations in their contents.
Consumers should tolerate zero padding between documents. This is build
metadata, not a BTF type tag or a runtime ABI.

An early IR consumer can find the globals by section name, read each string
initializer, and validate the format and version before interpreting it. It
must import the function contracts before inlining and resolve them against
actual IR call arguments. An optimizer-last consumer cannot reconstruct an
already removed helper call from this document alone. No IR consumer is added
by this change, and the existing fmod-ret metadata format is unchanged.

Version 2 document
------------------

The constants are shared in ``bpf_scan_ast_metadata.h``. The top-level object
contains:

``tokens``
  Abstract token declarations from ``token_context_lock()`` and
  ``token_context_lock_instance()``. Each record contains ``name``,
  ``capability`` and ``reentrant``. References use expression kind ``token``;
  these declarations do not identify mutable pointer loads or ELF storage.

``format``, ``version``
    The string ``bpf_scan.lock`` and integer ``2``.

``unit``, ``target``, ``char_bits``, ``pointer_bits``
    Main input filename, target triple, bits per target byte, and pointer width.
    Offsets described below are in bits, not host bytes.

``annotations_enabled``
    Whether ``WARN_CONTEXT_ANALYSIS`` is defined and neither ``__CHECKER__`` nor
    ``__GENKSYMS__`` is defined at the end of the translation unit. False must
    not be interpreted as an empty set of locking effects. True means
    annotation parsing was requested, not that all
    kernel code is annotated or that any locking proof has succeeded.

``functions``
    Descriptions of functions with locking attributes, callers of those
    functions, cleanup functions and functions mentioned by lock expressions.
    Each has a document-local integer ``id``, assembler ``symbol``,
    ``asm_label``, ``local_linkage``, ``weak``, ``defined``, ``location``, a
    ``parameters`` array of names and canonical type spellings, ``return_type``,
    ``variadic`` and a ``contracts`` array. Parameter indices are zero-based.
    Symbols honor assembler labels and Clang name mangling. ``asm_label`` identifies a literal
    label for which an IR consumer must account for LLVM's no-mangle prefix.
    Local symbols require the translation unit as part of their identity.
    Inlined or unused definitions described here need not exist in final IR.

``types``
    Record types annotated as capabilities, including the record name,
    declaration location, capability name, shared-capability spelling,
    reentrancy and scoped-lockable marker. These describe lock classes, not
    proof that two objects contain the same lock instance.

``guarded``
    Field, global or local declarations with ``guarded_by``, ``pt_guarded_by``,
    ``guarded_var`` or ``pt_guarded_var`` annotations. Each carries its
    declaration description and an ``annotations`` array. The first two
    operations retain all lock expressions. The latter two express an unnamed
    guard and must not be treated as requiring no locks.

``calls``
    Explicit source calls to directly resolved functions with locking
    attributes. Each has ``caller`` and ``callee`` function IDs, ``location``
    and ``arguments`` expressed in the caller's parameter namespace. These are
    syntactic call descriptions, not a CFG, execution order or a complete call
    graph. Calls in unreachable or unevaluated expressions may appear. Indirect
    calls are not resolved here. Calls inside attribute expressions are not
    included in this array. A consumer must match actual IR operations before
    using a source call as an effect.

``cleanups``
    Local declarations with Clang's cleanup attribute, including ``caller``,
    cleanup ``callee``, ``variable`` and declaration ``location``. The implicit
    call receives the address of that variable. These records preserve cleanup
    relationships used by guard macros; they do not identify execution order
    or prove that a matching acquisition occurred. IR still supplies the
    generated calls and scope-exit control flow.

Source locations carry separate ``expansion`` and ``spelling`` objects, each
with ``valid``, physical ``file``, byte ``offset``, ``line`` and ``column``.
Invalid locations carry only ``valid: false``. Location and type spellings
provide diagnostic information; names or locations alone are not alias proofs.

Contracts
---------

Attributes from all redeclarations are collected and equivalent descriptions
are deduplicated. Each contract retains its attribute spelling and location.
The operations are ``acquire``, ``release``, ``try_acquire``, ``require``,
``exclude``, ``assert``, ``returns_lock`` and ``analysis_disabled``.

The first six have a ``mode`` (``exclusive``, ``shared`` or ``generic``),
``locks`` array, ``implicit_lock`` flag for an attribute without explicit lock
arguments, and ``unresolved`` flag for delayed arguments. An unresolved or
implicit lock is not an empty effect. Try-acquire additionally has a
``success`` expression representing Clang's success condition; this must be
interpreted according to Clang's zero/nonzero or boolean trylock semantics,
rather than assuming all nonzero return values are errors. Conditional release
macros are preserved as their release and complementary try-acquire contracts.

``assert`` records an annotation's assumption, not a runtime check or an actual
acquisition. ``returns_lock`` carries a single ``lock`` expression describing
the returned lock's identity. ``analysis_disabled`` records an opt-out from
Clang's body checking; it does not erase the function's declared contracts or
prove that its body is lock-free. An empty contracts array likewise does not
mean a function has no locking effects.

Symbolic expressions
--------------------

Lock identities and call arguments use expression objects with a ``kind`` and
the expression's canonical ``type`` when available:

* ``parameter``: zero-based ``index`` in the enclosing function.
* ``global``: ``symbol``, ``local_linkage``, canonical ``type`` and declaration
  ``location``. A local-linkage global also requires translation-unit identity.
* ``local``: document-local declaration ``id``, owning ``function``, name,
  canonical type, location and ``static_storage`` flag. This identifies a
  declaration, not a particular dynamic invocation's storage or SSA value.
* ``member``: ``base``, ``arrow`` and ``field``; ``implicit_member`` has a field
  relative to the enclosing record instance. A field has record identity and
  location, field name, canonical type and index, union/bitfield flags, and ``offset_bits`` when
  its layout is available.
* ``unary``: operator ``op`` and operand ``value``. Address-of and dereference
  remain distinct operations.
* ``cast``: Clang cast kind, resulting canonical type and operand ``value``.
  This includes lvalue-to-rvalue loads; casts are not silently assumed to
  preserve lock identity.
* ``integer``: decimal ``value`` string, bit width and signedness. The string
  avoids loss of precision through JSON numeric representations.
* ``subscript``, ``binary`` and ``conditional`` retain their child expressions
  and operators. A direct ``call`` expression has a function ID and arguments;
  it is a symbolic expression, not itself evidence of an executed call.
* ``unknown``: unsupported or missing expression, foreign parameter or depth
  limit, with a reason and available AST class/location. Recursion is limited
  to 32 expression levels. Unknown never establishes aliasing or no effects.

For example, ``__acquires(&obj->lock)`` records address-of, the ``lock`` field
and its target-layout offset, and a base rooted in the relevant parameter.
``spin_lock(&obj->lock)`` also records the caller's actual expression. A future
IR consumer can substitute the argument for the formal parameter. It must use
IR values and alias analysis to account for loads, assignments, escaping locals,
pointer casts and distinct object instances. Matching only a structure name
and member offset is insufficient. Balanced cleanup and interprocedural lock
state derivation are deliberately left to subsequent analysis.
