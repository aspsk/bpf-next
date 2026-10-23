Context ownership regressions
=============================

Build the context plugins, resolve_btfids and bpftool with matching LLVM
development libraries, then run from the kernel source directory::

  python3 tools/bpf/resolve_btfids/tests/context.py

The runner uses ``clang-23`` by default (override with ``CLANG``), pahole with
the ``global_var`` feature, and the tools built in this tree. It compiles a
small input through the real AST/IR plugins, generates native BTF and runs
the resolver. It does not execute kernel code or require a running BPF kernel.

Positive cases cover disjoint stores and calls, loops, recursion, captured
pointers, bounded callback selectors, separate global objects and conditional
acquisitions. Negative cases cover premature unlock, overwritten lock storage,
opaque calls, pointer aliases, pointer reload/replacement, escaped callbacks,
mixed caller contexts, global aliases and invalidated pending acquisitions.
An unlock with an unrepresentable selected argument must invalidate ownership
because it can release the lock that was held.
The runner also checks that rejection reasons distinguish these cases.
Nested-lock cases distinguish declared releases of an inner instance from
raw writes inside the outer capability's storage. Releases at an aliased
address must still invalidate ownership.
The caller and callee may both use snapshot number zero for different
objects; a callee's private capture cannot establish caller ownership.
