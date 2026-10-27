Atomic fmodret recognition examples
==================================

The two C files show what ``bpf_scan_ir`` currently recognizes, rejects, and
still needs to support. They use real kernel headers and are compiled only;
the functions are never linked into or executed inside the kernel.

* ``fmodret_clean.c``: 26 supported examples. Each must receive ``CLEAN_SEED``.
  Groups cover constant errnos and widths, clean error exits alongside dirty
  success paths, ordinary reads, error pointers and casts, bounded nonconstant
  errnos, boolean conditions, assumptions, and private stack writes/copies.
* ``fmodret_unsafe.c``: 18 atomic negative examples. Observable stores, volatile
  accesses, atomics, opaque calls/assembly, unbalanced locks, escaped locals,
  external memory writes and infeasible error branches must not produce a seed.
* The final TODO group in ``fmodret_unsafe.c`` contains five clean patterns which
  must be supported in future: balanced spinlock, mutex and RCU operations,
  returning an input constrained to the errno range, and returning an IS_ERR
  input pointer through a merged exit. Known misses print ``ok``. Once one is
  recognized, its check fails with a request to move it to the clean file.

``FMODRET_TEST`` keeps each function present and identifies it to the runner.
The function name records its expectation: ``fmodret_clean_``, ``fmodret_unsafe_``
or ``fmodret_todo_``. Missing function descriptions always fail.

Run after building the plugin and ``kernel/fork.o`` with matching Clang::

  tools/testing/selftests/bpf/test_llvm_plugins.py

For a separate kernel output directory, use ``--kernel-build /path/to/build``
or ``KBUILD_OUTPUT``. ``--compile-command`` selects a saved Kbuild ``.cmd`` file
instead of ``kernel/.fork.o.cmd``. ``CLANG``/``--clang`` override the compiler.
Missing prerequisites produce a kselftest SKIP.

The runner reuses the kernel's target and headers, removes other plugins and
instrumentation, and compiles the two files at ``-O2`` in a temporary directory.
``optnone`` preserves the private stack examples. It reads only the emitted
function identities and CLEAN_SEED flags. No resolver, LLVM opt, BTF generation,
linked error propagation or final injection-safety analysis is involved.

The runner is registered in BPF selftests. Ordinary kernel builds do not run
it, and the runner does not invoke Kbuild or change the kernel build directory.
