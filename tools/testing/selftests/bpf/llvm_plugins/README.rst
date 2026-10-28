Atomic fmodret recognition tests
==================================

The two C files show what ``bpf_scan_ir`` currently recognizes, rejects, and
still needs to support. They use real kernel headers and are compiled only;
the functions are never linked into or executed inside the kernel.

* ``fmodret_clean.c``: 26 supported tests. Each must receive ``CLEAN_SEED``.
  Groups cover constant errnos and widths, clean error exits alongside dirty
  success paths, ordinary reads, error pointers and casts, bounded nonconstant
  errnos, boolean conditions, assumptions, and private stack writes/copies.
* ``fmodret_unsafe.c``: 18 atomic negative tests. Observable stores, volatile
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
``optnone`` preserves the private stack tests. It reads only the emitted
function identities and CLEAN_SEED flags. No resolver, LLVM opt, BTF generation,
linked error propagation or final injection-safety analysis is involved.

The runner is registered in BPF selftests. Ordinary kernel builds do not run
it, and the runner does not invoke Kbuild or change the kernel build directory.

Derived-function tests
-------------------------

``test_llvm_plugins_derived.py`` checks the linked analysis separately::

  tools/testing/selftests/bpf/test_llvm_plugins_derived.py --kernel-build /path/to/build

The fixtures are split into three readable groups:

* ``fmodret_derived_clean.c``: five constructed clean functions without a proved
  syscall boundary. They must not be tagged as fmod_ret targets.
* ``fmodret_derived_safe.c``: seven constructed clean functions with a proof for
  every negative errno in [-4095, -1]. They must get the ``bpf_fmodret`` and
  ``bpf_fmodret_auto`` BTF decl tags.
* ``fmodret_derived_unsafe.c``: twelve rejection cases covering dirty prefixes,
  discarded errors, unknown allocators, escaping callbacks and addresses,
  unseeded recursion, and clean bodies whose callers swallow their errors.
  This group includes proof limitations, not only demonstrably unsafe bodies.

``fmodret_derived_helpers.c`` supplies shared seeds, dispatchers and synthetic
syscall table entries. None of these tests is loaded or executed.

``fmodret_linked.c`` tests syscall boundaries and caller coverage in both
relocatable objects and final linked images. The x86 cases cover native and
compatibility syscall wrappers, instruction metadata, malformed metadata,
runtime function pointers and callers without compiler descriptions.

The runner compiles separate translation units using the saved kernel command,
checks that tested functions are not atomic seeds, links the candidate records,
generates BTF and invokes resolve_btfids. It checks constructed cleanliness and
the decl tags in the BTF written by resolve_btfids. Allocator
contracts and ERR_PTR helpers participate in derivation. Syscall table entries
and global x86 syscall wrappers terminate propagation at the syscall ABI.

The runner requires the built plugin, resolve_btfids, a target linker and pahole.
``--ld``, ``--pahole`` and ``--resolve-btfids`` override those tools. Compiler and
build-directory options follow the atomic runner. Temporary files are removed;
missing prerequisites produce a kselftest SKIP.
