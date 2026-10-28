.. SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

===============
bpftool-fmodret
===============
-------------------------------------------------------------------------------
tool to list BPF fmod_ret targets
-------------------------------------------------------------------------------

:Manual section: 8

.. include:: substitutions.rst

SYNOPSIS
========

**bpftool** [*OPTIONS*] **fmodret** *COMMAND*

*OPTIONS* := { |COMMON_OPTIONS| }

*COMMANDS* := { **list** | **help** }

FMODRET COMMANDS
================

| **bpftool** **fmodret** { **list** [**file** *FILE*] }
| **bpftool** **fmodret help**

DESCRIPTION
===========

bpftool fmodret list [file *FILE*]
    List the functions declared as fmod_ret targets in the BTF of vmlinux and
    of loaded modules. Each entry contains the BTF ID of the function, its
    name and the name of the object it belongs to. Targets which sleepable
    programs may attach to are marked **sleepable**.

    The targets are the functions tagged with the **bpf_fmodret** BTF decl tag
    by the kernel build. With **file**, read the BTF from *FILE* (for
    example a vmlinux image or a **BTF** file) instead of the running kernel.

    With **--json**, each entry contains **btf_id**, **name**, **owner** and
    **sleepable** fields.

    Only the targets declared with the tags are listed. The verifier may
    accept further functions by other rules, such as the error injection list
    or **security_** hooks. Normal verifier and tracing checks apply to all
    of them.

bpftool fmodret help
    Print short help message.

OPTIONS
========

.. include:: common_options.rst
