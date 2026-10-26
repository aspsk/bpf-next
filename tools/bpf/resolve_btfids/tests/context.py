#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the real compiler plugins, DWARF/BTF encoder and context resolver."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[4]
clang = os.environ.get("CLANG", "clang-23")
ld = os.environ.get("LD", "ld")
tool = root / "tools/bpf/bpftool/bpftool"
resolver = root / "tools/bpf/resolve_btfids/resolve_btfids"

with tempfile.TemporaryDirectory(prefix="context-regression-") as tmp:
    obj = Path(tmp) / "context.o"
    subprocess.run([
        clang, "-O2", "-g", "-DWARN_CONTEXT_ANALYSIS",
        *shlex.split(os.environ.get("CONTEXT_TEST_CFLAGS", "")),
        "-fexperimental-late-parse-attributes",
        "-fplugin=" + str(root / "scripts/llvm-plugins/bpf_scan_ast.so"),
        "-fpass-plugin=" + str(root / "scripts/llvm-plugins/bpf_context_ir.so"),
        "-c", str(Path(__file__).with_suffix(".c")), "-o", str(obj),
    ], check=True)
    subprocess.run(["pahole", "-J", "--btf_features=var,global_var,decl_tag,type_tag", str(obj)], check=True)
    linked = bool(os.environ.get("CONTEXT_TEST_LINKED"))
    no_relocations = bool(os.environ.get("CONTEXT_TEST_NO_RELOCS"))
    no_coverage = bool(os.environ.get("CONTEXT_TEST_NO_COVERAGE"))
    if linked:
        assembly = Path(tmp) / "entry.o"
        subprocess.run([clang, *shlex.split(os.environ.get("CONTEXT_TEST_CFLAGS", "")),
                        "-c", str(Path(__file__).with_name("context-entry.S")),
                        "-o", str(assembly)], check=True)
        image = Path(tmp) / "context-linked"
        subprocess.run([ld, *([] if no_relocations else ["--emit-relocs"]),
                        *([] if no_coverage else ["--defsym=__bpf_context_native_calls=1"]),
                        "--unresolved-symbols=ignore-all", "-e", "global_locked_case",
                        str(obj), str(assembly), "-o", str(image)], check=True)
        obj = image
    result = subprocess.run([str(resolver), "--context_analysis", "--verbose", "--verbose", str(obj)],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="")
    result.check_returncode()
    reasons = ("entry-rejected mixed_context: some callers have no proven ownership",
                   "entry-rejected escaped_callback: address or assembly escape",
                   "entry-rejected after_reload: no common lock expressible in the callee context")
    if "TEST_UNKNOWN_REPEAT_ASM" in os.environ.get("CONTEXT_TEST_CFLAGS", ""):
        reasons = ("entry-rejected after_store: address or assembly escape",)
    for reason in reasons:
        if reason not in result.stdout:
            raise AssertionError("missing diagnostic: " + reason)
    data = json.loads(subprocess.check_output([
        str(tool), "-j", "btf", "context-analysis", "file", str(obj) + ".BTF"
    ], text=True))
    entries = {x["name"]: [f for f in x["facts"] if f.get("fact") == "entry_held"]
               for x in data}
    if "TEST_UNKNOWN_REPEAT_ASM" in os.environ.get("CONTEXT_TEST_CFLAGS", ""):
        if any(entries.values()):
            raise AssertionError("unknown symbol-generating assembly closed caller sets")
        print("PASS unknown assembly retains open caller sets")
        raise SystemExit(0)
    if linked and not no_relocations and not no_coverage:
        if not any(f["lock"] == "arg(0)" for f in entries.get("global_locked", [])):
            raise AssertionError("missing closed global entry proof")
        print("PASS closed global caller coverage")
    elif entries.get("global_locked"):
        raise AssertionError("global caller coverage certified without native relocations")
    for name in ("global_mixed", "global_unknown_caller", "global_data_escape"):
        if entries.get(name):
            raise AssertionError("unsafe global entry guarantee: " + name)
        print("PASS global ownership withheld:", name)
    for name in ("after_store", "after_work", "after_loop", "after_capture",
                 "selected_a", "selected_b", "after_recursive", "after_pending",
                 "after_inner_release", "after_pending_inner", "after_stack_memory",
                 "after_memory_barrier", "after_register_read", "after_holder_write", "after_holder_call"):
        facts = entries.get(name, [])
        if not any(f["lock"] == "arg(0)" and f["mode"] == "exclusive" for f in facts):
            raise AssertionError("missing valid ownership: " + name)
        print("PASS ownership preserved:", name)
    for name in ("after_unlock", "after_corruption", "after_opaque", "after_alias",
                 "after_reload", "after_replacement", "mixed_context", "escaped_callback",
                 "after_global_alias", "after_pending_corruption", "after_unknown_release",
                 "after_inner_write", "after_alias_release", "after_foreign_snapshot",
                 "after_memory_corruption", "after_unrecognized_asm", "after_union_write", "after_scalar_write"):
        if entries.get(name):
            raise AssertionError("unsafe ownership guarantee: " + name)
        print("PASS ownership withheld:", name)
    if not any(f["lock"] == "global(global_a)" for f in entries.get("after_global", [])):
        raise AssertionError("missing ownership across a disjoint global write")
    print("PASS ownership preserved: after_global")
