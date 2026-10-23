#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the real compiler plugins, DWARF/BTF encoder and context resolver."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[4]
clang = os.environ.get("CLANG", "clang-23")
tool = root / "tools/bpf/bpftool/bpftool"
resolver = root / "tools/bpf/resolve_btfids/resolve_btfids"

with tempfile.TemporaryDirectory(prefix="context-regression-") as tmp:
    obj = Path(tmp) / "context.o"
    subprocess.run([
        clang, "-O2", "-g", "-DWARN_CONTEXT_ANALYSIS",
        "-fexperimental-late-parse-attributes",
        "-fplugin=" + str(root / "scripts/llvm-plugins/bpf_scan_ast.so"),
        "-fpass-plugin=" + str(root / "scripts/llvm-plugins/bpf_context_ir.so"),
        "-c", str(Path(__file__).with_suffix(".c")), "-o", str(obj),
    ], check=True)
    subprocess.run(["pahole", "-J", "--btf_features=var,global_var,decl_tag,type_tag", str(obj)], check=True)
    result = subprocess.run([str(resolver), "--context_analysis", "--verbose", "--verbose", str(obj)],
                            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="")
    for reason in ("entry-rejected mixed_context: some callers have no proven ownership",
                   "entry-rejected escaped_callback: address or assembly escape",
                   "entry-rejected after_reload: no common lock expressible in the callee context"):
        if reason not in result.stdout:
            raise AssertionError("missing diagnostic: " + reason)
    data = json.loads(subprocess.check_output([
        str(tool), "-j", "btf", "context-analysis", "file", str(obj) + ".BTF"
    ], text=True))
    entries = {x["name"]: [f for f in x["facts"] if f.get("fact") == "entry_held"]
               for x in data}
    for name in ("after_store", "after_work", "after_loop", "after_capture",
                 "selected_a", "selected_b", "after_recursive", "after_pending",
                 "after_inner_release", "after_pending_inner"):
        facts = entries.get(name, [])
        if not any(f["lock"] == "arg(0)" and f["mode"] == "exclusive" for f in facts):
            raise AssertionError("missing valid ownership: " + name)
        print("PASS ownership preserved:", name)
    for name in ("after_unlock", "after_corruption", "after_opaque", "after_alias",
                 "after_reload", "after_replacement", "mixed_context", "escaped_callback",
                 "after_global_alias", "after_pending_corruption", "after_unknown_release",
                 "after_inner_write", "after_alias_release"):
        if entries.get(name):
            raise AssertionError("unsafe ownership guarantee: " + name)
        print("PASS ownership withheld:", name)
    if not any(f["lock"] == "global(global_a)" for f in entries.get("after_global", [])):
        raise AssertionError("missing ownership across a disjoint global write")
    print("PASS ownership preserved: after_global")
