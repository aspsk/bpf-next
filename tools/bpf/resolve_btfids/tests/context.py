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
    subprocess.run(["pahole", "-J", str(obj)], check=True)
    subprocess.run([str(resolver), "--context_analysis", "--verbose", str(obj)], check=True)
    data = json.loads(subprocess.check_output([
        str(tool), "-j", "btf", "context-analysis", "file", str(obj) + ".BTF"
    ], text=True))
    entries = {x["name"]: [f for f in x["facts"] if f.get("fact") == "entry_held"]
               for x in data}
    for name in ("after_store", "after_work", "after_loop", "after_capture",
                 "selected_a", "selected_b", "after_recursive"):
        facts = entries.get(name, [])
        if not any(f["lock"] == "arg(0)" and f["mode"] == "exclusive" for f in facts):
            raise AssertionError("missing valid ownership: " + name)
        print("PASS ownership preserved:", name)
    for name in ("after_unlock", "after_corruption", "after_opaque", "after_alias",
                 "after_reload", "after_replacement", "mixed_context", "escaped_callback"):
        if entries.get(name):
            raise AssertionError("unsafe ownership guarantee: " + name)
        print("PASS ownership withheld:", name)
