#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check feasible-prefix certificates through the real compiler/BTF pipeline."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[4]
with tempfile.TemporaryDirectory(prefix="context-witness-") as tmp:
    obj = Path(tmp) / "witness.o"
    subprocess.run([
        os.environ.get("CLANG", "clang-23"), "-O2", "-g", "-DWARN_CONTEXT_ANALYSIS",
        *shlex.split(os.environ.get("CONTEXT_TEST_CFLAGS", "")),
        "-fexperimental-late-parse-attributes",
        "-fplugin=" + str(root / "scripts/llvm-plugins/bpf_scan_ast.so"),
        "-fpass-plugin=" + str(root / "scripts/llvm-plugins/bpf_context_ir.so"),
        "-c", str(Path(__file__).with_suffix(".c")), "-o", str(obj),
    ], check=True)
    subprocess.run(["pahole", "-J", "--btf_features=var,global_var,decl_tag,type_tag", str(obj)], check=True)
    subprocess.run([str(root / "tools/bpf/resolve_btfids/resolve_btfids"),
                    "--context_analysis", str(obj)], check=True)
    data = json.loads(subprocess.check_output([
        str(root / "tools/bpf/bpftool/bpftool"), "-j", "btf", "context-analysis",
        "file", str(obj) + ".BTF"], text=True))
    records = {f["name"]: f["facts"] for f in data}
    def witnesses(name):
        return [x for x in records.get(name, []) if x.get("evidence") == "path"]
    for name in ("guarded", "wrapper"):
        facts = witnesses(name)
        assert len(facts) == 1, (name, facts)
        assert facts[0]["lock"] == "add(arg(0),4)", facts
        assert facts[0]["condition"] == "bits_eq(arg(0),32,2097152,0)", facts
        assert facts[0]["via"].endswith("guarded@0/witness_lock[declared]"), facts
        print("PASS witnessed acquisition:", name)
    facts = witnesses("set_guard")
    assert len(facts) == 1 and facts[0]["condition"] == "bits_eq(arg(0),32,2097152,2097152)", facts
    print("PASS nonzero one-bit branch")
    facts = witnesses("wrong_instance")
    assert len(facts) == 1 and facts[0]["lock"] == "add(arg(1),4)", facts
    assert facts[0]["condition"] == "bits_eq(arg(1),32,2097152,0)", facts
    print("PASS exact lock instance substitution")
    for name in ("contradictory", "opaque_first", "unknown_guard", "write_first", "assumed",
                 "unreadable_prefix", "unsupported_mask", "extension_guard", "global_guard", "impossible_bool"):
        assert not witnesses(name), (name, witnesses(name))
        print("PASS witness withheld:", name)
    # Removing an unsupported witness never upgrades the old may summary.
    for name in ("opaque_first", "write_first", "unreadable_prefix"):
        assert not any(x.get("fact") == "lock_summary_complete" for x in records.get(name, [])), name
    pretty = subprocess.check_output([
        str(root / "tools/bpf/bpftool/bpftool"), "btf", "context-analysis",
        "file", str(obj) + ".BTF", "func", "wrapper"], text=True)
    assert "(task->flags & 0x200000) == 0x0" in pretty, pretty
    assert "[unproven path]" in pretty and "witnessed may_acquire" in pretty, pretty
    print("PASS readable guards and distinct candidate/witness evidence")
