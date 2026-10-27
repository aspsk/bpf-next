#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check derived cleanliness and syscall-only fmodret admission."""
import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile

from test_llvm_plugins import Elf, Skip, KSFT_SKIP, FMODRET_FN_CLEAN_SEED, FMODRET_FN_DEFINED
from test_llvm_plugins import compile_arguments, diagnostic


def run(command, build):
    result = subprocess.run(list(map(str, command)), cwd=build, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError("command failed: " + shlex.join(map(str, command)) + "\n" +
                         result.stdout + result.stderr)
    return result


def btf_functions(data):
    endian = "<" if data[:2] == b"\x9f\xeb" else ">"
    magic, version, _, header, start, size, strings, length = struct.unpack_from(endian + "HBB5I", data)
    if magic != 0xeb9f or version != 1:
        raise ValueError("invalid generated BTF header")
    names = data[header + strings:header + strings + length]
    offset, end, type_id = header + start, header + start + size, 1
    result = {}
    while offset < end:
        name, info, _ = struct.unpack_from(endian + "3I", data, offset)
        kind, count = (info >> 24) & 31, info & 0xffff
        if kind == 12:
            result[type_id] = Elf.string(names, name)
        fixed = {1: 4, 2: 0, 3: 12, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0,
                 12: 0, 14: 4, 16: 0, 17: 4, 18: 0}
        variable = {4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}
        if kind in fixed:
            payload = fixed[kind]
        elif kind in variable:
            payload = variable[kind] * count
        else:
            raise ValueError("unsupported generated BTF kind " + str(kind))
        offset += 12 + payload
        type_id += 1
    if offset != end:
        raise ValueError("invalid generated BTF type length")
    return result


def generated_ids(path):
    ids = Path(str(path) + ".BTF_fmodret_ids")
    if not ids.is_file():
        return {}
    data = ids.read_bytes()
    endian = "<" if path.read_bytes()[5] == 1 else ">"
    count, flags = struct.unpack_from(endian + "II", data)
    if flags or len(data) != 8 + count * 8:
        raise ValueError("invalid generated fmodret set")
    pairs = [struct.unpack_from(endian + "II", data, 8 + i * 8) for i in range(count)]
    if pairs != sorted(pairs) or len({i for i, _ in pairs}) != count:
        raise ValueError("fmodret set is not sorted and unique")
    functions = btf_functions(Path(str(path) + ".BTF").read_bytes())
    return {functions[i]: flags for i, flags in pairs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-build", type=Path)
    parser.add_argument("--compile-command", type=Path)
    parser.add_argument("--clang", default=os.environ.get("CLANG"))
    parser.add_argument("--ld", default=os.environ.get("LD", "ld"))
    parser.add_argument("--pahole", default=os.environ.get("PAHOLE", "pahole"))
    parser.add_argument("--resolve-btfids", type=Path)
    args = parser.parse_args()
    fixtures = Path(__file__).resolve().parent / "llvm_plugins"
    default = os.environ.get("KBUILD_OUTPUT")
    if not args.kernel_build and not default:
        default = next((p for p in Path(__file__).resolve().parents
                        if (p / "scripts/llvm-plugins/fmodret_metadata.h").is_file()), None)
        if default is None:
            raise Skip("kernel tree unavailable; set --kernel-build")
    build = (args.kernel_build or Path(default)).resolve()
    command_file = args.compile_command or build / "kernel/.fork.o.cmd"
    if not command_file.is_absolute():
        command_file = build / command_file
    resolver = (args.resolve_btfids or build / "tools/bpf/resolve_btfids/resolve_btfids").resolve()
    for path in (build / "include/generated/autoconf.h", command_file, resolver):
        if not path.is_file():
            raise Skip("missing prerequisite: " + str(path))
    ld, pahole = shlex.split(args.ld), shlex.split(args.pahole)
    if not ld or not pahole or not shutil.which(ld[0]) or not shutil.which(pahole[0]):
        raise Skip("target linker and pahole are required")
    command = compile_arguments(build, command_file, args.clang)
    command += ["-g", "-fno-optimize-sibling-calls", "-fpatchable-function-entry=2"]
    groups = []
    for category in ("clean", "safe", "unsafe"):
        source = fixtures / ("fmodret_derived_" + category + ".c")
        names = re.findall(r"^FMODRET_TEST\s+int\s+(fmodret_derived_\w+)\s*\(",
                           source.read_text(), re.M)
        if not names or len(set(names)) != len(names):
            raise ValueError("missing or duplicate derived tests: " + str(source))
        if any(not name.startswith("fmodret_derived_" + category + "_") for name in names):
            raise ValueError("derived fixture name does not match its category")
        groups.append((category, source, names))
    failed = 0
    with tempfile.TemporaryDirectory(prefix="bpf-llvm-derived-") as tmp:
        tmp = Path(tmp)
        objects = []
        seeds = {}
        for source in [fixtures / "fmodret_derived_helpers.c"] + [s for _, s, _ in groups]:
            obj = tmp / (source.stem + ".o")
            run(command + ["-c", source, "-o", obj], build)
            objects.append(obj)
            for name, flags in Elf(obj).clean_seeds().items():
                if not flags & FMODRET_FN_DEFINED:
                    continue
                if name in seeds:
                    raise ValueError("duplicate defined fixture: " + name)
                seeds[name] = flags
        script = tmp / "module.lds"
        script.write_text("SECTIONS {\n"
                          " .BTF_fmodret_candidates 0 (INFO) : { KEEP(*(.BTF_fmodret_candidates)) }\n"
                          " __patchable_function_entries 0 : { *(__patchable_function_entries) }\n"
                          "}\n")
        linked = tmp / "derived.o"
        run(ld + ["-r", "-T", script, *objects, "-o", linked], build)
        btf = tmp / "derived.btf"
        run(pahole + ["--btf_features=encode_force,var,float,enum64,decl_tag,type_tag,optimized_func,consistent_func",
                      "--btf_encode_detached=" + str(btf), linked], build)
        result = run([resolver, "-v", "--fmodret_error_injection", "--btf", btf, linked], build)
        states = dict(re.findall(r"^fmodret function: (\S+) .*? clean=(\S+) ",
                                 result.stderr, re.M))
        admitted = generated_ids(linked)
        if ".BTF_fmodret_candidates" in Elf(linked).names:
            raise ValueError("resolved object retains candidate metadata")
        print("TAP version 13")
        print("1.." + str(sum(len(names) for _, _, names in groups)))
        number = 0
        for category, _, names in groups:
            for name in names:
                number += 1
                error = None
                if name not in seeds or name not in states:
                    error = "missing function description or analysis result"
                elif seeds[name] & FMODRET_FN_CLEAN_SEED:
                    error = "test is atomic rather than derived"
                elif category in ("clean", "safe") and states[name] != "constructed":
                    error = "cleanliness was not derived"
                elif (name in admitted) != (category == "safe"):
                    error = "unexpected generated-set membership"
                elif name in admitted and admitted[name]:
                    error = "inferred function has unexpected attachment flags"
                if error:
                    failed += 1
                    print("not ok", number, name, "-", error)
                else:
                    print("ok", number, name)
        if failed:
            diagnostic(result.stderr)
    return int(bool(failed))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Skip as exc:
        print("TAP version 13\n1..0 # SKIP " + str(exc))
        sys.exit(KSFT_SKIP)
    except (OSError, ValueError, IndexError, KeyError, struct.error) as exc:
        print("TAP version 13\n1..1\nnot ok 1 - derived fmodret selftest")
        diagnostic(exc)
        sys.exit(1)
