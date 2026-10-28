#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check derived cleanliness and syscall-only fmod_ret tagging."""
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

EM_X86_64 = 62


def run(command, build):
    result = subprocess.run(list(map(str, command)), cwd=build, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError("command failed: " + shlex.join(map(str, command)) + "\n" +
                         result.stdout + result.stderr)
    return result


def btf_functions(data):
    """Return the functions of BTF as {type ID: name}, and its decl tags as
    [(tag name, target type ID)]."""
    endian = "<" if data[:2] == b"\x9f\xeb" else ">"
    magic, version, _, header, start, size, strings, length = struct.unpack_from(endian + "HBB5I", data)
    if magic != 0xeb9f or version != 1:
        raise ValueError("invalid generated BTF header")
    names = data[header + strings:header + strings + length]
    offset, end, type_id = header + start, header + start + size, 1
    result, tags = {}, []
    while offset < end:
        name, info, ref = struct.unpack_from(endian + "3I", data, offset)
        kind, count = (info >> 24) & 31, info & 0xffff
        if kind == 12:
            result[type_id] = Elf.string(names, name)
        elif kind == 17:
            tags.append((Elf.string(names, name), ref))
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
    return result, tags


def generated_ids(path):
    """Return {function name: set of fmod_ret decl tags} from the BTF which
    resolve_btfids wrote for PATH."""
    functions, tags = btf_functions(Path(str(path) + ".BTF").read_bytes())
    result = {}
    for tag, target in tags:
        if tag.startswith("bpf_fmodret") and target in functions:
            result.setdefault(functions[target], set()).add(tag)
    return result


def linked_cases(machine, ptr):
    cases = [
        ("syscall-dispatcher", ["TEST_DISPATCHER"], "", True),
        ("syscall-swallowed-error", ["TEST_SWALLOW"], "", False),
        ("non-syscall-boundary", ["TEST_NO_BOUNDARY"], "", False),
        ("non-syscall-caller", ["TEST_BAD_CALLER"], "", False),
    ]
    pointer = ".quad" if ptr == 8 else ".long"
    cases.append(("runtime-function-pointer", [],
                  '.section .rodata,"a"\n' + pointer + ' fmodret_linked_leaf\n', False))
    if machine != EM_X86_64:
        return cases
    for abi in ("X64", "X64_COMPAT", "IA32", "IA32_COMPAT"):
        cases.append((abi + "-syscall-wrapper",
                      ["TEST_" + abi + "_ENTRY", "TEST_NO_TABLE", "TEST_DISPATCHER"],
                      "", True))
    cases += [
        ("syscall-prefix-helper", ["TEST_FAKE_ENTRY", "TEST_NO_TABLE", "TEST_DISPATCHER"],
         "", False),
        ("local-syscall-name", ["TEST_X64_ENTRY", "TEST_LOCAL_ENTRY", "TEST_NO_TABLE",
                                "TEST_DISPATCHER"], "", False),
    ]
    for section in (".orc_unwind_ip", ".return_sites", ".call_sites",
                    ".retpoline_sites", ".ibt_endbr_seal", ".cfi_sites",
                    ".smp_locks", "runtime_ptr_linked"):
        cases.append((section, [], '.section ' + section + ',"a"\n'
                      '.long fmodret_linked_leaf - .\n', True))
    cases += [
        ("orc-absolute-pointer", [], '.section .orc_unwind_ip,"a"\n'
         '.quad fmodret_linked_leaf\n', False),
        ("orc-unaligned-offset", [], '.section .orc_unwind_ip,"a"\n'
         '.byte 0\n.long fmodret_linked_leaf - .\n.zero 3\n', False),
        ("static-call-site", [], '.section .static_call_sites,"a"\n'
         '.long fmodret_linked_leaf - .\n.long 0\n', True),
        ("static-call-key", [], '.section .static_call_sites,"a"\n'
         '.long 0\n.long fmodret_linked_leaf - .\n', False),
        ("alternative-site", [], '.section .altinstructions,"a"\n'
         '.long fmodret_linked_leaf - .\n.long 0\n.long 0\n.byte 1, 1\n', True),
        ("alternative-function-pointer", [], '.section .altinstructions,"a"\n'
         '.long 0\n.long fmodret_linked_leaf - .\n.long 0\n.byte 1, 1\n', False),
        ("exception-instruction", [], '.section __ex_table,"a"\n'
         '.long fmodret_linked_leaf - .\n.long 0\n.long 0\n', True),
        ("exception-data-pointer", [], '.section __ex_table,"a"\n'
         '.long 0\n.long 0\n.long fmodret_linked_leaf - .\n', False),
        ("exception-local-fixup", [], '.section __ex_table,"a"\n'
         '.long fmodret_linked_leaf - .\n.long fmodret_linked_leaf - .\n.long 0\n',
         (False, True)),
        ("exception-other-function", [], '.section __ex_table,"a"\n'
         '.long fmodret_linked_entry - .\n.long fmodret_linked_leaf - .\n.long 0\n', False),
        ("bug-instruction", ["TEST_BUG"], '.section __bug_table,"a"\n'
         '.long fmodret_linked_bug - .\n.long 0\n.short 0, 0\n', True),
        ("bug-function-pointer", [], '.section __bug_table,"a"\n'
         '.long fmodret_linked_leaf - .\n.long 0\n.short 0, 0\n', False),
        ("undescribed-caller", [], '.text\n.globl unknown_caller\n'
         '.type unknown_caller,@function\nunknown_caller:\n'
         'call fmodret_linked_leaf\nret\n.size unknown_caller, . - unknown_caller\n', False),
        ("undescribed-syscall-dispatcher", [], '.text\n.globl unknown_caller\n'
         '.type unknown_caller,@function\nunknown_caller:\n'
         'call fmodret_linked_entry\nmov %rax, saved_register(%rip)\nret\n'
         '.size unknown_caller, . - unknown_caller\n'
         '.data\nsaved_register: .quad 0\n', True),
    ]
    return cases


def check_linked_case(case, number, command, fixtures, tmp, ld, pahole,
                      resolver, build, final):
    name, defines, assembly, expected = case
    source = fixtures / "fmodret_linked.c"
    obj, extra, linked = (tmp / ("linked-" + str(number) + suffix)
                          for suffix in (".o", ".S.o", ".elf"))
    run(command + ["-D" + d for d in defines] + ["-c", source, "-o", obj], build)
    objects = [obj]
    if Elf(obj).unpack("H", 18)[0] == EM_X86_64:
        assembly += ('.text\n.globl __x86_return_thunk\n'
                     '.type __x86_return_thunk,@function\n'
                     '__x86_return_thunk: ret\n'
                     '.size __x86_return_thunk, . - __x86_return_thunk\n')
    if assembly:
        asm = tmp / ("linked-" + str(number) + ".S")
        asm.write_text(assembly + '.section .note.GNU-stack,"",@progbits\n')
        run(command + ["-D__ASSEMBLY__", "-Wno-unused-command-line-argument",
                       "-c", asm, "-o", extra], build)
        objects.append(extra)
    script = tmp / "linked.lds"
    text = ("SECTIONS {\n"
            " .BTF_fmodret_candidates 0 (INFO) : { KEEP(*(.BTF_fmodret_candidates)) }\n")
    if final:
        text += " .text 0x100000 : { *(.text .text.*) }\n"
    text += (" __patchable_function_entries" + ("" if final else " 0") +
             " : { *(__patchable_function_entries) }\n}\n")
    script.write_text(text)
    flags = ["--emit-relocs", "-e", "fmodret_linked_leaf"] if final else ["-r"]
    run(ld + flags + ["-T", script, *objects, "-o", linked], build)
    btf = tmp / "linked.btf"
    run(pahole + ["--btf_features=encode_force,var,float,enum64,decl_tag,type_tag,optimized_func,consistent_func",
                  "--btf_encode_detached=" + str(btf), linked], build)
    result = run([resolver, "-v", "--btf", btf, linked], build)
    admitted = "fmodret_linked_leaf" in generated_ids(linked)
    if isinstance(expected, tuple):
        expected = expected[final]
    mode = "executable" if final else "relocatable"
    if admitted != expected:
        print("not ok", number, mode, name, "- unexpected fmod_ret tags")
        diagnostic(result.stderr)
        return 1
    print("ok", number, mode, name)
    return 0


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
    command += ["-g", "-fno-optimize-sibling-calls", "-fpatchable-function-entry=2,2"]
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
        result = run([resolver, "-v", "--btf", btf, linked], build)
        elf = Elf(objects[0])
        cases = linked_cases(elf.unpack("H", 18)[0], elf.ptr)
        states = dict(re.findall(r"^fmodret function: (\S+) .*? clean=(\S+) ",
                                 result.stderr, re.M))
        admitted = generated_ids(linked)
        print("TAP version 13")
        print("1.." + str(sum(len(names) for _, _, names in groups) + 1 + 2 * len(cases)))
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
                    error = "unexpected fmod_ret tags"
                elif name in admitted and admitted[name] != {"bpf_fmodret", "bpf_fmodret_auto"}:
                    error = "inferred function has unexpected tags"
                if error:
                    failed += 1
                    print("not ok", number, name, "-", error)
                else:
                    print("ok", number, name)
        number += 1
        entries = sorted(n for n in admitted if n.startswith("derived_entry_"))
        if entries:
            failed += 1
            print("not ok", number, "syscall entries are not tagged -", ", ".join(entries[:3]))
        else:
            print("ok", number, "syscall entries are not tagged")
        if failed:
            diagnostic(result.stderr)
        for case in cases:
            for final in (False, True):
                number += 1
                failed += check_linked_case(case, number, command, fixtures, tmp,
                                            ld, pahole, resolver, build, final)
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
