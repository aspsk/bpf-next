#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check atomic CLEAN_SEED recognition in readable kernel C examples."""
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

KSFT_SKIP = 4
FMODRET_MAGIC = 0x46524D32
FMODRET_VERSION = 4
FMODRET_FN_DEFINED = 1 << 0
FMODRET_FN_CLEAN_SEED = 1 << 2
SECTION = ".BTF_fmodret_candidates"


class Skip(Exception):
    pass


class Elf:
    """Small independent ELF reader; no resolver, BTF tool or Python packages."""
    def __init__(self, path):
        self.data = path.read_bytes()
        if self.data[:4] != b"\x7fELF" or self.data[4] not in (1, 2) or self.data[5] not in (1, 2):
            raise ValueError("expected a 32- or 64-bit ELF object")
        self.wide = self.data[4] == 2
        self.endian = "<" if self.data[5] == 1 else ">"
        self.ptr = 8 if self.wide else 4
        shoff = self.unpack("Q" if self.wide else "I", 40 if self.wide else 32)[0]
        entsize, count, namesid = self.unpack("HHH", 58 if self.wide else 46)
        self.sections = [self.unpack("IIQQQQIIQQ" if self.wide else "IIIIIIIIII",
                                     shoff + i * entsize) for i in range(count)]
        names = self.contents(namesid)
        self.names = [self.string(names, s[0]) for s in self.sections]

    def unpack(self, fmt, offset, data=None):
        return struct.unpack_from(self.endian + fmt, self.data if data is None else data, offset)

    @staticmethod
    def string(data, offset):
        return data[offset:data.index(b"\0", offset)].decode()

    def contents(self, index):
        section = self.sections[index]
        return self.data[section[4]:section[4] + section[5]]

    def symbols(self, index):
        section = self.sections[index]
        data = self.contents(index)
        strings = self.contents(section[6])
        result = []
        if not section[9]:
            raise ValueError("empty symbol entry size")
        for offset in range(0, len(data), section[9]):
            if self.wide:
                name, info, _, shndx, value, _ = self.unpack("IBBHQQ", offset, data)
            else:
                name, value, _, info, _, shndx = self.unpack("IIIBBH", offset, data)
            result.append((self.string(strings, name), info & 15, shndx, value))
        return result

    def function_relocations(self, target):
        relocations = {}
        for index, section in enumerate(self.sections):
            if section[1] not in (4, 9) or section[7] != target:
                continue
            symbols = self.symbols(section[6])
            data = self.contents(index)
            if not section[9]:
                raise ValueError("empty relocation entry size")
            for offset in range(0, len(data), section[9]):
                address, info = self.unpack("QQ" if self.wide else "II", offset, data)
                symbol = symbols[info >> (32 if self.wide else 8)]
                if section[1] == 4:  # RELA carries an explicit addend.
                    addend = self.unpack("q" if self.wide else "i", offset + 2 * self.ptr, data)[0]
                else:
                    addend = self.unpack("q" if self.wide else "i", address, self.contents(target))[0]
                name, kind, shndx, value = symbol
                if kind == 3:  # Local function references may use a section symbol.
                    matches = [s[0] for s in symbols if s[1] == 2 and s[2] == shndx
                               and s[3] == value + addend]
                    if len(matches) == 1:
                        relocations[address] = matches[0]
                elif kind in (0, 2) and name and not addend:
                    relocations[address] = name
        return relocations

    def clean_seeds(self):
        if SECTION not in self.names:
            raise ValueError("plugin emitted no " + SECTION)
        result = {}
        # LLVM may emit a separate, identically named section for each record.
        for index, section_name in enumerate(self.names):
            if section_name != SECTION:
                continue
            data = self.contents(index)
            relocations = self.function_relocations(index)
            offset = 0
            while offset < len(data):
                magic, version, size, flags = self.unpack("IIII", offset, data)
                if magic != FMODRET_MAGIC or version != FMODRET_VERSION:
                    raise ValueError("unexpected fmodret metadata magic/version")
                if size < 24 + self.ptr or offset + size > len(data):
                    raise ValueError("invalid function record size")
                name = relocations.get(offset + 16)
                if not name:
                    raise ValueError("function record has no unique symbol relocation")
                if name in result:
                    raise ValueError("duplicate function description: " + name)
                result[name] = flags
                offset = (offset + size + self.ptr - 1) & -self.ptr
        return result


def compile_arguments(build, command_file, clang):
    """Replay only the compiler, never the shell commands or Kbuild preparation."""
    text = command_file.read_text()
    saved = re.search(r"^(?:saved)?cmd_\S+\s*:=\s*(.+)$", text, re.M)
    source = re.search(r"^source_\S+\s*:=\s*(.+)$", text, re.M)
    if not saved or not source:
        raise ValueError("no saved compiler command/source in " + str(command_file))
    lexer = shlex.shlex(saved[1], posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    words = []
    for word in lexer:
        if word in (";", "&&", "||", "|", "<", ">", ">>"):
            break
        words.append(word.replace('\\"', '"'))
    prefix = next((i for i, word in enumerate(words) if word.startswith("-")), len(words))
    compiler = shlex.split(clang) if clang else words[:prefix]
    if not compiler or not shutil.which(compiler[0]):
        raise Skip("kernel compiler is unavailable; set CLANG or --clang")
    version = subprocess.run(compiler + ["--version"], cwd=build, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if version.returncode or "clang" not in version.stdout.lower():
        raise Skip("kernel compiler is not Clang; set CLANG or --clang")
    if "-c" not in words or source[1].strip() not in words:
        raise ValueError("saved command is not a C object compilation")
    result = compiler[:]
    skip_next = False
    for word in words[prefix:]:
        if skip_next:
            skip_next = False
            continue
        if word in ("-o", "-MF", "-MT", "-MQ"):
            skip_next = True
            continue
        if word in ("-c", "-MD", "-MMD", "-MP", "-pg", "-mfentry", "-ftest-coverage", source[1].strip()):
            continue
        if word.startswith(("-Wp,-M", "-fpass-plugin=", "-fplugin=", "-flto", "-fsanitize",
                            "-fno-sanitize", "-fprofile-", "-finstrument-functions", "-DKBUILD_", "-D__KBUILD_",
                            "-DLLVM_PLUGINS", "-DWARN_CONTEXT_ANALYSIS", "-Wthread-safety",
                            "--warning-suppression-mappings=")):
            continue
        result.append(word)
    plugin = build / "scripts/llvm-plugins/bpf_scan_ir.so"
    if not plugin.is_file():
        raise Skip("bpf_scan_ir.so is not built in " + str(build))
    result += ["-O2", "-fno-lto", "-fno-sanitize=all", "-fno-stack-protector",
               "-Wno-tautological-overlap-compare", "-Wno-tautological-negation-compare",
               "-Wno-missing-prototypes", "-Wno-missing-declarations", "-Wno-unused-but-set-variable",
               '-DKBUILD_BASENAME="fmodret_selftest"', '-DKBUILD_MODNAME="fmodret_selftest"',
               '-DKBUILD_MODFILE="fmodret_selftest"', "-D__KBUILD_MODNAME=fmodret_selftest",
               "-fpass-plugin=" + str(plugin)]
    return result


def diagnostic(message):
    for line in str(message).splitlines():
        print("# " + line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-build", type=Path,
                        help="configured kernel output directory (default: KBUILD_OUTPUT or source tree)")
    parser.add_argument("--compile-command", type=Path,
                        help="saved Kbuild .cmd file (default: kernel/.fork.o.cmd in the build directory)")
    parser.add_argument("--clang", default=os.environ.get("CLANG"),
                        help="compiler override; otherwise reuse the saved kernel compiler")
    args = parser.parse_args()
    fixtures = Path(__file__).resolve().parent / "llvm_plugins"
    default_build = os.environ.get("KBUILD_OUTPUT")
    if not args.kernel_build and not default_build:
        default_build = next((p for p in Path(__file__).resolve().parents
                              if (p / "scripts/llvm-plugins/fmodret_metadata.h").is_file()), None)
        if default_build is None:
            raise Skip("kernel tree unavailable; set --kernel-build or KBUILD_OUTPUT")
    build = (args.kernel_build or Path(default_build)).resolve()
    command_file = args.compile_command or build / "kernel/.fork.o.cmd"
    if not command_file.is_absolute():
        command_file = build / command_file
    for path in (build / "include/generated/autoconf.h", command_file):
        if not path.is_file():
            raise Skip("missing kernel build prerequisite: " + str(path))
    command = compile_arguments(build, command_file, args.clang)
    groups = []
    for category in ("clean", "unsafe"):
        path = fixtures / ("fmodret_" + category + ".c")
        names = re.findall(r"^FMODRET_TEST\s+.*?\b(fmodret_\w+)\s*\(", path.read_text(), re.M)
        if not names or len(set(names)) != len(names):
            raise ValueError("missing or duplicate fixture names in " + str(path))
        prefixes = ("fmodret_clean_",) if category == "clean" else ("fmodret_unsafe_", "fmodret_todo_")
        if any(not name.startswith(prefixes) for name in names):
            raise ValueError("fixture name does not match its category: " + str(path))
        groups.append((category, path, names))
    failed = 0
    number = 0
    with tempfile.TemporaryDirectory(prefix="bpf-llvm-plugins-") as tmp:
        tmp = Path(tmp)
        # Distinguish an unavailable/incompatible plugin from fixture failures.
        probe = subprocess.run(command + ["-x", "c", "-c", "-", "-o", str(tmp / "probe.o")],
                               cwd=build, input="int fmodret_probe(void) { return -22; }\n",
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if probe.returncode:
            if any(s in probe.stdout.lower() for s in ("unable to load plugin", "could not load library",
                                                       "failed to load passes", "unknown argument: '-fpass-plugin")):
                raise Skip("compiler cannot load bpf_scan_ir: " + probe.stdout.splitlines()[0])
            raise ValueError("kernel compiler probe failed:\n" + probe.stdout)
        if not Elf(tmp / "probe.o").clean_seeds().get("fmodret_probe", 0) & FMODRET_FN_CLEAN_SEED:
            raise ValueError("plugin did not recognize the constant-errno probe")
        print("TAP version 13")
        print("1.." + str(sum(len(names) for _, _, names in groups)))
        for category, path, names in groups:
            obj = tmp / (path.stem + ".o")
            result = subprocess.run(command + ["-c", str(path), "-o", str(obj)], cwd=build,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            diagnostic(result.stdout)
            records = {}
            error = None
            if result.returncode:
                error = "fixture compilation failed"
            else:
                try:
                    records = Elf(obj).clean_seeds()
                except (ValueError, IndexError, struct.error) as exc:
                    error = str(exc)
            if error:
                diagnostic(error)
            for name in names:
                number += 1
                if error or name not in records or not records[name] & FMODRET_FN_DEFINED:
                    print("not ok", number, name, "- missing valid function description")
                    failed += 1
                    continue
                clean = bool(records[name] & FMODRET_FN_CLEAN_SEED)
                if name.startswith("fmodret_todo_"):
                    if clean:
                        print("not ok", number, name, "- now recognized; move to fmodret_clean.c")
                        failed += 1
                    else:
                        print("ok", number, name, "- known limitation: clean state not yet recognized")
                elif clean == (category == "clean"):
                    print("ok", number, name)
                else:
                    print("not ok", number, name, "- unexpected CLEAN_SEED=" + str(int(clean)))
                    failed += 1
    return int(bool(failed))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Skip as exc:
        print("TAP version 13\n1..0 # SKIP " + str(exc))
        sys.exit(KSFT_SKIP)
    except (OSError, ValueError, IndexError, struct.error) as exc:
        print("TAP version 13\n1..1\nnot ok 1 - compiler plugin selftest")
        diagnostic(exc)
        sys.exit(1)
