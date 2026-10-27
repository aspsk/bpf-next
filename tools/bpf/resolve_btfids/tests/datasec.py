#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise DATASEC repairs against real linked ELF symbols and synthetic BTF."""
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[4]
resolver = root / 'tools/bpf/resolve_btfids/resolve_btfids'


def elf_symbols(path):
    data = path.read_bytes()
    endian = '<' if data[5] == 1 else '>'
    bits = data[4]
    if bits == 2:
        offset = struct.unpack_from(endian + 'Q', data, 40)[0]
        width, count, names_index = struct.unpack_from(endian + 'HHH', data, 58)
        fmt = 'IIQQQQIIQQ'
    else:
        offset = struct.unpack_from(endian + 'I', data, 32)[0]
        width, count, names_index = struct.unpack_from(endian + 'HHH', data, 46)
        fmt = 'IIIIIIIIII'
    sections = [struct.unpack_from(endian + fmt, data, offset + i * width)
                for i in range(count)]
    strings = sections[names_index]
    names = data[strings[4]:strings[4] + strings[5]]
    section_names = [names[s[0]:names.index(0, s[0])].decode() for s in sections]
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        names = data[strings[4]:strings[4] + strings[5]]
        for pos in range(section[4], section[4] + section[5], section[9]):
            if bits == 2:
                name, info, _, index, address, size = struct.unpack_from(endian + 'IBBHQQ', data, pos)
            else:
                name, address, size, info, _, index = struct.unpack_from(endian + 'IIIBBH', data, pos)
            if info & 15 != 1 or not 0 < index < len(sections):
                continue
            name = names[name:names.index(0, name)].decode()
            symbols.setdefault(name, []).append((section_names[index], address - sections[index][3], size))
    return endian, symbols, {name: section[5] for name, section in zip(section_names, sections)}


class Btf:
    def __init__(self, endian, base=None):
        self.endian = endian
        self.start = len(base.types) + 1 if base else 1
        self.string_start = len(base.strings) if base else 0
        self.strings = b'' if base else b'\0'
        self.types = []

    def add(self, kind, name, value, words=(), vlen=0):
        name_offset = 0
        if name:
            name_offset = self.string_start + len(self.strings)
            self.strings += name.encode() + b'\0'
        self.types.append(struct.pack(self.endian + 'III', name_offset, kind << 24 | vlen, value) +
                          struct.pack(self.endian + 'I' * len(words), *words))
        return self.start + len(self.types) - 1

    def write(self, path):
        types = b''.join(self.types)
        header = struct.pack(self.endian + 'HBBIIIII', 0xeb9f, 1, 0, 24, 0, len(types),
                             len(types), len(self.strings))
        path.write_bytes(header + types + self.strings)


def read_btf(path, base=None):
    data = path.read_bytes()
    endian = '<' if data[:2] == b'\x9f\xeb' else '>'
    _, _, _, header, offset, length, strings_offset, strings_length = struct.unpack_from(
        endian + 'HBBIIIII', data)
    strings = (base[1] if base else b'') + data[header + strings_offset:header + strings_offset + strings_length]
    records = dict(base[0]) if base else {}
    pos = header + offset
    while pos < header + offset + length:
        name, info, value = struct.unpack_from(endian + 'III', data, pos)
        pos += 12
        kind, count = info >> 24 & 127, info & 0xffffff
        size = {1: 4, 2: 0, 3: 12, 8: 0, 10: 0, 14: 4, 15: count * 12, 17: 4}[kind]
        words = struct.unpack_from(endian + 'I' * (size // 4), data, pos)
        records[len(records) + 1] = (kind, strings[name:strings.index(0, name)].decode(), value, words)
        pos += size
    return records, strings


with tempfile.TemporaryDirectory(prefix='btf-datasec-') as directory:
    tmp = Path(directory)
    source = tmp / 'strong.c'
    source.write_text('int shared = 7; int other = 9; void entry(void) {}\n'
                      'extern int shared_alias __attribute__((alias("shared")));\n'
                      'unsigned char shrunk = 1; unsigned char adjacent = 2;\n'
                      'static unsigned char p0 __asm__("piece.0") __attribute__((used)) = 1;\n'
                      'static unsigned char p1 __asm__("piece.1") __attribute__((used)) = 2;\n'
                      'static volatile int local = 1; int read_local(void) { return local; }\n')
    weak = tmp / 'weak.c'
    weak.write_text('int shared __attribute__((weak));\n'
                    'static volatile int local = 2; int read_other(void) { return local; }\n')
    objects = []
    for path in (source, weak):
        obj = path.with_suffix('.o')
        subprocess.run([os.environ.get('CLANG', 'clang-23'),
                        *shlex.split(os.environ.get('DATASEC_TEST_CFLAGS', '')),
                        '-O2', '-c', str(path), '-o', str(obj)], check=True)
        objects.append(str(obj))
    image = tmp / 'linked'
    subprocess.run([os.environ.get('LD', 'ld.lld-23'), '-e', 'entry', *objects, '-o', str(image)], check=True)
    endian, symbols, sections = elf_symbols(image)
    shared_section, shared_offset, shared_size = symbols['shared'][0]
    other_section, other_offset, other_size = symbols['other'][0]
    assert shared_section == other_section

    def run(name, different_type=False, base=False, false_identity=False,
            repeated_member=False, embedded=False):
        ancestor = Btf(endian) if base else None
        if ancestor:
            integer = ancestor.add(1, 'int', 4, [1 << 24 | 32])
        btf = Btf(endian, ancestor)
        if not ancestor:
            integer = btf.add(1, 'int', 4, [1 << 24 | 32])
        first = btf.add(14, 'shared', integer, [1])
        if different_type:
            integer = btf.add(1, 'unsigned int', 4, [32])
        duplicate = btf.add(14, 'other' if false_identity else 'shared', integer, [1])
        other = btf.add(14, 'other', integer, [1])
        btf.add(17, 'duplicate-reference', duplicate, [0xffffffff])
        btf.add(15, shared_section, sections[shared_section],
                [first, shared_offset, shared_size,
                 first if repeated_member else duplicate, shared_offset, shared_size,
                 other, other_offset, other_size], 3)
        raw = tmp / (name + '.btf')
        btf.write(raw)
        args = [str(resolver), '--verbose', '--btf', str(raw)]
        parent = None
        if ancestor:
            parent = tmp / 'base.btf'
            ancestor.write(parent)
            if not embedded:
                args += ['--btf_base', str(parent)]
        target = image
        if embedded:
            target = tmp / 'embedded'
            subprocess.run([os.environ.get('OBJCOPY', 'llvm-objcopy-23'),
                            '--add-section', '.BTF=' + str(raw),
                            '--add-section', '.BTF.base=' + str(parent),
                            str(image), str(target)], check=True)
            args = [str(resolver), '--verbose']
        result = subprocess.run([*args, str(target)], capture_output=True, text=True)
        if different_type:
            assert result.returncode and 'incompatible definitions' in result.stderr, result.stderr
            print('PASS incompatible definitions rejected')
            return
        if false_identity:
            assert result.returncode and 'overlaps' in result.stderr, result.stderr
            assert 'shared' in result.stderr and 'other' in result.stderr, result.stderr
            print('PASS unverified overlap rejected without merging distinct names')
            return
        assert result.returncode == 0, result.stderr
        records, _ = read_btf(Path(str(target) + '.BTF'), read_btf(parent) if parent else None)
        variables = [(i, t) for i, t in records.items() if t[0] == 14]
        members = next(t[3] for t in records.values() if t[0] == 15)
        shared = [i for i, t in variables if t[1] == 'shared']
        assert len(shared) == (2 if repeated_member else 1), records
        assert len(members) == 6, records
        tag = next(t for t in records.values() if t[0] == 17)
        assert tag[2] in shared, records
        if not repeated_member:
            assert tag[2] == shared[0], records
        if base:
            assert records[1][0] == 1 and all(t[2] == 1 for _, t in variables), records
        print('PASS', name)

    run('weak-strong')
    run('split-btf', base=True)
    run('embedded-base', base=True, embedded=True)
    run('distinct-names', false_identity=True)
    run('repeated-member', repeated_member=True)
    run('incompatible', different_type=True)

    def storage(name, rows, expected=None, error=None, base=False):
        ancestor = Btf(endian) if base else None
        if ancestor:
            integer = ancestor.add(1, 'int', 4, [1 << 24 | 32])
        btf = Btf(endian, ancestor)
        if not ancestor:
            integer = btf.add(1, 'int', 4, [1 << 24 | 32])
        members = []
        for variable, offset, size, linkage in rows:
            ident = btf.add(14, variable, integer, [linkage])
            members += [ident, offset, size]
            btf.add(17, 'keep-' + variable, ident, [0xffffffff])
        btf.add(15, shared_section, sections[shared_section], members, len(rows))
        raw = tmp / (name + '.btf')
        btf.write(raw)
        args = [str(resolver), '--verbose', '--btf', str(raw)]
        parent = None
        if ancestor:
            parent = tmp / 'base.btf'
            ancestor.write(parent)
            args += ['--btf_base', str(parent)]
        result = subprocess.run([*args, str(image)], capture_output=True, text=True)
        if error:
            assert result.returncode and error in result.stderr, result.stderr
        else:
            assert result.returncode == 0, result.stderr
            records, _ = read_btf(Path(str(image) + '.BTF'), read_btf(parent) if parent else None)
            members = next(t[3] for t in records.values() if t[0] == 15)
            actual = [(records[members[i]][1], members[i + 1], members[i + 2])
                      for i in range(0, len(members), 3)]
            assert actual == expected, (actual, expected)
            variables = {t[1]: (i, t) for i, t in records.items() if t[0] == 14}
            for variable, _, _, _ in rows:
                # Aliases and shrunk variables retain their source types and tags.
                ident, var = variables[variable]
                assert records[var[2]][0:3] == (1, 'int', 4), records
                assert any(t[0] == 17 and t[1] == 'keep-' + variable and t[2] == ident
                           for t in records.values()), records
        print('PASS', name)

    shrunk_section, shrunk_offset, shrunk_size = symbols['shrunk'][0]
    adjacent_section, adjacent_offset, adjacent_size = symbols['adjacent'][0]
    assert shrunk_section == adjacent_section == shared_section
    assert adjacent_offset == shrunk_offset + 1
    storage('optimized-size', [('shrunk', shrunk_offset, 4, 1), ('adjacent', adjacent_offset, 4, 1)],
            [('shrunk', shrunk_offset, 1), ('adjacent', adjacent_offset, 1)])
    storage('size-without-next-member', [('shrunk', shrunk_offset, 4, 1)],
            [('shrunk', shrunk_offset, 1)])
    storage('split-optimized-size', [('shrunk', shrunk_offset, 4, 1)],
            [('shrunk', shrunk_offset, 1)], base=True)
    # Incorrect incoming sizes must be corrected before duplicate matching.
    storage('duplicate-with-different-size', [('shared', shared_offset, 1, 1),
                                            ('shared', shared_offset, 4, 1)],
            [('shared', shared_offset, 4)])
    assert symbols['shared_alias'][0] == symbols['shared'][0]
    storage('verified-ELF-alias', [('shared', shared_offset, 4, 1),
                                 ('shared_alias', shared_offset, 4, 1)],
            [('shared', shared_offset, 4)])
    locals_ = sorted(symbols['local'], key=lambda x: x[1])
    assert len(locals_) == 2 and locals_[0][1] != locals_[1][1]
    storage('same-local-name', [('local', offset, size, 0) for _, offset, size in locals_],
            [('local', offset, size) for _, offset, size in locals_])
    pieces = sorted([symbols['piece.0'][0], symbols['piece.1'][0]], key=lambda x: x[1])
    storage('compiler-split-pieces', [('piece', offset, 4, 0) for _, offset, _ in pieces],
            [('piece', offset, size) for _, offset, size in pieces])
    storage('unknown-valid-piece', [('unknown_piece', shrunk_offset, 1, 0)],
            [('unknown_piece', shrunk_offset, 1)])
    storage('unverified-partial-overlap', [('shared', shared_offset, 4, 1),
                                         ('unknown_piece', shared_offset + 1, 1, 0)], error='overlaps')
    storage('offset-overflow', [('shrunk', 0xfffffffe, 4, 1)], error='outside section')
    storage('size-overflow', [('unknown_piece', shrunk_offset, 0xffffffff, 0)], error='outside section')
    storage('empty-unknown-piece', [('unknown_piece', shrunk_offset, 0, 0)], error='empty')

    for reverse in (False, True):
        btf = Btf(endian)
        integer = btf.add(1, 'int', 4, [1 << 24 | 32])
        char = btf.add(1, 'char', 1, [1 << 24 | 8])
        char = btf.add(10, '', char)
        short = btf.add(3, '', 0, [char, integer, 3])
        full = btf.add(3, '', 0, [char, integer, 4])
        a = btf.add(14, 'shared', full if reverse else short, [1])
        b = btf.add(14, 'shared', short if reverse else full, [1])
        btf.add(17, 'array-reference', a, [0xffffffff])
        btf.add(15, shared_section, sections[shared_section],
                [a, shared_offset, 4 if reverse else 3,
                 b, shared_offset, 3 if reverse else 4], 2)
        raw = tmp / 'array.btf'
        btf.write(raw)
        result = subprocess.run([str(resolver), '--btf', str(raw), str(image)],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        records, _ = read_btf(Path(str(image) + '.BTF'))
        variables = [(i, t) for i, t in records.items() if t[0] == 14]
        assert len(variables) == 1 and records[variables[0][1][2]][3][2] == 4, records
        assert next(t for t in records.values() if t[0] == 17)[2] == variables[0][0], records
        print('PASS final array extent', '(reverse order)' if reverse else '')
