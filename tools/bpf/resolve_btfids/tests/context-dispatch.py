#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check registration-bound callback entry ownership using native relocations."""
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile

root=Path(__file__).resolve().parents[4]
flags=shlex.split(os.environ.get('CONTEXT_TEST_CFLAGS',''))

def instruction_symbols(path):
    """Exercise instruction metadata referencing FUNC symbols plus addends."""
    data = bytearray(path.read_bytes())
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, names_index = struct.unpack_from('<HHH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size)
                for i in range(count)]
    strings = sections[names_index]
    names = data[strings[4]:strings[4] + strings[5]]
    rewritten = 0
    for section in sections:
        name = names[section[0]:names.index(0, section[0])]
        if name != b'.rela.return_sites':
            continue
        symbols = sections[section[6]]
        table = [struct.unpack_from('<IBBHQQ', data, symbols[4] + i * symbols[9])
                 for i in range(symbols[5] // symbols[9])]
        for pos in range(section[4], section[4] + section[5], section[9]):
            address, info, addend = struct.unpack_from('<QQq', data, pos)
            target = table[info >> 32]
            location = target[4] + addend
            for index, symbol in enumerate(table):
                if symbol[1] & 15 == 2 and symbol[3] == target[3] and \
                   symbol[4] <= location < symbol[4] + symbol[5]:
                    struct.pack_into('<QQq', data, pos, address,
                                     index << 32 | (info & 0xffffffff), location - symbol[4])
                    rewritten += 1
                    break
    assert rewritten, 'return-thunk fixture contains no native instruction records'
    path.write_bytes(data)

with tempfile.TemporaryDirectory(prefix='context-dispatch-') as tmp:
    cases = ['', 'TEST_DISPATCH_MIXED', 'TEST_DISPATCH_ESCAPED', 'TEST_DISPATCH_KEY_ESCAPE',
             'TEST_DISPATCH_SIGNATURE']
    native_trampoline = '-DTEST_DISPATCH_TRAMPOLINE' in flags
    if native_trampoline:
        cases.append('TEST_DISPATCH_OPAQUE_TRAMP')
    script = Path(tmp) / 'merged.lds'
    script.write_text('''SECTIONS {
      . = 0x10000;
      .text : { *(.text) *(.static_call.text) }
      .data : {
        *(.data) . = ALIGN(8);
        __start___jump_table = .; *(__jump_table) __stop___jump_table = .;
        __start_static_call_sites = .; *(.static_call_sites) __stop_static_call_sites = .;
        __start_mcount_loc = .; *(__mcount_loc) __stop_mcount_loc = .;
      }
      .bss : { *(.bss) }
      /DISCARD/ : { *(.discard.addressable) }
    }''')
    for case in cases:
        obj=Path(tmp)/'dispatch.o'
        image=Path(tmp)/('linked-'+(case or 'positive'))
        subprocess.run([os.environ.get('CLANG','clang-23'),'-O2','-g','-DWARN_CONTEXT_ANALYSIS',
            *flags,*(['-D'+case] if case else []),'-fexperimental-late-parse-attributes',
            '-fplugin='+str(root/'scripts/llvm-plugins/bpf_scan_ast.so'),
            '-fpass-plugin='+str(root/'scripts/llvm-plugins/bpf_context_ir.so'),
            '-c',str(Path(__file__).with_suffix('.c')),'-o',str(obj)],check=True)
        if os.environ.get('OBJTOOL'):
            subprocess.run([os.environ['OBJTOOL'], '--static-call', '--hacks=jump_label',
                            '--mcount', '--mnop',
                            *(['--link', '--rethunk', '--ibt'] if '-fcf-protection=branch' in flags else []),
                            str(obj)], check=True)
            if '-fcf-protection=branch' in flags:
                instruction_symbols(obj)
        if native_trampoline:
            subprocess.run([os.environ.get('OBJCOPY', 'objcopy'),
                            '--remove-section=.discard.annotate_insn', str(obj)], check=True)
        subprocess.run(['pahole','-J','--btf_features=var,global_var,decl_tag,type_tag',str(obj)],check=True)
        for merged in ([False, True] if native_trampoline else [False]):
            target = Path(str(image) + ('.merged' if merged else ''))
            subprocess.run([os.environ.get('LD','ld'),'--emit-relocs','--defsym=__bpf_context_native_calls=1',
                '--unresolved-symbols=ignore-all','-e','locked_dispatch',
                *(['-T', str(script)] if merged else []),str(obj),'-o',str(target)],check=True)
            result=subprocess.run([str(root/'tools/bpf/resolve_btfids/resolve_btfids'),'--context_analysis',
                '--verbose','--verbose',str(target)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            if result.returncode: print(result.stdout)
            result.check_returncode()
            records=json.loads(subprocess.check_output([str(root/'tools/bpf/bpftool/bpftool'),'-j','btf',
                'context-analysis','file',str(target)+'.BTF','func','callback_entry'],text=True))
            facts=[f for p in records for f in p['facts'] if f.get('fact')=='entry_held']
            if case:
                assert not facts,(case,facts,result.stdout)
            else:
                assert any(f['lock']=='arg(0)' and f['mode']=='exclusive' for f in facts),(facts,result.stdout)
            print('PASS registration closure:',case or 'closed callback acquires entry ownership',
                  '(merged tables)' if merged else '')
