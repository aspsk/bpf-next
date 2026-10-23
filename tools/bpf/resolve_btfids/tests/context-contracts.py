#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check spin ownership interfaces across separately compiled objects."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[4]
source = Path(__file__).with_suffix('.c')
disabled_provider = bool(os.environ.get('CONTEXT_PROVIDER_DISABLE'))
with tempfile.TemporaryDirectory(prefix='context-contracts-') as tmp:
    objects = []
    for provider in (False, True):
        obj = Path(tmp) / ('provider.o' if provider else 'caller.o')
        subprocess.run(['clang-23', '-O2', '-g',
            *(['-DCONTEXT_PROVIDER', *(['-DWARN_CONTEXT_ANALYSIS', '-DCONTEXT_PROVIDER_DISABLE']
               if disabled_provider else [])] if provider else ['-DWARN_CONTEXT_ANALYSIS']),
            '-fexperimental-late-parse-attributes',
            '-fplugin=' + str(root / 'scripts/llvm-plugins/bpf_scan_ast.so'),
            '-fpass-plugin=' + str(root / 'scripts/llvm-plugins/bpf_context_ir.so'),
            '-c', str(source), '-o', str(obj)], check=True)
        objects.append(str(obj))
    image = Path(tmp) / 'linked.o'
    subprocess.run(['ld', '-r', *objects, '-o', str(image)], check=True)
    subprocess.run(['pahole', '-J', '--btf_features=var,global_var,decl_tag,type_tag', str(image)], check=True)
    subprocess.run([str(root / 'tools/bpf/resolve_btfids/resolve_btfids'),
                    '--context_analysis', str(image)], check=True)
    data = json.loads(subprocess.check_output([str(root / 'tools/bpf/bpftool/bpftool'),
        '-j', 'btf', 'context-analysis', 'file', str(image) + '.BTF'], text=True))
    entries = {f['name']: [x for x in f['facts'] if x.get('fact') == 'entry_held'] for f in data}
    if disabled_provider:
        assert not entries.get('after_legacy'), entries
        print('PASS ownership withheld when only the definition disables analysis')
    else:
        assert any(x['lock'] == 'arg(0)' for x in entries.get('after_legacy', [])), entries
        print('PASS spin ownership across a complete direct-call interface')
    for name in ('after_legacy_unlock', 'after_unchecked', 'after_external'):
        assert not entries.get(name), (name, entries.get(name))
        print('PASS spin ownership withheld:', name)
