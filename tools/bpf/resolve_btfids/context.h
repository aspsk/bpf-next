/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RESOLVE_BTFIDS_CONTEXT_H
#define RESOLVE_BTFIDS_CONTEXT_H

struct btf;
int context_btf_generate(const char *path, struct btf *btf, int verbose);

#endif
