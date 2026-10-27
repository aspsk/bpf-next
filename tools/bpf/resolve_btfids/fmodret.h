/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RESOLVE_BTFIDS_FMODRET_H
#define __RESOLVE_BTFIDS_FMODRET_H

#include <libelf.h>

struct btf;
struct btf_id_set8;

int fmodret_analyse_collect(Elf *elf, const struct btf *btf,
			    struct btf_id_set8 **result, int verbose);

#endif
