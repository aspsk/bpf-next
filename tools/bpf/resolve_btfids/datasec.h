/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __RESOLVE_BTFIDS_DATASEC_H
#define __RESOLVE_BTFIDS_DATASEC_H

#include <libelf.h>

struct btf;

int btf_datasec_dedup(struct btf **btf, Elf *elf, int verbose);

#endif
