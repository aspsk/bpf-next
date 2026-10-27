/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __RESOLVE_BTFIDS_DATASEC_H
#define __RESOLVE_BTFIDS_DATASEC_H

#include <libelf.h>

struct btf;

/* If *btf is replaced, its original owner must keep the old BTF alive until
 * the replacement is freed: the original can own an embedded .BTF.base.
 */
int btf_datasec_fixup(struct btf **btf, Elf *elf, int verbose);

#endif
