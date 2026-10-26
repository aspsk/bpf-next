// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include "context_locking.skel.h"

void test_context_locking(void)
{
	const char *prefix = "bpf_context:v1:";
	struct btf *btf;
	bool available = false;
	__u32 i;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "vmlinux_btf"))
		return;
	for (i = 1; i < btf__type_cnt(btf); i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);

		if (btf_is_decl_tag(t) &&
		    !strncmp(btf__name_by_offset(btf, t->name_off), prefix, strlen(prefix))) {
			available = true;
			break;
		}
	}
	btf__free(btf);
	/* Context analysis is optional. Missing hook facts on a kernel with
	 * analysis metadata must fail the rejection test rather than skip it.
	 */
	if (!available) {
		test__skip();
		return;
	}
	RUN_TESTS(context_locking);
}
