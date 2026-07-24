// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <linux/btf.h>
#include <test_progs.h>
#include <unistd.h>

#include <bpf/btf.h>

#include "bpf_lsm_iter.skel.h"
#include "bpf_lsm_iter_fail.skel.h"
#include "progs/bpf_lsm_iter.h"

#define BPF_LSM_ITER_F_ALL	(BPF_LSM_ITER_F_DISABLED |	\
				 BPF_LSM_ITER_F_BPF_ONLY |	\
				 BPF_LSM_ITER_F_SLEEPABLE)

static int read_one_byte_at_a_time(int fd, void **data, size_t *data_len)
{
	unsigned char *buf = NULL;
	size_t capacity = 0;
	size_t len = 0;
	unsigned char byte;
	ssize_t ret;
	void *tmp;

	while (true) {
		ret = read(fd, &byte, sizeof(byte));
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			break;

		if (len == capacity) {
			capacity = capacity ? capacity * 2 : 256;
			tmp = realloc(buf, capacity);
			if (!tmp) {
				free(buf);
				return -ENOMEM;
			}
			buf = tmp;
		}
		buf[len++] = byte;
	}

	if (ret < 0) {
		ret = -errno;
		free(buf);
		return ret;
	}

	*data = buf;
	*data_len = len;
	return 0;
}

static const struct bpf_lsm_iter_entry *
find_entry(const struct bpf_lsm_iter_entry *entries, size_t count, __u32 btf_id)
{
	size_t left = 0;
	size_t right = count;

	while (left < right) {
		size_t mid = left + (right - left) / 2;

		if (entries[mid].btf_id < btf_id)
			left = mid + 1;
		else
			right = mid;
	}

	if (left == count || entries[left].btf_id != btf_id)
		return NULL;
	return &entries[left];
}

static void check_hook_flags(struct btf *btf,
			     const struct bpf_lsm_iter_entry *entries,
			     size_t count, const char *name, __u32 expected_flags)
{
	const struct bpf_lsm_iter_entry *entry;
	int btf_id;

	btf_id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
	if (!ASSERT_GT(btf_id, 0, name))
		return;

	entry = find_entry(entries, count, btf_id);
	if (!ASSERT_NEQ(entry, NULL, name))
		return;

	ASSERT_EQ(entry->flags, expected_flags, name);
}

static void run_bpf_lsm_iter(void)
{
	const struct bpf_lsm_iter_entry *entries;
	struct bpf_lsm_iter *skel = NULL;
	struct bpf_link *link = NULL;
	struct btf *btf = NULL;
	void *data = NULL;
	size_t data_len = 0;
	size_t count, i;
	int iter_fd = -1;
	int err;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		goto cleanup;

	skel = bpf_lsm_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_lsm_iter__open_and_load"))
		goto cleanup;

	link = bpf_program__attach_iter(skel->progs.dump_bpf_lsm, NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto cleanup;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create"))
		goto cleanup;

	err = read_one_byte_at_a_time(iter_fd, &data, &data_len);
	if (!ASSERT_OK(err, "read_one_byte_at_a_time"))
		goto cleanup;
	if (!ASSERT_GT(data_len, 0, "iterator_output_nonempty") ||
	    !ASSERT_EQ(data_len % sizeof(*entries), 0, "iterator_output_size"))
		goto cleanup;

	entries = data;
	count = data_len / sizeof(*entries);

	ASSERT_EQ(skel->bss->num_entries, count, "num_entries");
	ASSERT_EQ(skel->bss->num_terminal, 1, "num_terminal");

	for (i = 0; i < count; i++) {
		const struct btf_type *type;
		const char *name;

		if (!ASSERT_GT(entries[i].btf_id, 0, "valid_btf_id"))
			break;
		if (i && !ASSERT_LT(entries[i - 1].btf_id, entries[i].btf_id,
				    "sorted_unique_btf_ids"))
			break;

		type = btf__type_by_id(btf, entries[i].btf_id);
		if (!ASSERT_NEQ(type, NULL, "btf__type_by_id") ||
		    !ASSERT_EQ(BTF_INFO_KIND(type->info), BTF_KIND_FUNC,
			       "btf_kind_func"))
			break;

		name = btf__name_by_offset(btf, type->name_off);
		if (!ASSERT_NEQ(name, NULL, "btf__name_by_offset") ||
		    !ASSERT_EQ(strncmp(name, "bpf_lsm_", 8), 0,
			       "bpf_lsm_name_prefix"))
			break;

		if (!ASSERT_EQ(entries[i].flags & ~BPF_LSM_ITER_F_ALL, 0,
			       "known_flags"))
			break;
	}

	check_hook_flags(btf, entries, count, "bpf_lsm_file_alloc_security",
			 BPF_LSM_ITER_F_DISABLED);
	check_hook_flags(btf, entries, count, "bpf_lsm_file_open",
			 BPF_LSM_ITER_F_SLEEPABLE);
	check_hook_flags(btf, entries, count, "bpf_lsm_task_free", 0);

cleanup:
	if (iter_fd >= 0)
		close(iter_fd);
	bpf_link__destroy(link);
	bpf_lsm_iter__destroy(skel);
	btf__free(btf);
	free(data);
}

void test_bpf_lsm_iter(void)
{
	if (test__start_subtest("enumerate"))
		run_bpf_lsm_iter();
	if (test__start_subtest("verifier"))
		RUN_TESTS(bpf_lsm_iter_fail);
}
