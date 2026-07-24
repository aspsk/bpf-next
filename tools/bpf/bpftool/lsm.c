// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "main.h"
#include "skeleton/lsm_iter.h"

#define BPF_LSM_PREFIX		"bpf_lsm_"
#define LSM_ITER_F_KNOWN	(LSM_ITER_F_DISABLED |	\
				 LSM_ITER_F_BPF_ONLY |	\
				 LSM_ITER_F_SLEEPABLE)

#ifdef BPFTOOL_WITHOUT_SKELETONS

static int do_list(int argc, char **argv)
{
	if (argc)
		return BAD_ARG();

	p_err("bpftool was built without BPF skeleton support");
	return -EOPNOTSUPP;
}

#else /* BPFTOOL_WITHOUT_SKELETONS */

#include "lsm_iter.skel.h"

static int read_iterator(int fd, struct lsm_iter_entry **entries,
			 size_t *entry_cnt)
{
	unsigned char *buf = NULL;
	size_t capacity = 0;
	size_t len = 0;
	ssize_t ret;
	void *tmp;
	int err;

	while (true) {
		if (len == capacity) {
			size_t new_capacity = capacity ? capacity * 2 : 4096;

			if (new_capacity < capacity) {
				err = -EOVERFLOW;
				goto err_free;
			}

			tmp = realloc(buf, new_capacity);
			if (!tmp) {
				err = -ENOMEM;
				goto err_free;
			}
			buf = tmp;
			capacity = new_capacity;
		}

		ret = read(fd, buf + len, capacity - len);
		if (ret < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (ret < 0) {
			err = -errno;
			goto err_free;
		}
		if (!ret)
			break;

		len += ret;
	}

	if (len % sizeof(**entries)) {
		err = -EINVAL;
		goto err_free;
	}

	*entries = (void *)buf;
	*entry_cnt = len / sizeof(**entries);
	return 0;

err_free:
	free(buf);
	return err;
}

static int resolve_names(struct btf *btf, const struct lsm_iter_entry *entries,
			 size_t entry_cnt, const char ***names)
{
	const char **resolved_names;
	size_t i;

	if (!entry_cnt) {
		*names = NULL;
		return 0;
	}

	resolved_names = calloc(entry_cnt, sizeof(*resolved_names));
	if (!resolved_names)
		return -ENOMEM;

	for (i = 0; i < entry_cnt; i++) {
		const struct btf_type *type;
		const char *name;

		type = btf__type_by_id(btf, entries[i].btf_id);
		if (!type || !btf_is_func(type)) {
			p_err("BTF ID %u is not a function", entries[i].btf_id);
			free(resolved_names);
			return -EINVAL;
		}

		name = btf__name_by_offset(btf, type->name_off);
		if (!name || strncmp(name, BPF_LSM_PREFIX,
				     sizeof(BPF_LSM_PREFIX) - 1)) {
			p_err("BTF ID %u does not identify a BPF LSM hook",
			      entries[i].btf_id);
			free(resolved_names);
			return -EINVAL;
		}

		resolved_names[i] = name + sizeof(BPF_LSM_PREFIX) - 1;
	}

	*names = resolved_names;
	return 0;
}

static void show_entry_plain(const struct lsm_iter_entry *entry,
			     const char *name)
{
	__u32 unknown_flags = entry->flags & ~LSM_ITER_F_KNOWN;

	printf("%u: %s", entry->btf_id, name);
	if (entry->flags & LSM_ITER_F_DISABLED)
		printf(" disabled");
	if (entry->flags & LSM_ITER_F_BPF_ONLY)
		printf(" bpf_only");
	if (entry->flags & LSM_ITER_F_SLEEPABLE)
		printf(" sleepable");
	if (unknown_flags)
		printf(" unknown_flags=0x%x", unknown_flags);
	printf("\n");
}

static void show_entry_json(const struct lsm_iter_entry *entry,
			    const char *name)
{
	jsonw_start_object(json_wtr);
	jsonw_uint_field(json_wtr, "btf_id", entry->btf_id);
	jsonw_string_field(json_wtr, "name", name);
	jsonw_uint_field(json_wtr, "flags", entry->flags);
	jsonw_bool_field(json_wtr, "disabled",
			 entry->flags & LSM_ITER_F_DISABLED);
	jsonw_bool_field(json_wtr, "bpf_only",
			 entry->flags & LSM_ITER_F_BPF_ONLY);
	jsonw_bool_field(json_wtr, "sleepable",
			 entry->flags & LSM_ITER_F_SLEEPABLE);
	jsonw_end_object(json_wtr);
}

static int do_list(int argc, char **argv)
{
	struct lsm_iter_entry *entries = NULL;
	const char **names = NULL;
	struct lsm_iter_bpf *skel = NULL;
	struct btf *btf = NULL;
	size_t entry_cnt = 0;
	int iter_fd = -1;
	size_t i;
	int err;

	if (argc)
		return BAD_ARG();

	set_max_rlimit();

	skel = lsm_iter_bpf__open_and_load();
	if (!skel) {
		err = errno ? -errno : -EINVAL;
		p_err("failed to load BPF LSM iterator: %s", strerror(-err));
		goto out;
	}

	err = lsm_iter_bpf__attach(skel);
	if (err) {
		p_err("failed to attach BPF LSM iterator: %s", strerror(-err));
		goto out;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.iter));
	if (iter_fd < 0) {
		err = -errno;
		p_err("failed to create BPF LSM iterator session: %s",
		      strerror(-err));
		goto out;
	}

	err = read_iterator(iter_fd, &entries, &entry_cnt);
	if (err) {
		p_err("failed to read BPF LSM iterator output: %s",
		      strerror(-err));
		goto out;
	}

	btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf);
	if (err) {
		p_err("failed to load vmlinux BTF: %s", strerror(-err));
		btf = NULL;
		goto out;
	}

	err = resolve_names(btf, entries, entry_cnt, &names);
	if (err) {
		if (err == -ENOMEM)
			p_err("failed to allocate memory for BPF LSM hook names");
		goto out;
	}

	if (json_output)
		jsonw_start_array(json_wtr);
	for (i = 0; i < entry_cnt; i++) {
		if (json_output)
			show_entry_json(&entries[i], names[i]);
		else
			show_entry_plain(&entries[i], names[i]);
	}
	if (json_output)
		jsonw_end_array(json_wtr);

	err = 0;
out:
	if (iter_fd >= 0)
		close(iter_fd);
	lsm_iter_bpf__destroy(skel);
	btf__free(btf);
	free(names);
	free(entries);
	return err;
}

#endif /* BPFTOOL_WITHOUT_SKELETONS */

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s { list }\n"
		"       %1$s %2$s help\n"
		"       " HELP_SPEC_OPTIONS " }\n"
		"\n",
		bin_name, "lsm");

	return 0;
}

static const struct cmd cmds[] = {
	{ "list",	do_list },
	{ "help",	do_help },
	{ 0 }
};

int do_lsm(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
