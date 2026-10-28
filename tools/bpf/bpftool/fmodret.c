// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "main.h"

/* Decl tags added by resolve_btfids to functions in BTF_FMODRET sets */
#define TAG_FMODRET		"bpf_fmodret"
#define TAG_FMODRET_SLEEPABLE	"bpf_fmodret_sleepable"
#define TAG_FMODRET_AUTO	"bpf_fmodret_auto"

#define SYS_BTF_DIR		"/sys/kernel/btf"

#define F_TARGET		(1U << 0)
#define F_SLEEPABLE		(1U << 1)
#define F_AUTO			(1U << 2)

struct fmodret_entry {
	__u32 btf_id;
	unsigned int flags;
};

static int cmp_entry(const void *a, const void *b)
{
	const struct fmodret_entry *x = a, *y = b;

	return (x->btf_id > y->btf_id) - (x->btf_id < y->btf_id);
}

/* Return the fmod_ret targets of BTF, sorted by BTF ID */
static int collect_targets(const struct btf *btf, struct fmodret_entry **targets,
			   size_t *target_cnt)
{
	const struct btf *base = btf__base_btf(btf);
	__u32 id, nr_types = btf__type_cnt(btf);
	struct fmodret_entry *entries = NULL, *tmp;
	size_t cnt = 0, capacity = 0, i, out = 0;

	/* Each tag is a separate type, so join the tags of a function by ID */
	for (id = base ? btf__type_cnt(base) : 1; id < nr_types; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);
		unsigned int flags;
		const char *name;

		if (!btf_is_decl_tag(t) || btf_decl_tag(t)->component_idx != -1)
			continue;
		name = btf__name_by_offset(btf, t->name_off);
		if (!strcmp(name, TAG_FMODRET))
			flags = F_TARGET;
		else if (!strcmp(name, TAG_FMODRET_SLEEPABLE))
			flags = F_SLEEPABLE;
		else if (!strcmp(name, TAG_FMODRET_AUTO))
			flags = F_AUTO;
		else
			continue;
		if (!btf_is_func(btf__type_by_id(btf, t->type)))
			continue;

		if (cnt == capacity) {
			capacity = capacity ? 2 * capacity : 64;
			tmp = realloc(entries, capacity * sizeof(*entries));
			if (!tmp) {
				free(entries);
				return -ENOMEM;
			}
			entries = tmp;
		}
		entries[cnt].btf_id = t->type;
		entries[cnt].flags = flags;
		cnt++;
	}

	qsort(entries, cnt, sizeof(*entries), cmp_entry);
	for (i = 0; i < cnt; i++) {
		if (out && entries[out - 1].btf_id == entries[i].btf_id)
			entries[out - 1].flags |= entries[i].flags;
		else
			entries[out++] = entries[i];
	}
	/* A sleepable tag alone does not make a target */
	for (i = 0, cnt = 0; i < out; i++)
		if (entries[i].flags & F_TARGET)
			entries[cnt++] = entries[i];

	*targets = entries;
	*target_cnt = cnt;
	return 0;
}

static void show_target(const char *owner, const struct btf *btf,
			const struct fmodret_entry *entry)
{
	const struct btf_type *t = btf__type_by_id(btf, entry->btf_id);
	const char *name = btf__name_by_offset(btf, t->name_off);
	bool sleepable = entry->flags & F_SLEEPABLE;
	bool automatic = entry->flags & F_AUTO;

	if (json_output) {
		jsonw_start_object(json_wtr);
		jsonw_uint_field(json_wtr, "btf_id", entry->btf_id);
		jsonw_string_field(json_wtr, "name", name);
		jsonw_string_field(json_wtr, "owner", owner);
		jsonw_bool_field(json_wtr, "sleepable", sleepable);
		jsonw_bool_field(json_wtr, "auto", automatic);
		jsonw_end_object(json_wtr);
	} else {
		printf("%u  %s (%s)%s%s\n", entry->btf_id, name, owner,
		       sleepable ? " sleepable" : "", automatic ? " auto" : "");
	}
}

static int show_btf(const char *owner, const struct btf *btf)
{
	struct fmodret_entry *targets = NULL;
	size_t cnt = 0, i;
	int err;

	err = collect_targets(btf, &targets, &cnt);
	if (err) {
		p_err("failed to collect fmod_ret targets of %s: %s", owner,
		      strerror(-err));
		return err;
	}
	for (i = 0; i < cnt; i++)
		show_target(owner, btf, &targets[i]);
	free(targets);
	return 0;
}

static int filter_module(const struct dirent *entry)
{
	size_t len = strlen(entry->d_name);

	/* Skip ".", "..", vmlinux and the ".inline" companions of modules */
	return entry->d_name[0] != '.' && strcmp(entry->d_name, "vmlinux") &&
	       !(len > 7 && !strcmp(entry->d_name + len - 7, ".inline"));
}

static int show_live(void)
{
	struct dirent **modules = NULL;
	struct btf *vmlinux;
	int i, nr_modules, err;

	vmlinux = btf__load_vmlinux_btf();
	err = libbpf_get_error(vmlinux);
	if (err) {
		p_err("failed to load vmlinux BTF: %s", strerror(-err));
		return err;
	}
	err = show_btf("vmlinux", vmlinux);
	if (err)
		goto out;

	/* There is no module directory without module BTF, which is fine */
	nr_modules = scandir(SYS_BTF_DIR, &modules, filter_module, alphasort);
	for (i = 0; i < nr_modules; i++) {
		const char *name = modules[i]->d_name;
		struct btf *btf;

		btf = btf__load_module_btf(name, vmlinux);
		if (libbpf_get_error(btf)) {
			/* The module may have been unloaded meanwhile */
			p_info("failed to load BTF of module %s", name);
			continue;
		}
		err = show_btf(name, btf);
		btf__free(btf);
		if (err)
			break;
	}
	for (i = 0; i < nr_modules; i++)
		free(modules[i]);
	free(modules);
out:
	btf__free(vmlinux);
	return err;
}

static int show_file(const char *path)
{
	struct btf *btf;
	int err;

	btf = btf__parse(path, NULL);
	err = libbpf_get_error(btf);
	if (err) {
		p_err("failed to parse BTF from %s: %s", path, strerror(-err));
		return err;
	}
	err = show_btf(path, btf);
	btf__free(btf);
	return err;
}

static int do_list(int argc, char **argv)
{
	const char *path = NULL;
	int err;

	if (argc) {
		if (!is_prefix(*argv, "file"))
			return BAD_ARG();
		NEXT_ARG();
		if (!REQ_ARGS(1))
			return -1;
		path = GET_ARG();
		if (argc)
			return BAD_ARG();
	}

	if (json_output)
		jsonw_start_array(json_wtr);
	err = path ? show_file(path) : show_live();
	if (json_output)
		jsonw_end_array(json_wtr);

	return err;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s list [file FILE]\n"
		"       %1$s %2$s help\n"
		"       " HELP_SPEC_OPTIONS " }\n"
		"\n",
		bin_name, "fmodret");
	return 0;
}

static const struct cmd cmds[] = {
	{ "list",	do_list },
	{ "help",	do_help },
	{ 0 }
};

int do_fmodret(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
