// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <gelf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf_internal.h>

#include "datasec.h"

struct variable_symbol {
	const char *name;
	GElf_Addr offset;
	GElf_Xword size;
	size_t section;
	unsigned int binding;
};

struct variable_symbols {
	struct variable_symbol *v;
	size_t n;
};

static int cmp_symbol(const void *left, const void *right)
{
	const struct variable_symbol *a = left, *b = right;

	if (a->section != b->section)
		return a->section < b->section ? -1 : 1;
	if (a->offset != b->offset)
		return a->offset < b->offset ? -1 : 1;
	return strcmp(a->name, b->name);
}

static int collect_symbols(Elf *elf, struct variable_symbols *symbols)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;

	while ((scn = elf_nextscn(elf, scn))) {
		Elf_Data *data;
		size_t i, count;

		if (!gelf_getshdr(scn, &shdr))
			return -EINVAL;
		if (shdr.sh_type != SHT_SYMTAB)
			continue;
		if (!shdr.sh_entsize || shdr.sh_size / shdr.sh_entsize > INT_MAX)
			return -EINVAL;
		count = shdr.sh_size / shdr.sh_entsize;
		data = elf_getdata(scn, NULL);
		if (!data)
			return -EINVAL;
		symbols->v = calloc(count ?: 1, sizeof(*symbols->v));
		if (!symbols->v)
			return -ENOMEM;
		for (i = 0; i < count; i++) {
			struct variable_symbol *out = &symbols->v[symbols->n];
			GElf_Shdr target;
			GElf_Sym sym;

			if (!gelf_getsym(data, i, &sym))
				return -EINVAL;
			if (GELF_ST_TYPE(sym.st_info) != STT_OBJECT ||
			    sym.st_shndx == SHN_UNDEF || sym.st_shndx >= SHN_LORESERVE)
				continue;
			if (!gelf_getshdr(elf_getscn(elf, sym.st_shndx), &target) ||
			    sym.st_value < target.sh_addr)
				return -EINVAL;
			out->name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (!out->name)
				return -EINVAL;
			out->section = sym.st_shndx;
			out->offset = sym.st_value - target.sh_addr;
			out->size = sym.st_size;
			out->binding = GELF_ST_BIND(sym.st_info);
			symbols->n++;
		}
		qsort(symbols->v, symbols->n, sizeof(*symbols->v), cmp_symbol);
		return 0;
	}
	return 0;
}

static Elf_Scn *find_section(Elf *elf, const char *name)
{
	Elf_Scn *scn = NULL;
	size_t strings;
	GElf_Shdr shdr;

	if (elf_getshdrstrndx(elf, &strings))
		return NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		const char *section;

		if (!gelf_getshdr(scn, &shdr))
			return NULL;
		section = elf_strptr(elf, strings, shdr.sh_name);
		if (section && !strcmp(section, name))
			return scn;
	}
	return NULL;
}

/* Match a variable to storage, not just to a possibly repeated local name. */
static const struct variable_symbol *find_symbol(const struct variable_symbols *symbols,
						Elf_Scn *section, const char *name,
						__u32 offset)
{
	struct variable_symbol key = {
		.name = name,
		.section = elf_ndxscn(section),
		.offset = offset,
	};
	const struct variable_symbol *symbol, *first, *last;

	if (!symbols->n)
		return NULL;
	symbol = bsearch(&key, symbols->v, symbols->n, sizeof(*symbols->v), cmp_symbol);
	if (!symbol)
		return NULL;
	first = symbol;
	last = symbols->v + symbols->n;
	while (first > symbols->v && !cmp_symbol(&key, first - 1))
		first--;
	for (symbol = first + 1; symbol < last && !cmp_symbol(&key, symbol); symbol++)
		if (symbol->size != first->size || symbol->binding != first->binding)
			return NULL;
	return first;
}

struct variable {
	struct btf_var_secinfo info;
	const char *name;
	__u32 type;
	unsigned int linkage;
};

static int cmp_variable(const void *left, const void *right)
{
	const struct variable *a = left, *b = right;
	int cmp;

	if (a->info.offset != b->info.offset)
		return a->info.offset < b->info.offset ? -1 : 1;
	cmp = strcmp(a->name, b->name);
	if (cmp)
		return cmp;
	if (a->info.size != b->info.size)
		return a->info.size < b->info.size ? -1 : 1;
	return a->info.type < b->info.type ? -1 : a->info.type != b->info.type;
}

static int cmp_secinfo(const void *left, const void *right)
{
	const struct btf_var_secinfo *a = left, *b = right;

	if (a->offset != b->offset)
		return a->offset < b->offset ? -1 : 1;
	if (a->type != b->type)
		return a->type < b->type ? -1 : 1;
	return a->size < b->size ? -1 : a->size != b->size;
}

/* Rebuild to remove duplicate VARs and DATASEC members, then remap every kind. */
static int rebuild_btf(struct btf **btfp, __u32 *canonical)
{
	struct btf *src = *btfp, *dst;
	const struct btf *base = btf__base_btf(src);
	LIBBPF_OPTS(btf_new_opts, opts,
		.base_btf = (struct btf *)base,
		.add_layout = btf_header(src)->layout_len != 0,
	);
	__u32 start = base ? btf__type_cnt(base) : 1;
	__u32 n = btf__type_cnt(src), i, *id_map;
	int err = -ENOMEM;

	id_map = calloc(n, sizeof(*id_map));
	if (!id_map)
		return -ENOMEM;
	dst = btf__new_empty_opts(&opts);
	if (!dst)
		goto out;
	btf__set_endianness(dst, btf__endianness(src));
	if (btf__pointer_size(src))
		btf__set_pointer_size(dst, btf__pointer_size(src));
	for (i = 0; i < start; i++)
		id_map[i] = i;
	for (i = start; i < n; i++) {
		const struct btf_type *t = btf__type_by_id(src, i);

		if (canonical[i] != i)
			continue;
		if (btf_is_datasec(t)) {
			struct btf_var_secinfo *v;
			__u32 j, count = btf_vlen(t);

			v = calloc(count ?: 1, sizeof(*v));
			if (!v) {
				err = -ENOMEM;
				goto out;
			}
			memcpy(v, btf_var_secinfos(t), count * sizeof(*v));
			for (j = 0; j < count; j++)
				v[j].type = canonical[v[j].type];
			qsort(v, count, sizeof(*v), cmp_secinfo);
			err = btf__add_datasec(dst, btf__name_by_offset(src, t->name_off), t->size);
			if (err >= 0) {
				id_map[i] = err;
				for (j = 0; j < count; j++) {
					if (j && !cmp_secinfo(&v[j - 1], &v[j]))
						continue;
					err = btf__add_datasec_var_info(dst, v[j].type, v[j].offset, v[j].size);
					if (err < 0)
						break;
				}
			}
			free(v);
		} else {
			err = btf__add_type(dst, src, t);
			if (err >= 0)
				id_map[i] = err;
		}
		if (err < 0)
			goto out;
	}
	for (i = start; i < n; i++)
		if (canonical[i] != i)
			id_map[i] = id_map[canonical[i]];
	for (i = start; i < btf__type_cnt(dst); i++) {
		struct btf_type *t = (struct btf_type *)btf__type_by_id(dst, i);
		struct btf_field_iter it;
		__u32 *id;

		err = btf_field_iter_init(&it, t, BTF_FIELD_ITER_IDS);
		if (err)
			goto out;
		while ((id = btf_field_iter_next(&it))) {
			if (*id >= n) {
				err = -EINVAL;
				goto out;
			}
			*id = id_map[*id];
		}
	}
	btf__free(src);
	*btfp = dst;
	dst = NULL;
	err = 0;
out:
	btf__free(dst);
	free(id_map);
	return err;
}

int btf_datasec_dedup(struct btf **btfp, Elf *elf, int verbose)
{
	struct variable_symbols symbols = {};
	struct btf *btf = *btfp;
	const struct btf *base = btf__base_btf(btf);
	__u32 start = base ? btf__type_cnt(base) : 1;
	__u32 i, n, *canonical = NULL, duplicates = 0;
	int err;

	/* Compare referenced types only after their ordinary deduplication. */
	err = btf__dedup(btf, NULL);
	if (err)
		return err;
	err = collect_symbols(elf, &symbols);
	if (err)
		goto out;
	n = btf__type_cnt(btf);
	canonical = malloc(n * sizeof(*canonical));
	if (!canonical) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < n; i++)
		canonical[i] = i;
	for (i = start; i < n; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		struct variable *v;
		Elf_Scn *section;
		__u32 j, count;

		if (!btf_is_datasec(t))
			continue;
		section = find_section(elf, btf__name_by_offset(btf, t->name_off));
		if (!section)
			continue;
		count = btf_vlen(t);
		v = calloc(count ?: 1, sizeof(*v));
		if (!v) {
			err = -ENOMEM;
			goto out;
		}
		for (j = 0; j < count; j++) {
			const struct btf_type *var;

			v[j].info = btf_var_secinfos(t)[j];
			var = btf__type_by_id(btf, v[j].info.type);
			if (!var || !btf_is_var(var)) {
				free(v);
				err = -EINVAL;
				goto out;
			}
			v[j].name = btf__name_by_offset(btf, var->name_off);
			v[j].type = var->type;
			v[j].linkage = btf_var(var)->linkage;
		}
		qsort(v, count, sizeof(*v), cmp_variable);
		for (j = 1; j < count; j++) {
			const struct variable_symbol *symbol;
			struct variable *a = &v[j - 1], *b = &v[j];

			if (a->info.offset != b->info.offset || a->info.size != b->info.size ||
			    strcmp(a->name, b->name) ||
			    a->linkage != BTF_VAR_GLOBAL_ALLOCATED ||
			    b->linkage != BTF_VAR_GLOBAL_ALLOCATED)
				continue;
			symbol = find_symbol(&symbols, section, b->name, b->info.offset);
			if (!symbol || (symbol->binding != STB_GLOBAL && symbol->binding != STB_WEAK))
				continue;
			if (a->type != b->type) {
				fprintf(stderr, "DATASEC %s: incompatible definitions of %s at %#x\n",
					btf__name_by_offset(btf, t->name_off), b->name, b->info.offset);
				free(v);
				err = -EINVAL;
				goto out;
			}
			canonical[b->info.type] = canonical[a->info.type];
			duplicates++;
		}
		free(v);
	}
	if (duplicates) {
		for (i = start; i < n; i++)
			while (canonical[i] != canonical[canonical[i]])
				canonical[i] = canonical[canonical[i]];
		err = rebuild_btf(btfp, canonical);
	}
	if (!err && verbose)
		fprintf(stderr, "DATASEC: merged %u duplicate global variable records\n", duplicates);
out:
	free(canonical);
	free(symbols.v);
	return err;
}
