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
	size_t low, high, length = strlen(name);

	if (!symbols->n)
		return NULL;
	symbol = bsearch(&key, symbols->v, symbols->n, sizeof(*symbols->v), cmp_symbol);
	if (!symbol) {
		/* LLVM global optimization can split a source variable into
		 * objects named NAME.0, NAME.1, ... . DWARF/BTF retains NAME
		 * and the source type for a piece. Require its exact address.
		 */
		key.name = "";
		low = 0;
		high = symbols->n;
		while (low < high) {
			size_t mid = low + (high - low) / 2;

			if (cmp_symbol(&symbols->v[mid], &key) < 0)
				low = mid + 1;
			else
				high = mid;
		}
		first = NULL;
		for (; low < symbols->n; low++) {
			const char *suffix;

			symbol = &symbols->v[low];
			if (symbol->section != key.section || symbol->offset != key.offset)
				break;
			if (strncmp(symbol->name, name, length) || symbol->name[length] != '.')
				continue;
			suffix = symbol->name + length + 1;
			if (!*suffix || strspn(suffix, "0123456789") != strlen(suffix))
				continue;
			if (first && (first->size != symbol->size || first->binding != symbol->binding))
				return NULL;
			first = symbol;
		}
		return first;
	}
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

static __u32 canonical_id(const __u32 *canonical, __u32 id)
{
	while (canonical[id] != id)
		id = canonical[id];
	return id;
}

static int select_definition(struct btf *btf, __u32 a, __u32 b,
			     const struct variable_symbol *symbol)
{
	const struct btf_type *va = btf__type_by_id(btf, a);
	const struct btf_type *vb = btf__type_by_id(btf, b);
	const struct btf_type *ta, *tb;
	int type_a, type_b;

	if (va->type == vb->type)
		return a < b ? a : b;
	/* A weak array can have an older extent, e.g. linux_banner after the
	 * final timestamp rebuild. Select the extent matching actual storage,
	 * provided the array element and index types agree.
	 */
	type_a = btf__resolve_type(btf, va->type);
	type_b = btf__resolve_type(btf, vb->type);
	if (type_a < 0 || type_b < 0)
		return -EINVAL;
	ta = btf__type_by_id(btf, type_a);
	tb = btf__type_by_id(btf, type_b);
	if (!btf_is_array(ta) || !btf_is_array(tb) ||
	    btf_array(ta)->type != btf_array(tb)->type ||
	    btf_array(ta)->index_type != btf_array(tb)->index_type)
		return -EINVAL;
	if (btf__resolve_size(btf, va->type) == symbol->size)
		return a;
	if (btf__resolve_size(btf, vb->type) == symbol->size)
		return b;
	return -EINVAL;
}

static bool storage_alias(struct btf *btf, const struct variable_symbols *symbols,
			  Elf_Scn *section, const struct btf_var_secinfo *a,
			  const struct btf_var_secinfo *b)
{
	const struct variable_symbol *sa, *sb;
	const struct btf_type *va, *vb;

	if (!section || !a->size || a->offset != b->offset || a->size != b->size)
		return false;
	va = btf__type_by_id(btf, a->type);
	vb = btf__type_by_id(btf, b->type);
	sa = find_symbol(symbols, section, btf__name_by_offset(btf, va->name_off), a->offset);
	sb = find_symbol(symbols, section, btf__name_by_offset(btf, vb->name_off), b->offset);
	return sa && sb && sa->size == a->size && sb->size == b->size;
}

/* Rebuild to remove duplicate VARs and DATASEC members, then remap every kind. */
static int rebuild_btf(struct btf **btfp, __u32 *canonical, Elf *elf,
		       const struct variable_symbols *symbols, int verbose)
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
			const char *name = btf__name_by_offset(src, t->name_off);
			Elf_Scn *section = find_section(elf, name);
			__u32 j, last = 0, count = btf_vlen(t);

			v = calloc(count ?: 1, sizeof(*v));
			if (!v) {
				err = -ENOMEM;
				goto out;
			}
			memcpy(v, btf_var_secinfos(t), count * sizeof(*v));
			for (j = 0; j < count; j++)
				v[j].type = canonical[v[j].type];
			qsort(v, count, sizeof(*v), cmp_secinfo);
			err = btf__add_datasec(dst, name, t->size);
			if (err >= 0) {
				id_map[i] = err;
				for (j = 0; j < count; j++) {
					if (j && !cmp_secinfo(&v[j - 1], &v[j]))
						continue;
					/* Constant merging and explicit aliases can give distinct
					 * variables exactly the same ELF storage. Describe it once,
					 * but retain every alias VAR and its original source type.
					 */
					if (j && storage_alias(src, symbols, section, &v[last], &v[j])) {
						if (verbose)
							fprintf(stderr, "DATASEC %s: shared storage at %#x, retaining alias VAR %s\n",
								name, v[j].offset,
								btf__name_by_offset(src, btf__type_by_id(src, v[j].type)->name_off));
						continue;
					}
					err = btf__add_datasec_var_info(dst, v[j].type, v[j].offset, v[j].size);
					if (err < 0)
						break;
					last = j;
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
	*btfp = dst;
	dst = NULL;
	err = 0;
out:
	btf__free(dst);
	free(id_map);
	return err;
}

static int fix_storage_sizes(struct btf *btf, Elf *elf,
			     const struct variable_symbols *symbols, int verbose)
{
	const struct btf *base = btf__base_btf(btf);
	__u32 start = base ? btf__type_cnt(base) : 1, i;
	unsigned int resized = 0;

	/* btf__dedup() has made the local types modifiable. No raw-data
	 * serialization may be cached between this point and the repairs.
	 */
	for (i = start; i < btf__type_cnt(btf); i++) {
		struct btf_type *t = (struct btf_type *)btf__type_by_id(btf, i);
		const char *name;
		Elf_Scn *section;
		GElf_Shdr shdr;
		__u32 j;

		if (!btf_is_datasec(t))
			continue;
		name = btf__name_by_offset(btf, t->name_off);
		section = find_section(elf, name);
		/* Size-zero object-file DATASECs can be unresolved BPF metadata.
		 * Leave relocation of those records to their existing consumers.
		 */
		if (!section || !t->size)
			continue;
		if (!gelf_getshdr(section, &shdr) || shdr.sh_size > UINT_MAX)
			return -E2BIG;
		t->size = shdr.sh_size;
		for (j = 0; j < btf_vlen(t); j++) {
			struct btf_var_secinfo *v = btf_var_secinfos(t) + j;
			const struct variable_symbol *symbol;
			const struct btf_type *var = btf__type_by_id(btf, v->type);

			if (!var || !btf_is_var(var))
				return -EINVAL;
			symbol = find_symbol(symbols, section, btf__name_by_offset(btf, var->name_off), v->offset);
			if (!symbol || !symbol->size)
				continue;
			if (symbol->size > UINT_MAX)
				return -E2BIG;
			if (v->size != symbol->size) {
				if (verbose)
					fprintf(stderr, "DATASEC %s: %s at %#x: storage size %u -> %llu\n",
						name, symbol->name, v->offset, v->size,
						(unsigned long long)symbol->size);
				v->size = symbol->size;
				resized++;
			}
		}
	}
	if (verbose)
		fprintf(stderr, "DATASEC: corrected %u variable storage sizes\n", resized);
	return 0;
}

static int validate_datasecs(struct btf *btf, Elf *elf)
{
	const struct btf *base = btf__base_btf(btf);
	__u32 start = base ? btf__type_cnt(base) : 1, i;
	GElf_Ehdr ehdr;

	if (!gelf_getehdr(elf, &ehdr))
		return -EINVAL;
	for (i = start; i < btf__type_cnt(btf); i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		const char *name, *previous = "<none>";
		__u64 end = 0;
		__u32 j;

		if (!btf_is_datasec(t))
			continue;
		name = btf__name_by_offset(btf, t->name_off);
		if (!find_section(elf, name) || (!t->size && ehdr.e_type == ET_REL))
			continue;
		if (!t->size) {
			fprintf(stderr, "DATASEC %s: section size is zero\n", name);
			return -EINVAL;
		}
		for (j = 0; j < btf_vlen(t); j++) {
			const struct btf_var_secinfo *v = btf_var_secinfos(t) + j;
			const struct btf_type *var = btf__type_by_id(btf, v->type);
			const char *variable;

			if (!var || !btf_is_var(var))
				return -EINVAL;
			variable = btf__name_by_offset(btf, var->name_off);
			if (!v->size || v->offset >= t->size || (__u64)v->offset + v->size > t->size) {
				fprintf(stderr, "DATASEC %s: %s at %#x size %u is outside section size %u or empty\n",
					name, variable, v->offset, v->size, t->size);
				return -EINVAL;
			}
			if (v->offset < end) {
				fprintf(stderr, "DATASEC %s: %s at %#x size %u overlaps %s ending at %#llx\n",
					name, variable, v->offset, v->size, previous,
					(unsigned long long)end);
				return -EINVAL;
			}
			end = (__u64)v->offset + v->size;
			previous = variable;
		}
	}
	return 0;
}

int btf_datasec_fixup(struct btf **btfp, Elf *elf, int verbose)
{
	struct variable_symbols symbols = {};
	struct btf *btf = *btfp;
	const struct btf *base = btf__base_btf(btf);
	__u32 start = base ? btf__type_cnt(base) : 1;
	__u32 i, n, *canonical = NULL, duplicates = 0;
	bool rebuild = false;
	int err;

	/* Compare referenced types only after their ordinary deduplication. */
	err = btf__dedup(btf, NULL);
	if (err)
		return err;
	err = collect_symbols(elf, &symbols);
	if (err)
		goto out;
	err = fix_storage_sizes(btf, elf, &symbols, verbose);
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
			__u32 first, second;
			int selected;

			if (a->info.offset == b->info.offset && a->info.size == b->info.size)
				rebuild = true;
			if (a->info.offset != b->info.offset || a->info.size != b->info.size ||
			    strcmp(a->name, b->name) ||
			    a->linkage != BTF_VAR_GLOBAL_ALLOCATED ||
			    b->linkage != BTF_VAR_GLOBAL_ALLOCATED)
				continue;
			symbol = find_symbol(&symbols, section, b->name, b->info.offset);
			if (!symbol || (symbol->binding != STB_GLOBAL && symbol->binding != STB_WEAK))
				continue;
			first = canonical_id(canonical, a->info.type);
			second = canonical_id(canonical, b->info.type);
			selected = select_definition(btf, first, second, symbol);
			if (selected < 0) {
				fprintf(stderr, "DATASEC %s: incompatible definitions of %s at %#x\n",
					btf__name_by_offset(btf, t->name_off), b->name, b->info.offset);
				free(v);
				err = -EINVAL;
				goto out;
			}
			canonical[first] = selected;
			canonical[second] = selected;
			duplicates++;
		}
		free(v);
	}
	if (rebuild) {
		for (i = start; i < n; i++)
			while (canonical[i] != canonical[canonical[i]])
				canonical[i] = canonical[canonical[i]];
		err = rebuild_btf(btfp, canonical, elf, &symbols, verbose);
	}
	if (!err)
		err = validate_datasecs(*btfp, elf);
	if (!err && verbose)
		fprintf(stderr, "DATASEC: merged %u duplicate global variable records\n", duplicates);
out:
	free(canonical);
	free(symbols.v);
	return err;
}
