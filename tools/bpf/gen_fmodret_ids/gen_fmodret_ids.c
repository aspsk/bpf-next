// SPDX-License-Identifier: GPL-2.0-only

#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <subcmd/parse-options.h>

static bool is_module = false;

#define FMODRET_SECTION ".fmodret_ids"
#define FMODRET_CANDIDATES_SECTION ".fmodret_candidates"

struct fmodret_symbol {
	char *name;
	bool required;
	size_t nr_functions;
	size_t nr_candidates;
	size_t nr_traceable;
};

struct fmodret_symbol_list {
	struct fmodret_symbol *symbols;
	size_t nr;
	size_t capacity;
};

struct fmodret_id_pair {
	uint32_t id;
	uint32_t flags;
};

struct elf_function {
	char *name;
	GElf_Addr value;
	GElf_Xword size;
	Elf64_Section shndx;
	size_t symtab_ndx;
	size_t sym_ndx;
	bool candidate;
	bool traceable;
};

struct elf_function_list {
	struct elf_function *functions;
	size_t nr;
	size_t capacity;
};

enum ftrace_site_kind {
	FTRACE_SITE_MCOUNT,
	FTRACE_SITE_PATCHABLE,
	FTRACE_SITE_UNKNOWN,
};

#define MAX_PATCHABLE_FUNCTION_ENTRY_SIZE 64

static int find_section(Elf *elf, size_t shstrndx, const char *wanted,
			Elf_Scn **result);

static void free_fmodret_symbols(struct fmodret_symbol_list *list)
{
	size_t i;

	for (i = 0; i < list->nr; i++)
		free(list->symbols[i].name);
	free(list->symbols);
}

static int append_fmodret_symbol(struct fmodret_symbol_list *list,
				 const char *name, bool required)
{
	struct fmodret_symbol *symbols;
	size_t capacity;
	char *copy;

	if (list->nr == list->capacity) {
		capacity = list->capacity ? 2 * list->capacity : 64;
		if (capacity < list->capacity ||
		    capacity > SIZE_MAX / sizeof(*symbols))
			return -E2BIG;
		symbols = realloc(list->symbols, capacity * sizeof(*symbols));
		if (!symbols)
			return -ENOMEM;
		list->symbols = symbols;
		list->capacity = capacity;
	}

	copy = strdup(name);
	if (!copy)
		return -ENOMEM;
	list->symbols[list->nr].name = copy;
	list->symbols[list->nr].required = required;
	list->symbols[list->nr].nr_functions = 0;
	list->symbols[list->nr].nr_candidates = 0;
	list->symbols[list->nr].nr_traceable = 0;
	list->nr++;
	return 0;
}

static int add_fmodret_symbol(struct fmodret_symbol_list *list,
			      const char *name, bool required)
{
	size_t i;

	for (i = 0; i < list->nr; i++) {
		if (strcmp(list->symbols[i].name, name))
			continue;
		list->symbols[i].required |= required;
		return 0;
	}
	return append_fmodret_symbol(list, name, required);
}

static int add_default_fmodret_symbols(struct fmodret_symbol_list *list)
{
	static const char * const default_list[] = {
		//"genl_family_rcv_msg_doit",
		//"genl_family_rcv_msg_dumpit",
	};
	size_t i;
	int err;

	if (is_module)
		return 0;

	for (i = 0; i < ARRAY_SIZE(default_list); i++) {
		err = add_fmodret_symbol(list, default_list[i], true);
		if (err)
			return err;
	}
	return 0;
}

static void free_elf_functions(struct elf_function_list *list)
{
	size_t i;

	for (i = 0; i < list->nr; i++)
		free(list->functions[i].name);
	free(list->functions);
}

static int add_elf_function(struct elf_function_list *list, const char *name,
			    const GElf_Sym *sym, size_t symtab_ndx,
			    size_t sym_ndx)
{
	struct elf_function *functions;
	size_t capacity;
	char *copy;

	if (list->nr == list->capacity) {
		capacity = list->capacity ? 2 * list->capacity : 1024;
		if (capacity < list->capacity ||
		    capacity > SIZE_MAX / sizeof(*functions))
			return -E2BIG;
		functions = realloc(list->functions,
				    capacity * sizeof(*functions));
		if (!functions)
			return -ENOMEM;
		list->functions = functions;
		list->capacity = capacity;
	}

	copy = strdup(name);
	if (!copy)
		return -ENOMEM;
	list->functions[list->nr] = (struct elf_function) {
		.name = copy,
		.value = sym->st_value,
		.size = sym->st_size,
		.shndx = sym->st_shndx,
		.symtab_ndx = symtab_ndx,
		.sym_ndx = sym_ndx,
	};
	list->nr++;
	return 0;
}

static int cmp_elf_function_location(const void *va, const void *vb)
{
	const struct elf_function *a = va;
	const struct elf_function *b = vb;

	if (a->shndx > b->shndx)
		return 1;
	if (a->shndx < b->shndx)
		return -1;
	if (a->value > b->value)
		return 1;
	if (a->value < b->value)
		return -1;
	return 0;
}

static bool function_contains(const struct elf_function *function,
			      GElf_Addr address)
{
	if (address < function->value)
		return false;
	if (!function->size)
		return address == function->value;
	return address - function->value < function->size;
}

/*
 * Mark the function containing an ftrace call site. Functions are sorted by
 * section and address. Mark all aliases at the same address: at run time BTF
 * attachment is name based and may resolve to any of them.
 */
static bool mark_traceable_function(struct elf_function_list *list,
				    Elf64_Section shndx,
				    GElf_Addr address,
				    enum ftrace_site_kind kind)
{
	size_t left = 0;
	size_t right = list->nr;
	size_t first;
	size_t i;
	bool found = false;

	/* Find the first function after ADDRESS in SHNDX. */
	while (left < right) {
		size_t middle = left + (right - left) / 2;
		struct elf_function *function = &list->functions[middle];

		if (function->shndx < shndx ||
		    (function->shndx == shndx && function->value <= address))
			left = middle + 1;
		else
			right = middle;
	}
	if (kind != FTRACE_SITE_MCOUNT &&
	    ((left && list->functions[left - 1].shndx == shndx &&
	      list->functions[left - 1].value == address) ||
	     (left < list->nr && list->functions[left].shndx == shndx &&
	      list->functions[left].value - address <=
					 MAX_PATCHABLE_FUNCTION_ENTRY_SIZE))) {
		first = left && list->functions[left - 1].shndx == shndx &&
			list->functions[left - 1].value == address ? left - 1 : left;
		while (first && list->functions[first - 1].shndx == shndx &&
		       list->functions[first - 1].value ==
						list->functions[first].value)
			first--;
		for (i = first; i < list->nr &&
		     list->functions[i].shndx == shndx &&
		     list->functions[i].value ==
					list->functions[first].value; i++) {
			list->functions[i].traceable = true;
			found = true;
		}
		return found;
	}
	if (kind == FTRACE_SITE_PATCHABLE || !left)
		return false;

	/* The nearest preceding function owns the call site. */
	first = left - 1;
	if (list->functions[first].shndx != shndx)
		return false;
	while (first && list->functions[first - 1].shndx == shndx &&
	       list->functions[first - 1].value == list->functions[first].value)
		first--;
	for (i = first; i < list->nr &&
	     list->functions[i].shndx == shndx &&
	     list->functions[i].value == list->functions[first].value; i++) {
		if (!function_contains(&list->functions[i], address))
			continue;
		list->functions[i].traceable = true;
		found = true;
	}
	return found;
}

static int find_symbol(Elf *elf, const char *wanted, GElf_Sym *result,
		       bool *found)
{
	Elf_Scn *scn = NULL;

	*found = false;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;
		Elf_Data *data;
		size_t nr_symbols;
		size_t i;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if (shdr.sh_type != SHT_SYMTAB)
			continue;
		if (!shdr.sh_entsize || shdr.sh_size % shdr.sh_entsize)
			return -EINVAL;
		data = elf_getdata(scn, NULL);
		if (!data || elf_getdata(scn, data))
			return -1;
		nr_symbols = shdr.sh_size / shdr.sh_entsize;
		for (i = 0; i < nr_symbols; i++) {
			const char *name;
			GElf_Sym sym;

			if (!gelf_getsym(data, i, &sym))
				return -1;
			if (sym.st_shndx == SHN_UNDEF || !sym.st_name)
				continue;
			name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (!name)
				return -1;
			if (strcmp(name, wanted))
				continue;
			*result = sym;
			*found = true;
			return 0;
		}
	}
	return 0;
}

static int section_for_address(Elf *elf, GElf_Addr address,
			       Elf64_Section *result)
{
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if (!(shdr.sh_flags & SHF_EXECINSTR) || address < shdr.sh_addr ||
		    address - shdr.sh_addr >= shdr.sh_size)
			continue;
		*result = elf_ndxscn(scn);
		return 0;
	}
	*result = SHN_UNDEF;
	return 0;
}

static bool relocation_offset(const GElf_Shdr *target, GElf_Addr offset,
			      size_t width, size_t *result)
{
	if (target->sh_size < width)
		return false;
	if (offset >= target->sh_addr &&
	    offset - target->sh_addr <= target->sh_size - width) {
		*result = offset - target->sh_addr;
		return true;
	}
	/* ET_REL relocation offsets are relative to their target section. */
	if (offset <= target->sh_size - width) {
		*result = offset;
		return true;
	}
	return false;
}

static int collect_elf_functions(Elf *elf, struct elf_function_list *list)
{
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;
		Elf_Data *data;
		size_t nr_symbols;
		size_t i;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if (shdr.sh_type != SHT_SYMTAB)
			continue;
		if (!shdr.sh_entsize || shdr.sh_size % shdr.sh_entsize)
			return -EINVAL;
		data = elf_getdata(scn, NULL);
		if (!data || elf_getdata(scn, data))
			return -1;

		nr_symbols = shdr.sh_size / shdr.sh_entsize;
		for (i = 0; i < nr_symbols; i++) {
			const char *name;
			GElf_Sym sym;
			int err;

			if (!gelf_getsym(data, i, &sym))
				return -1;
			if (GELF_ST_TYPE(sym.st_info) != STT_FUNC ||
			    sym.st_shndx == SHN_UNDEF || !sym.st_name)
				continue;
			name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (!name)
				return -1;
			err = add_elf_function(list, name, &sym,
					       elf_ndxscn(scn), i);
			if (err)
				return err;
		}
	}
	return 0;
}

static bool mark_candidate_symbol(struct elf_function_list *list,
				  size_t symtab_ndx, size_t sym_ndx)
{
	struct elf_function *target = NULL;
	size_t i;

	for (i = 0; i < list->nr; i++) {
		if (list->functions[i].symtab_ndx == symtab_ndx &&
		    list->functions[i].sym_ndx == sym_ndx) {
			target = &list->functions[i];
			break;
		}
	}
	if (!target)
		return false;

	/* Treat duplicate symbol-table entries for one function as one target. */
	for (i = 0; i < list->nr; i++)
		if (list->functions[i].symtab_ndx == target->symtab_ndx &&
		    list->functions[i].shndx == target->shndx &&
		    list->functions[i].value == target->value &&
		    !strcmp(list->functions[i].name, target->name))
			list->functions[i].candidate = true;
	return true;
}

static bool mark_candidate_section_offset(struct elf_function_list *list,
					  size_t symtab_ndx,
					  Elf64_Section shndx,
					  GElf_Addr value)
{
	bool found = false;
	size_t i;

	for (i = 0; i < list->nr; i++) {
		if (list->functions[i].symtab_ndx != symtab_ndx ||
		    list->functions[i].shndx != shndx ||
		    list->functions[i].value != value)
			continue;
		list->functions[i].candidate = true;
		found = true;
	}
	return found;
}

static int cmp_elf_function_value(const void *va, const void *vb)
{
	const struct elf_function *a = va;
	const struct elf_function *b = vb;

	if (a->value > b->value)
		return 1;
	if (a->value < b->value)
		return -1;
	return 0;
}

static bool mark_candidate_value(struct elf_function_list *list,
				 GElf_Addr value)
{
	size_t left = 0;
	size_t right = list->nr;
	size_t i;

	while (left < right) {
		size_t middle = left + (right - left) / 2;

		if (list->functions[middle].value < value)
			left = middle + 1;
		else
			right = middle;
	}
	if (left == list->nr || list->functions[left].value != value)
		return false;
	for (i = left; i < list->nr && list->functions[i].value == value; i++)
		list->functions[i].candidate = true;
	return true;
}

static uint64_t read_elf_value(const unsigned char *p, size_t size,
			       unsigned int encoding)
{
	uint64_t value = 0;
	size_t i;

	if (encoding == ELFDATA2LSB) {
		for (i = 0; i < size; i++)
			value |= (uint64_t)p[i] << (8 * i);
	} else {
		for (i = 0; i < size; i++)
			value = (value << 8) | p[i];
	}
	return value;
}

static int copy_section_data(Elf_Scn *scn, const GElf_Shdr *shdr,
			     unsigned char **result)
{
	Elf_Data *data = NULL;
	unsigned char *buf;

	buf = calloc(1, shdr->sh_size);
	if (!buf)
		return -ENOMEM;
	while ((data = elf_getdata(scn, data))) {
		if (data->d_off > shdr->sh_size ||
		    data->d_size > shdr->sh_size - data->d_off) {
			free(buf);
			return -EINVAL;
		}
		memcpy(buf + data->d_off, data->d_buf, data->d_size);
	}
	*result = buf;
	return 0;
}

static int mark_relocated_ftrace_sites(Elf *elf, size_t target_ndx,
				       const unsigned char *target_data,
				       const GElf_Shdr *target_shdr,
				       size_t begin, size_t end,
				       size_t ptr_size, unsigned int encoding,
				       struct elf_function_list *functions,
				       enum ftrace_site_kind kind,
				       bool *relocated)
{
	Elf_Scn *scn = NULL;

	*relocated = false;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;
		Elf_Data *data;
		size_t nr_relocations;
		size_t i;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if ((shdr.sh_type != SHT_RELA && shdr.sh_type != SHT_REL) ||
		    (shdr.sh_info && shdr.sh_info != target_ndx))
			continue;
		if (!shdr.sh_entsize || shdr.sh_size % shdr.sh_entsize)
			return -EINVAL;
		data = elf_getdata(scn, NULL);
		if (!data || elf_getdata(scn, data))
			return -1;

		nr_relocations = shdr.sh_size / shdr.sh_entsize;
		for (i = 0; i < nr_relocations; i++) {
			Elf_Scn *symtab_scn;
			Elf_Data *symtab_data;
			GElf_Shdr symtab_shdr;
			GElf_Sxword addend;
			GElf_Addr raw_offset;
			GElf_Addr address;
			GElf_Sym sym;
			size_t sym_ndx;
			size_t offset;

			if (shdr.sh_type == SHT_RELA) {
				GElf_Rela rela;

				if (!gelf_getrela(data, i, &rela))
					return -1;
				sym_ndx = GELF_R_SYM(rela.r_info);
				raw_offset = rela.r_offset;
				addend = rela.r_addend;
			} else {
				GElf_Rel rel;

				if (!gelf_getrel(data, i, &rel))
					return -1;
				sym_ndx = GELF_R_SYM(rel.r_info);
				raw_offset = rel.r_offset;
				if (!relocation_offset(target_shdr, raw_offset,
						       ptr_size, &offset))
					continue;
				addend = read_elf_value(target_data + offset,
							ptr_size, encoding);
			}
			if (!relocation_offset(target_shdr, raw_offset, ptr_size,
					       &offset))
				continue;
			if (offset < begin || offset >= end)
				continue;
			*relocated = true;

			/*
			 * PIE vmlinux uses symbol-less RELATIVE relocations. Its
			 * addend is the link-time call-site address, represented as
			 * a signed ELF addend.
			 */
			if (!sym_ndx) {
				Elf64_Section target_shndx;

				address = (GElf_Addr)addend;
				if (section_for_address(elf, address,
							&target_shndx))
					return -1;
				if (target_shndx != SHN_UNDEF)
					mark_traceable_function(functions,
								target_shndx,
								address, kind);
				continue;
			}

			symtab_scn = elf_getscn(elf, shdr.sh_link);
			if (!symtab_scn ||
			    !gelf_getshdr(symtab_scn, &symtab_shdr))
				return -1;
			symtab_data = elf_getdata(symtab_scn, NULL);
			if (!symtab_data || elf_getdata(symtab_scn, symtab_data) ||
			    !gelf_getsym(symtab_data, sym_ndx, &sym))
				return -1;
			if (sym.st_shndx == SHN_UNDEF)
				continue;
			if (sym.st_shndx >= SHN_LORESERVE)
				continue;
			if (addend < 0) {
				GElf_Addr delta = -(addend + 1);

				delta++;
				if (delta > sym.st_value)
					continue;
				address = sym.st_value - delta;
			} else {
				if ((GElf_Addr)addend > UINT64_MAX - sym.st_value)
					continue;
				address = sym.st_value + addend;
			}
			mark_traceable_function(functions, sym.st_shndx, address,
						kind);
		}
	}
	return 0;
}

static int read_ftrace_site_range(Elf *elf, Elf_Scn *scn, size_t begin,
				  size_t end, size_t ptr_size,
				  unsigned int encoding,
				  struct elf_function_list *functions,
				  enum ftrace_site_kind kind)
{
	unsigned char *buf = NULL;
	GElf_Shdr shdr;
	bool relocated;
	size_t offset;
	int err;

	if (!gelf_getshdr(scn, &shdr))
		return -1;
	if (begin > end || end > shdr.sh_size ||
	    (end - begin) % ptr_size)
		return -EINVAL;
	if (begin == end)
		return 0;
	err = copy_section_data(scn, &shdr, &buf);
	if (err)
		return err;
	err = mark_relocated_ftrace_sites(elf, elf_ndxscn(scn), buf, &shdr,
					  begin, end, ptr_size, encoding,
					  functions, kind, &relocated);
	if (err || relocated)
		goto out;

	for (offset = begin; offset < end; offset += ptr_size) {
		GElf_Addr address;
		Elf64_Section shndx;

		address = read_elf_value(buf + offset, ptr_size, encoding);
		err = section_for_address(elf, address, &shndx);
		if (err)
			goto out;
		if (shndx != SHN_UNDEF)
			mark_traceable_function(functions, shndx, address, kind);
	}
out:
	free(buf);
	return err;
}

static bool section_prefix(const char *name, const char *prefix)
{
	size_t len = strlen(prefix);

	return !strncmp(name, prefix, len) &&
	       (!name[len] || name[len] == '.');
}

static bool section_cannot_be_attached(const char *name)
{
	return section_prefix(name, ".init.text") ||
	       section_prefix(name, ".exit.text") ||
	       section_prefix(name, ".noinstr.text") ||
	       section_prefix(name, ".meminit.text") ||
	       section_prefix(name, ".memexit.text") ||
	       section_prefix(name, ".cpuinit.text") ||
	       section_prefix(name, ".cpuexit.text") ||
	       section_prefix(name, ".devinit.text") ||
	       section_prefix(name, ".devexit.text");
}

static int remove_unattachable_functions(Elf *elf,
					 struct elf_function_list *functions,
					 size_t shstrndx)
{
	GElf_Sym noinstr_start;
	GElf_Sym noinstr_end;
	bool found_start;
	bool found_end;
	size_t i;
	int err;

	err = find_symbol(elf, "__noinstr_text_start", &noinstr_start,
			  &found_start);
	if (err)
		return err;
	err = find_symbol(elf, "__noinstr_text_end", &noinstr_end, &found_end);
	if (err)
		return err;

	for (i = 0; i < functions->nr; i++) {
		struct elf_function *function = &functions->functions[i];
		Elf_Scn *scn;
		GElf_Shdr shdr;
		const char *name;

		if (!function->traceable)
			continue;
		scn = elf_getscn(elf, function->shndx);
		if (!scn || !gelf_getshdr(scn, &shdr))
			return -1;
		name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!name)
			return -1;
		if (section_cannot_be_attached(name) ||
		    (found_start && found_end &&
		     function->shndx == noinstr_start.st_shndx &&
		     noinstr_start.st_shndx == noinstr_end.st_shndx &&
		     function->value >= noinstr_start.st_value &&
		     function->value < noinstr_end.st_value))
			function->traceable = false;
	}
	return 0;
}

static int read_ftrace_symbol_range(Elf *elf, const GElf_Sym *start,
				    const GElf_Sym *stop, size_t ptr_size,
				    unsigned int encoding,
				    struct elf_function_list *functions,
				    enum ftrace_site_kind kind)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	size_t begin;
	size_t end;

	if (start->st_shndx != stop->st_shndx)
		return -EINVAL;
	scn = elf_getscn(elf, start->st_shndx);
	if (!scn || !gelf_getshdr(scn, &shdr))
		return -1;
	if (start->st_value < shdr.sh_addr || stop->st_value < start->st_value ||
	    stop->st_value - shdr.sh_addr > shdr.sh_size)
		return -EINVAL;
	begin = start->st_value - shdr.sh_addr;
	end = stop->st_value - shdr.sh_addr;
	return read_ftrace_site_range(elf, scn, begin, end, ptr_size, encoding,
				       functions, kind);
}

static int read_ftrace_sites(Elf *elf, size_t shstrndx,
			     size_t ptr_size, unsigned int encoding,
			     struct elf_function_list *functions)
{
	static const char * const sections[] = {
		"__mcount_loc",
		"__patchable_function_entries",
	};
	GElf_Sym start;
	GElf_Sym stop;
	GElf_Sym patchable_start;
	GElf_Sym patchable_stop;
	bool found_start;
	bool found_stop;
	bool found_patchable_start;
	bool found_patchable_stop;
	size_t i;
	int err;

	qsort(functions->functions, functions->nr, sizeof(*functions->functions),
	      cmp_elf_function_location);

	for (i = 0; i < ARRAY_SIZE(sections); i++) {
		Elf_Scn *scn = NULL;
		GElf_Shdr shdr;

		err = find_section(elf, shstrndx, sections[i], &scn);
		if (err)
			return err;
		if (!scn)
			continue;
		if (!gelf_getshdr(scn, &shdr))
			return -1;
		err = read_ftrace_site_range(elf, scn, 0, shdr.sh_size,
					     ptr_size, encoding, functions,
					     i ? FTRACE_SITE_PATCHABLE :
						 FTRACE_SITE_MCOUNT);
		if (err)
			return err;
	}

	err = find_symbol(elf, "__start_mcount_loc", &start, &found_start);
	if (err)
		return err;
	err = find_symbol(elf, "__stop_mcount_loc", &stop, &found_stop);
	if (err)
		return err;
	err = find_symbol(elf, "__start_patchable_function_entries",
			  &patchable_start, &found_patchable_start);
	if (err)
		return err;
	err = find_symbol(elf, "__stop_patchable_function_entries",
			  &patchable_stop, &found_patchable_stop);
	if (err)
		return err;
	if (found_start && found_stop) {
		if (found_patchable_start && found_patchable_stop) {
			err = read_ftrace_symbol_range(elf, &start,
						       &patchable_start,
						       ptr_size, encoding,
						       functions,
						       FTRACE_SITE_MCOUNT);
			if (err)
				return err;
			err = read_ftrace_symbol_range(elf, &patchable_start,
						       &patchable_stop,
						       ptr_size, encoding,
						       functions,
						       FTRACE_SITE_PATCHABLE);
		} else {
			/* Support images linked before the split range markers. */
			err = read_ftrace_symbol_range(elf, &start, &stop,
						       ptr_size, encoding,
						       functions,
						       FTRACE_SITE_UNKNOWN);
		}
		if (err)
			return err;
	}

	return remove_unattachable_functions(elf, functions, shstrndx);
}

static int mark_relocated_candidates(Elf *elf, size_t candidate_ndx,
				     const unsigned char *candidate_data,
				     const GElf_Shdr *candidate_shdr,
				     size_t ptr_size, unsigned int encoding,
				     struct elf_function_list *functions,
				     bool *found)
{
	Elf_Scn *scn = NULL;

	*found = false;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;
		Elf_Data *data;
		size_t nr_relocations;
		size_t i;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if ((shdr.sh_type != SHT_RELA && shdr.sh_type != SHT_REL) ||
		    shdr.sh_info != candidate_ndx)
			continue;
		if (!shdr.sh_entsize || shdr.sh_size % shdr.sh_entsize)
			return -EINVAL;
		data = elf_getdata(scn, NULL);
		if (!data || elf_getdata(scn, data))
			return -1;

		nr_relocations = shdr.sh_size / shdr.sh_entsize;
		for (i = 0; i < nr_relocations; i++) {
			Elf_Scn *symtab_scn;
			Elf_Data *symtab_data;
			GElf_Shdr symtab_shdr;
			GElf_Sxword addend;
			GElf_Addr offset;
			GElf_Sym sym;
			size_t sym_ndx;
			bool marked;

			if (shdr.sh_type == SHT_RELA) {
				GElf_Rela rela;

				if (!gelf_getrela(data, i, &rela))
					return -1;
				sym_ndx = GELF_R_SYM(rela.r_info);
				offset = rela.r_offset;
				addend = rela.r_addend;
			} else {
				GElf_Rel rel;

				if (!gelf_getrel(data, i, &rel))
					return -1;
				sym_ndx = GELF_R_SYM(rel.r_info);
				offset = rel.r_offset;
				if (offset < candidate_shdr->sh_addr ||
				    offset - candidate_shdr->sh_addr >
				    candidate_shdr->sh_size - ptr_size)
					return -EINVAL;
				addend = read_elf_value(candidate_data + offset -
							candidate_shdr->sh_addr,
							ptr_size, encoding);
			}

			symtab_scn = elf_getscn(elf, shdr.sh_link);
			if (!symtab_scn || !gelf_getshdr(symtab_scn, &symtab_shdr))
				return -1;
			symtab_data = elf_getdata(symtab_scn, NULL);
			if (!symtab_data || elf_getdata(symtab_scn, symtab_data) ||
			    !gelf_getsym(symtab_data, sym_ndx, &sym))
				return -1;

			marked = mark_candidate_symbol(functions, shdr.sh_link,
						       sym_ndx);
			if (!marked && sym.st_shndx != SHN_UNDEF)
				marked = mark_candidate_section_offset(functions,
							       shdr.sh_link,
							       sym.st_shndx,
							       sym.st_value + addend);
			if (!marked) {
				fprintf(stderr,
					"candidate relocation does not refer to an ELF function\n");
				return -ENOENT;
			}
			*found = true;
		}
	}
	return 0;
}

static int cmp_elf_function_name(const void *va, const void *vb)
{
	const struct elf_function *a = va;
	const struct elf_function *b = vb;

	return strcmp(a->name, b->name);
}

static int summarize_elf_functions(struct elf_function_list *functions,
				   struct fmodret_symbol_list *symbols)
{
	size_t nr_existing = symbols->nr;
	size_t i = 0;

	qsort(functions->functions, functions->nr, sizeof(*functions->functions),
	      cmp_elf_function_name);
	while (i < functions->nr) {
		struct fmodret_symbol *symbol = NULL;
		size_t nr_candidates = 0;
		size_t nr_traceable = 0;
		size_t j;
		size_t k;
		int err;

		for (j = i; j < functions->nr &&
		     !strcmp(functions->functions[i].name,
			     functions->functions[j].name); j++) {
			nr_candidates += functions->functions[j].candidate;
			nr_traceable += functions->functions[j].traceable;
		}

		for (k = 0; k < nr_existing; k++)
			if (!strcmp(symbols->symbols[k].name,
				    functions->functions[i].name)) {
				symbol = &symbols->symbols[k];
				break;
			}
		if (!symbol && !nr_candidates) {
			i = j;
			continue;
		}
		if (!symbol) {
			err = append_fmodret_symbol(symbols,
						    functions->functions[i].name,
						    false);
			if (err)
				return err;
			symbol = &symbols->symbols[symbols->nr - 1];
		}
		symbol->nr_functions = j - i;
		symbol->nr_candidates = nr_candidates;
		symbol->nr_traceable = nr_traceable;
		i = j;
	}
	return 0;
}

static int read_fmodret_candidates(const char *path,
				   struct fmodret_symbol_list *list)
{
	struct elf_function_list functions = {};
	Elf_Scn *candidate_scn = NULL;
	unsigned char *buf = NULL;
	unsigned char *ident;
	GElf_Shdr shdr;
	size_t shstrndx;
	size_t ptr_size;
	size_t offset;
	bool relocated;
	Elf *elf;
	int fd;
	int err = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
		return -1;
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		fprintf(stderr, "failed to read %s: %s\n", path, elf_errmsg(-1));
		close(fd);
		return -1;
	}

	err = collect_elf_functions(elf, &functions);
	if (err)
		goto out;
	if (elf_getshdrstrndx(elf, &shstrndx)) {
		err = -1;
		goto out;
	}
	ptr_size = gelf_getclass(elf) == ELFCLASS64 ? 8 : 4;
	ident = (unsigned char *)elf_getident(elf, NULL);
	if (!ident) {
		err = -1;
		goto out;
	}
	if (find_section(elf, shstrndx, FMODRET_CANDIDATES_SECTION,
			 &candidate_scn)) {
		err = -1;
		goto out;
	}
	if (!candidate_scn)
		goto attachability;
	if (!gelf_getshdr(candidate_scn, &shdr)) {
		err = -1;
		goto out;
	}

	if (shdr.sh_size % ptr_size) {
		fprintf(stderr, "%s has invalid size %llu\n",
			FMODRET_CANDIDATES_SECTION,
			(unsigned long long)shdr.sh_size);
		err = -EINVAL;
		goto out;
	}
	if (shdr.sh_size) {
		err = copy_section_data(candidate_scn, &shdr, &buf);
		if (err)
			goto out;
	}
	err = mark_relocated_candidates(elf, elf_ndxscn(candidate_scn),
					 buf, &shdr, ptr_size, ident[EI_DATA],
					 &functions, &relocated);
	if (err)
		goto out;
	if (!relocated && shdr.sh_size) {
		qsort(functions.functions, functions.nr,
		      sizeof(*functions.functions), cmp_elf_function_value);
		for (offset = 0; offset < shdr.sh_size; offset += ptr_size) {
			GElf_Addr value;

			value = read_elf_value(buf + offset, ptr_size,
					       ident[EI_DATA]);
			if (!mark_candidate_value(&functions, value)) {
				fprintf(stderr,
					"no ELF function at candidate address %#llx\n",
					(unsigned long long)value);
				err = -ENOENT;
				goto out;
			}
		}
	}

attachability:
	err = read_ftrace_sites(elf, shstrndx, ptr_size, ident[EI_DATA],
				&functions);
	if (err)
		goto out;
	err = summarize_elf_functions(&functions, list);
out:
	if (err == -1)
		fprintf(stderr, "failed to read %s from %s: %s\n",
			FMODRET_CANDIDATES_SECTION, path, elf_errmsg(-1));
	free(buf);
	free_elf_functions(&functions);
	elf_end(elf);
	close(fd);
	return err;
}

static int cmp_fmodret_ids(const void *va, const void *vb)
{
	const struct fmodret_id_pair *a = va;
	const struct fmodret_id_pair *b = vb;

	if (a->id > b->id)
		return 1;
	if (a->id < b->id)
		return -1;
	return 0;
}

static int find_fmodret_ids(const char *elf_file,
			    const char *btf_file,
			    const char *btf_base_file,
			    struct fmodret_id_pair **pairs, size_t *nr_pairs)
{
	struct btf *base_btf = NULL;
	struct btf *btf;
	struct fmodret_id_pair *result;
	struct fmodret_symbol_list list = {};
	size_t nr_result = 0;
	size_t i;
	int err;

	*pairs = NULL;
	*nr_pairs = 0;
	err = add_default_fmodret_symbols(&list);
	if (err)
		goto out_symbols;
	err = read_fmodret_candidates(elf_file, &list);
	if (err)
		goto out_symbols;

	if (btf_base_file) {
		base_btf = btf__parse(btf_base_file, NULL);
		if (libbpf_get_error(base_btf)) {
			fprintf(stderr, "failed to load base BTF from %s\n",
				btf_base_file);
			err = -1;
			base_btf = NULL;
			goto out_symbols;
		}
	}

	btf = btf__parse_split(btf_file, base_btf);
	if (libbpf_get_error(btf)) {
		fprintf(stderr, "failed to load BTF from %s\n", btf_file);
		err = -1;
		btf = NULL;
		goto out_btf;
	}

	result = calloc(list.nr, sizeof(*result));
	if (list.nr && !result) {
		err = -ENOMEM;
		goto out_btf;
	}

	for (i = 0; i < list.nr; i++) {
		int id;

		/*
		 * BTF lookup is name-based and cannot select one of several local
		 * ELF functions with the same name. Only admit the name when every
		 * such ELF function is mechanically attachable and (unless it is on
		 * the explicit list) independently marked as a candidate.
		 */
		if (!list.symbols[i].nr_functions ||
		    list.symbols[i].nr_traceable !=
					list.symbols[i].nr_functions ||
		    (!list.symbols[i].required &&
		     list.symbols[i].nr_candidates !=
					list.symbols[i].nr_functions))
			continue;
		id = btf__find_by_name_kind_own(btf, list.symbols[i].name,
						BTF_KIND_FUNC);
		if (id <= 0 && !list.symbols[i].required)
			continue;
		if (id < 0) {
			fprintf(stderr, "failed to find %s in BTF\n",
				list.symbols[i].name);
			err = id;
			goto out_result;
		}
		if (!id) {
			fprintf(stderr, "%s is not present in BTF\n",
				list.symbols[i].name);
			err = -ENOENT;
			goto out_result;
		}

		result[nr_result++].id = id;
	}

	if (nr_result)
		qsort(result, nr_result, sizeof(*result), cmp_fmodret_ids);

	btf__free(btf);
	btf__free(base_btf);
	free_fmodret_symbols(&list);
	*pairs = result;
	*nr_pairs = nr_result;
	return 0;

out_result:
	free(result);
out_btf:
	btf__free(btf);
	btf__free(base_btf);
out_symbols:
	free_fmodret_symbols(&list);
	return err;
}

static int get_elf_header(const char *path, GElf_Ehdr *ehdr)
{
	Elf *elf;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
		return -1;
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		fprintf(stderr, "failed to read ELF header from %s: %s\n", path,
			elf_errmsg(-1));
		close(fd);
		return -1;
	}

	if (!gelf_getehdr(elf, ehdr)) {
		fprintf(stderr, "failed to get ELF header from %s: %s\n", path,
			elf_errmsg(-1));
		elf_end(elf);
		close(fd);
		return -1;
	}

	elf_end(elf);
	close(fd);
	return 0;
}

static int build_set_data(const struct fmodret_id_pair *pairs,
			  size_t nr_pairs, uint32_t **data, size_t *nr_words)
{
	uint32_t *words;
	size_t i;

	if (nr_pairs > (SIZE_MAX / sizeof(*words) - 2) / 2 ||
		nr_pairs > UINT32_MAX)
		return -E2BIG;

	*nr_words = 2 + 2 * nr_pairs;
	words = calloc(*nr_words, sizeof(*words));
	if (!words)
		return -ENOMEM;

	words[0] = nr_pairs;
	for (i = 0; i < nr_pairs; i++) {
		words[2 + 2 * i] = pairs[i].id;
		words[3 + 2 * i] = pairs[i].flags;
	}

	*data = words;
	return 0;
}

static int set_section_data(Elf_Scn *scn, uint32_t *data, size_t nr_words,
			    bool new_section)
{
	GElf_Shdr shdr;
	Elf_Data *elf_data;

	if (new_section)
		elf_data = elf_newdata(scn);
	else
		elf_data = elf_getdata(scn, NULL);
	if (!elf_data) {
		fprintf(stderr, "failed to get %s section data: %s\n",
			FMODRET_SECTION, elf_errmsg(-1));
		return -1;
	}

	if (!new_section && elf_getdata(scn, elf_data)) {
		fprintf(stderr, "%s contains multiple data descriptors\n",
			FMODRET_SECTION);
		return -1;
	}

	elf_data->d_buf = data;
	elf_data->d_size = nr_words * sizeof(*data);
	elf_data->d_type = ELF_T_WORD;
	elf_data->d_version = EV_CURRENT;
	elf_data->d_align = 8;
	elf_flagdata(elf_data, ELF_C_SET, ELF_F_DIRTY);

	if (!gelf_getshdr(scn, &shdr)) {
		fprintf(stderr, "failed to get %s section header: %s\n",
			FMODRET_SECTION, elf_errmsg(-1));
		return -1;
	}

	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_flags = SHF_ALLOC;
	shdr.sh_size = elf_data->d_size;
	shdr.sh_addralign = 8;
	if (!gelf_update_shdr(scn, &shdr)) {
		fprintf(stderr, "failed to update %s section header: %s\n",
			FMODRET_SECTION, elf_errmsg(-1));
		return -1;
	}

	return 0;
}

static int find_section(Elf *elf, size_t shstrndx, const char *wanted,
			Elf_Scn **result)
{
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr;
		const char *name;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!name)
			return -1;
		if (!strcmp(name, wanted)) {
			*result = scn;
			return 0;
		}
	}

	*result = NULL;
	return 0;
}

static int append_section_name(Elf *elf, size_t shstrndx, size_t *name_offset)
{
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Shdr shdr;
	char *name;

	scn = elf_getscn(elf, shstrndx);
	if (!scn || !gelf_getshdr(scn, &shdr))
		return -1;

	data = elf_getdata(scn, NULL);
	if (!data)
		return -1;

	name = strdup(FMODRET_SECTION);
	if (!name)
		return -ENOMEM;

	data = elf_newdata(scn);
	if (!data) {
		free(name);
		return -1;
	}

	*name_offset = shdr.sh_size;
	data->d_buf = name;
	data->d_size = strlen(FMODRET_SECTION) + 1;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	data->d_align = 1;
	elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);

	shdr.sh_size += data->d_size;
	if (!gelf_update_shdr(scn, &shdr)) {
		free(name);
		return -1;
	}

	return 0;
}

static int create_output_elf(const char *path, const GElf_Ehdr *source,
			    uint32_t *data, size_t nr_words)
{
	static const char shstrtab[] = "\0.fmodret_ids\0.shstrtab\0";
	const size_t fmodret_name_offset = 1;
	const size_t shstrtab_name_offset = 1 + sizeof(FMODRET_SECTION);
	GElf_Ehdr ehdr;
	Elf_Data *elf_data;
	Elf_Scn *scn;
	Elf *elf;
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		fprintf(stderr, "failed to create %s: %s\n", path, strerror(errno));
		return -1;
	}

	elf = elf_begin(fd, ELF_C_WRITE, NULL);
	if (!elf) {
		fprintf(stderr, "failed to create ELF descriptor: %s\n",
			elf_errmsg(-1));
		close(fd);
		return -1;
	}

	if (!gelf_newehdr(elf, source->e_ident[EI_CLASS])) {
		fprintf(stderr, "failed to create ELF header: %s\n", elf_errmsg(-1));
		goto out;
	}
	if (!gelf_getehdr(elf, &ehdr))
		goto out;

	ehdr.e_ident[EI_DATA] = source->e_ident[EI_DATA];
	ehdr.e_ident[EI_OSABI] = source->e_ident[EI_OSABI];
	ehdr.e_ident[EI_ABIVERSION] = source->e_ident[EI_ABIVERSION];
	ehdr.e_type = ET_REL;
	ehdr.e_machine = source->e_machine;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_flags = source->e_flags;
	if (!gelf_update_ehdr(elf, &ehdr))
		goto out;

	scn = elf_newscn(elf);
	if (!scn)
		goto out;
	elf_data = elf_newdata(scn);
	if (!elf_data)
		goto out;
	elf_data->d_buf = (void *)shstrtab;
	elf_data->d_size = sizeof(shstrtab);
	elf_data->d_type = ELF_T_BYTE;
	elf_data->d_version = EV_CURRENT;
	elf_data->d_align = 1;
	{
		GElf_Shdr shdr;

		if (!gelf_getshdr(scn, &shdr))
			goto out;
		shdr.sh_type = SHT_STRTAB;
		shdr.sh_name = shstrtab_name_offset;
		shdr.sh_size = elf_data->d_size;
		shdr.sh_addralign = 1;
		if (!gelf_update_shdr(scn, &shdr))
			goto out;
	}

	ehdr.e_shstrndx = elf_ndxscn(scn);
	if (!gelf_update_ehdr(elf, &ehdr))
		goto out;

	scn = elf_newscn(elf);
	if (!scn)
		goto out;
	if (set_section_data(scn, data, nr_words, true))
		goto out;
	{
		GElf_Shdr shdr;

		if (!gelf_getshdr(scn, &shdr))
			goto out;
		shdr.sh_name = fmodret_name_offset;
		if (!gelf_update_shdr(scn, &shdr))
			goto out;
	}

	if (elf_update(elf, ELF_C_WRITE) < 0)
		goto out;

	elf_end(elf);
	close(fd);
	return 0;
out:
	fprintf(stderr, "failed to write %s: %s\n", path, elf_errmsg(-1));
	elf_end(elf);
	close(fd);
	return -1;
}

static int update_elf_in_place(const char *path, uint32_t *data, size_t nr_words)
{
	Elf_Scn *scn = NULL;
	Elf *elf;
	size_t shstrndx;
	int fd;
	int err = -1;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
		return -1;
	}

	elf = elf_begin(fd, ELF_C_RDWR, NULL);
	if (!elf) {
		fprintf(stderr, "failed to create ELF descriptor: %s\n",
			elf_errmsg(-1));
		close(fd);
		return -1;
	}

	if (elf_getshdrstrndx(elf, &shstrndx))
		goto out;
	if (find_section(elf, shstrndx, FMODRET_SECTION, &scn))
		goto out;

	if (!scn) {
		size_t name_offset;

		if (append_section_name(elf, shstrndx, &name_offset))
			goto out;
		scn = elf_newscn(elf);
		if (!scn)
			goto out;
		if (set_section_data(scn, data, nr_words, true))
			goto out;
		{
			GElf_Shdr shdr;

			if (!gelf_getshdr(scn, &shdr))
				goto out;
			shdr.sh_name = name_offset;
			if (!gelf_update_shdr(scn, &shdr))
				goto out;
		}
	} else if (set_section_data(scn, data, nr_words, false)) {
		goto out;
	}

	elf_flagelf(elf, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(elf, ELF_C_WRITE) < 0)
		goto out;
	err = 0;
out:
	if (err)
		fprintf(stderr, "failed to update %s: %s\n", path, elf_errmsg(-1));
	elf_end(elf);
	close(fd);
	return err;
}

static const char *const gen_fmodret_ids_usage[] = {
	"gen_fmodret_ids [<options>] <target ELF> <BTF ELF> [output ELF]",
	NULL,
};

int main(int argc, const char **argv)
{
	const char *btf_base_file_name = NULL;
	const char *elf_file;
	const char *btf_file;
	const char *output_file = NULL;


	struct fmodret_id_pair *pairs;
	GElf_Ehdr ehdr;
	size_t nr_pairs, nr_words;
	uint32_t *data;

	int err;
	struct option options[] = {
		OPT_STRING(0, "btf_base", &btf_base_file_name, "file",
			   "path of file providing base BTF"),
		OPT_END(),
	};

	argc = parse_options(argc, argv, options, gen_fmodret_ids_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);

	if (argc != 2 && argc != 3)
		usage_with_options(gen_fmodret_ids_usage, options);

	elf_file = argv[0];
	btf_file = argv[1];
	if (argc == 3)
		output_file = argv[2];
	else
		is_module = true;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "libelf initialization failed\n");
		return EXIT_FAILURE;
	}

	if (get_elf_header(elf_file, &ehdr))
		return EXIT_FAILURE;

	err = find_fmodret_ids(elf_file, btf_file, btf_base_file_name, &pairs, &nr_pairs);
	if (err)
		return EXIT_FAILURE;

	err = build_set_data(pairs, nr_pairs, &data, &nr_words);
	free(pairs);
	if (err)
		return EXIT_FAILURE;

	/* If the output_file is given, we consider this vmlinux */
	if (output_file)
		err = create_output_elf(output_file, &ehdr, data, nr_words);
	else
		err = update_elf_in_place(elf_file, data, nr_words);

	free(data);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
