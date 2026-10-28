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
#include "fmodret.h"
#include "../../../scripts/llvm-plugins/fmodret_metadata.h"
#include <linux/btf_ids.h>
#include <linux/kernel.h>

#define FMODRET_CANDIDATES_SECTION ".BTF_fmodret_candidates"


struct fmodret_symbol {
	char *name;
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
	size_t node;
	bool candidate;
	bool traceable;
	const char *attach_rejection;
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
				 const char *name)
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
	list->symbols[list->nr].nr_functions = 0;
	list->symbols[list->nr].nr_candidates = 0;
	list->symbols[list->nr].nr_traceable = 0;
	list->nr++;
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
		.attach_rejection = "no-ftrace-site",
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
			list->functions[i].attach_rejection = NULL;
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
		list->functions[i].attach_rejection = NULL;
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
		if (section_cannot_be_attached(name)) {
			function->traceable = false;
			function->attach_rejection = "excluded-text-section";
		} else if (found_start && found_end &&
			   function->shndx == noinstr_start.st_shndx &&
			   noinstr_start.st_shndx == noinstr_end.st_shndx &&
			   function->value >= noinstr_start.st_value &&
			   function->value < noinstr_end.st_value) {
			function->traceable = false;
			function->attach_rejection = "noinstr-address-range";
		}
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

/* A node identifies a linked function body, never a source-level name. */
#define ERROR_WORDS ((FMODRET_META_ERRNOS + 63) / 64)
#define NO_NODE SIZE_MAX

struct error_case {
	int first, last;
	unsigned int kind;
	int replacement;
};

struct callback_binding {
	size_t function;
	unsigned int argument, source_param;
};

struct callback_parameters {
	unsigned int nr;
	unsigned int *flags;
};

struct error_call {
	size_t caller, callee;
	size_t next_in, next_out, metadata_offset;
	unsigned int flags, nr_cases, ordinal;
	unsigned int callee_param, nr_bindings;
	bool weak_definition, resolved_callback;
	struct error_case *cases;
	struct callback_binding *bindings;
};

struct error_node {
	const char *name;
	GElf_Addr value;
	Elf64_Section shndx;
	unsigned int flags, definitions;
	unsigned int strong_flags, weak_flags;
	unsigned int strong_definitions, weak_definitions;
	size_t incoming, outgoing, clean_via;
	size_t nr_unmodelled_refs, reference_caller;
	const char *reference_section, *reference_reason;
	GElf_Addr reference_site;
	bool clean, terminal, incomplete, queued, callback_unresolved;
	struct callback_parameters strong_params, weak_params;
	const struct callback_parameters *params;
	uint64_t good[ERROR_WORDS];
};

struct error_graph {
	struct error_node *nodes;
	struct error_call *calls;
	size_t nr_nodes, nr_calls, capacity;
	size_t nr_records, nr_defined_records, nr_reference_records;
	size_t nr_overridden_weak, nr_discarded_calls;
	size_t nr_input_calls, nr_callback_bindings, nr_resolved_bindings, nr_callback_edges;
	bool audited_text;
};

static void free_error_graph(struct error_graph *g)
{
	size_t i;

	for (i = 0; i < g->nr_calls; i++) {
		free(g->calls[i].cases);
		free(g->calls[i].bindings);
	}
	for (i = 0; i < g->nr_nodes; i++) {
		free(g->nodes[i].strong_params.flags);
		free(g->nodes[i].weak_params.flags);
	}
	free(g->calls);
	free(g->nodes);
}

/* FUNCTIONS stay location-sorted until the graph analysis has finished. */
static size_t graph_function(const struct elf_function_list *functions,
			     Elf64_Section shndx, GElf_Addr value,
			     bool containing)
{
	size_t lo = 0, hi = functions->nr;
	const struct elf_function *f;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		f = &functions->functions[mid];
		if (f->shndx < shndx || (f->shndx == shndx && f->value <= value))
			lo = mid + 1;
		else
			hi = mid;
	}
	if (!lo)
		return NO_NODE;
	f = &functions->functions[lo - 1];
	if (f->shndx != shndx)
		return NO_NODE;
	if (!containing)
		return f->value == value ? f->node : NO_NODE;
	/* Aliases can have different sizes (including zero). */
	while (true) {
		if (function_contains(f, value))
			return f->node;
		if (--lo == 0 || cmp_elf_function_location(f - 1, f))
			return NO_NODE;
		f--;
	}
}

static int init_error_graph(struct error_graph *g,
			     struct elf_function_list *functions)
{
	size_t i;

	qsort(functions->functions, functions->nr, sizeof(*functions->functions),
	      cmp_elf_function_location);
	g->nodes = calloc(functions->nr, sizeof(*g->nodes));
	if (functions->nr && !g->nodes)
		return -ENOMEM;
	for (i = 0; i < functions->nr; i++) {
		struct elf_function *f = &functions->functions[i];

		if (!i || cmp_elf_function_location(f - 1, f)) {
			g->nodes[g->nr_nodes].name = f->name;
			g->nodes[g->nr_nodes].value = f->value;
			g->nodes[g->nr_nodes].shndx = f->shndx;
			g->nodes[g->nr_nodes].clean_via = NO_NODE;
			g->nodes[g->nr_nodes].reference_caller = NO_NODE;
			g->nodes[g->nr_nodes].incoming = NO_NODE;
			g->nodes[g->nr_nodes].outgoing = NO_NODE;
			g->nr_nodes++;
		}
		f->node = g->nr_nodes - 1;
	}
	return 0;
}

static int add_error_call(struct error_graph *g, size_t caller, size_t callee,
			   unsigned int flags, unsigned int nr_cases,
			   const unsigned char *p, unsigned int encoding,
			   size_t metadata_offset, unsigned int ordinal,
			   bool weak_definition)
{
	struct error_call *c;
	unsigned int i;
	int expected = -FMODRET_META_ERRNOS;
	unsigned int result = flags & FMODRET_CALL_RESULT_MASK;

	if (!nr_cases || nr_cases > FMODRET_META_ERRNOS ||
	    (flags & ~FMODRET_CALL_FLAGS) || (result & (result - 1)))
		return -EINVAL;
	if (((flags & FMODRET_CALL_NULL_ALLOCATOR) && result != FMODRET_CALL_RESULT_PTR) ||
	    ((flags & FMODRET_CALL_NULL_ERROR) && !(flags & FMODRET_CALL_NULL_ALLOCATOR)))
		return -EINVAL;
	if (g->nr_calls == g->capacity) {
		size_t cap = g->capacity ? g->capacity * 2 : 1024;
		void *calls;

		if (cap < g->capacity || cap > SIZE_MAX / sizeof(*c))
			return -E2BIG;
		calls = realloc(g->calls, cap * sizeof(*c));
		if (!calls)
			return -ENOMEM;
		g->calls = calls;
		g->capacity = cap;
	}
	c = &g->calls[g->nr_calls];
	*c = (struct error_call){ .caller = caller, .callee = callee,
		.flags = flags, .nr_cases = nr_cases,
		.metadata_offset = metadata_offset, .ordinal = ordinal,
		.weak_definition = weak_definition,
		.callee_param = FMODRET_NO_PARAM,
		.next_in = NO_NODE, .next_out = NO_NODE };
	c->cases = calloc(nr_cases, sizeof(*c->cases));
	if (!c->cases)
		return -ENOMEM;
	/* Count immediately so the common teardown also handles malformed cases. */
	g->nr_calls++;
	for (i = 0; i < nr_cases; i++, p += FMODRET_META_CASE_SIZE) {
		struct error_case *e = &c->cases[i];
		unsigned int kind;

		e->first = (int32_t)read_elf_value(p, 4, encoding);
		e->last = (int32_t)read_elf_value(p + 4, 4, encoding);
		e->kind = read_elf_value(p + 8, 4, encoding);
		e->replacement = (int32_t)read_elf_value(p + 12, 4, encoding);
		kind = e->kind & FMODRET_ERROR_RETURN_MASK;
		if (e->first != expected || e->last < e->first || e->last >= 0 ||
		    (e->kind & ~FMODRET_ERROR_RETURN_MASK) ||
		    kind > FMODRET_ERROR_CONSTANT ||
		    (kind == FMODRET_ERROR_CONSTANT &&
		     (e->replacement >= 0 || e->replacement < -FMODRET_META_ERRNOS)) ||
		    (kind != FMODRET_ERROR_CONSTANT && e->replacement))
			return -EINVAL;
		expected = e->last + 1;
	}
	if (expected)
		return -EINVAL;

	return 0;
}

struct symbol_range {
	GElf_Sym start;
	GElf_Addr end;
	bool valid;
};

static int get_symbol_range(Elf *elf, const char *start, const char *stop,
			    struct symbol_range *range)
{
	GElf_Sym end;
	bool found;
	int err;

	err = find_symbol(elf, start, &range->start, &found);
	if (err || !found)
		return err;
	if (!stop) {
		range->end = range->start.st_value + range->start.st_size;
		range->valid = range->end > range->start.st_value;
		return 0;
	}
	err = find_symbol(elf, stop, &end, &found);
	if (err || !found)
		return err;
	range->end = end.st_value;
	range->valid = end.st_shndx == range->start.st_shndx &&
		       range->end > range->start.st_value;
	return 0;
}

static bool in_symbol_range(const struct symbol_range *r, size_t shndx,
			    GElf_Addr address)
{
	return r->valid && r->start.st_shndx == shndx &&
	       address >= r->start.st_value && address < r->end;
}

static bool jump_label_reference(const GElf_Ehdr *ehdr,
				 const struct symbol_range *table, size_t shndx,
				 GElf_Addr site, unsigned int type, size_t ptr_size)
{
	size_t entry_size = 8 + ptr_size;
	GElf_Addr field;

	/* These architectures use two relative s32 code labels followed by a
	 * pointer-sized key. Only the code labels are patching metadata; a key
	 * that references a function must still fail the runtime-reference audit.
	 */
	if (ptr_size != 8 ||
	    !((ehdr->e_machine == EM_AARCH64 && type == R_AARCH64_PREL32) ||
	      (ehdr->e_machine == EM_X86_64 && type == R_X86_64_PC32)) ||
	    !in_symbol_range(table, shndx, site) ||
	    (table->end - table->start.st_value) % entry_size)
		return false;
	field = (site - table->start.st_value) % entry_size;
	return field == 0 || field == 4;
}

static bool arm64_code_metadata_reference(Elf *elf, const char *name,
					 Elf_Scn *scn, const GElf_Shdr *shdr,
					 size_t offset, const GElf_Sym *sym,
					 GElf_Sxword addend, unsigned int encoding,
					 const struct elf_function_list *functions,
					 size_t node)
{
	Elf_Data *data;
	GElf_Shdr code;
	GElf_Addr address;
	size_t field;

	if (!strcmp(name, ".altinstructions")) {
		/* arm64 struct alt_instr: two s32 offsets, u16 cpucap and
		 * two u8 lengths. The second offset can name a real callback.
		 */
		if (shdr->sh_size % 12)
			return false;
		field = offset % 12;
		if (!field)
			return true;
		if (field != 4)
			return false;
		data = elf_getdata(scn, NULL);
		if (!data || data->d_off || data->d_size != shdr->sh_size)
			return false;
		return !(read_elf_value((unsigned char *)data->d_buf + offset + 4,
				       2, encoding) & (1U << 15));
	}
	if (!strcmp(name, "__ex_table")) {
		GElf_Ehdr ehdr;

		/* arm64 exception entries contain s32 insn/fixup and u16 type/data.
		 * The fault site identifies an instruction, not another caller.
		 * A fixup is an intra-function continuation only when its fault site
		 * belongs to the same function as the fixup target being audited.
		 */
		if (shdr->sh_size % 12)
			return false;
		field = offset % 12;
		if (!field)
			return true;
		if (field != 4 || !gelf_getehdr(elf, &ehdr) || ehdr.e_type == ET_REL)
			return false;
		data = elf_getdata(scn, NULL);
		if (!data || data->d_off || data->d_size != shdr->sh_size)
			return false;
		address = shdr->sh_addr + offset - 4 +
			  (int32_t)read_elf_value((unsigned char *)data->d_buf + offset - 4,
						 4, encoding);
		return graph_function(functions, sym->st_shndx, address, true) == node;
	}
	/* Runtime-constant sections are arrays of s32 instruction offsets. */
	if (!strncmp(name, "runtime_ptr_", 12) ||
	    !strncmp(name, "runtime_shift_", 14) ||
	    !strncmp(name, "runtime_mask_", 13))
		return !(shdr->sh_size % 4) && !(offset % 4);
	if (strcmp(name, "__bug_table"))
		return false;
	/* A bug record points at a BRK #BUG_BRK_IMM instruction. Check the
	 * instruction instead of guessing the configuration-dependent record
	 * size. Filename references and arbitrary function pointers stay audited.
	 */
	scn = elf_getscn(elf, sym->st_shndx);
	if (!scn || !gelf_getshdr(scn, &code) || !(code.sh_flags & SHF_EXECINSTR))
		return false;
	address = sym->st_value + addend;
	if (address < code.sh_addr || address - code.sh_addr > code.sh_size ||
	    code.sh_size - (address - code.sh_addr) < 4)
		return false;
	data = elf_getdata(scn, NULL);
	if (!data || data->d_off || data->d_size != code.sh_size)
		return false;
	/* AArch64 instructions are little endian even in a big-endian ELF. */
	return read_elf_value((unsigned char *)data->d_buf + address - code.sh_addr,
			      4, ELFDATA2LSB) == 0xd4210000;
}

static bool x86_code_metadata_reference(Elf *elf, const char *name, Elf_Scn *scn,
					const GElf_Shdr *shdr, size_t offset,
					const GElf_Sym *sym, GElf_Sxword addend,
					const struct elf_function_list *functions,
					size_t node)
{
	static const char * const sites[] = {
		".orc_unwind_ip", ".return_sites", ".call_sites", ".retpoline_sites",
		".ibt_endbr_seal", ".cfi_sites", ".smp_locks",
	};
	Elf_Scn *code_scn = elf_getscn(elf, sym->st_shndx);
	GElf_Addr address = sym->st_value + addend;
	GElf_Shdr code;
	Elf_Data *data;
	size_t shstrndx;
	size_t field;

	if (!code_scn || !gelf_getshdr(code_scn, &code) || !(code.sh_flags & SHF_EXECINSTR))
		return false;
	for (size_t i = 0; i < ARRAY_SIZE(sites); i++)
		if (!strcmp(name, sites[i]))
			return !(shdr->sh_size % 4) && !(offset % 4);
	if (!strncmp(name, "runtime_ptr_", 12) ||
	    !strncmp(name, "runtime_shift_", 14) ||
	    !strncmp(name, "runtime_mask_", 13))
		return !(shdr->sh_size % 4) && !(offset % 4);
	if (!strcmp(name, ".static_call_sites"))
		return !(shdr->sh_size % 8) && !(offset % 8);
	if (!strcmp(name, ".altinstructions")) {
		if (shdr->sh_size % 14)
			return false;
		field = offset % 14;
		if (!field)
			return true;
		if (field != 4 || elf_getshdrstrndx(elf, &shstrndx))
			return false;
		name = elf_strptr(elf, shstrndx, code.sh_name);
		return name && !strcmp(name, ".altinstr_replacement");
	}
	if (!strcmp(name, "__ex_table")) {
		GElf_Ehdr ehdr;

		if (shdr->sh_size % 12)
			return false;
		field = offset % 12;
		if (!field)
			return true;
		if (field != 4 || !gelf_getehdr(elf, &ehdr) || ehdr.e_type == ET_REL)
			return false;
		data = elf_getdata(scn, NULL);
		if (!data || data->d_off || data->d_size != shdr->sh_size)
			return false;
		address = shdr->sh_addr + offset - 4 +
			  (int32_t)read_elf_value((unsigned char *)data->d_buf + offset - 4,
						 4, ELFDATA2LSB);
		return graph_function(functions, sym->st_shndx, address, true) == node;
	}
	if (strcmp(name, "__bug_table") || address < code.sh_addr ||
	    address - code.sh_addr > code.sh_size ||
	    code.sh_size - (address - code.sh_addr) < 2)
		return false;
	data = elf_getdata(code_scn, NULL);
	if (!data || data->d_off || data->d_size != code.sh_size)
		return false;
	return read_elf_value((unsigned char *)data->d_buf + address - code.sh_addr,
			      2, ELFDATA2LSB) == 0x0b0f;
}

static bool described_call(const struct error_graph *g, size_t caller,
			   size_t callee)
{
	size_t e;

	if (caller == NO_NODE || g->nodes[caller].definitions != 1)
		return false;
	for (e = g->nodes[caller].outgoing; e != NO_NODE; e = g->calls[e].next_out)
		if (g->calls[e].callee == callee)
			return true;
	return false;
}

/* Materializing a callback argument is a code reference to its address,
 * rather than a direct invocation. Its complete use chain is checked later.
 */
static bool described_callback_argument(const struct error_graph *g, size_t caller,
				       size_t function)
{
	size_t e;

	if (caller == NO_NODE || g->nodes[caller].definitions != 1)
		return false;
	for (e = g->nodes[caller].outgoing; e != NO_NODE; e = g->calls[e].next_out) {
		const struct error_call *c = &g->calls[e];
		unsigned int i;

		for (i = 0; i < c->nr_bindings; i++)
			if (c->bindings[i].source_param == FMODRET_NO_PARAM &&
			    c->bindings[i].function == function)
				return true;
	}
	return false;
}

static void record_unmodelled_reference(struct error_graph *g, size_t node,
					const char *reason, const char *section,
					GElf_Addr site, size_t caller)
{
	struct error_node *n = &g->nodes[node];

	n->incomplete = true;
	if (!n->nr_unmodelled_refs++) {
		n->reference_reason = reason;
		n->reference_section = section;
		n->reference_site = site;
		n->reference_caller = caller;
	}
}

static bool x86_syscall_entry(const struct error_node *n)
{
	static const char * const prefixes[] = {
		"__x64_sys_", "__x64_compat_sys_", "__ia32_sys_", "__ia32_compat_sys_",
	};

	if (n->definitions != 1 || !(n->flags & FMODRET_FN_INTEGER) ||
	    (n->flags & FMODRET_FN_LOCAL))
		return false;
	for (size_t i = 0; i < ARRAY_SIZE(prefixes); i++)
		if (!strncmp(n->name, prefixes[i], strlen(prefixes[i])))
			return true;
	return false;
}

/* Read pointer relocations before parsing records, then audit the other ELF
 * references after the call graph exists. An unmodelled caller blocks proof.
 * In particular, assembly and objects built without the plugin are not assumed
 * to propagate errors. Syscall entries are return-to-userspace boundaries;
 * explicit error-reporting endpoints are carried by individual call cases.
 */
/* Export table entries only name the exported functions. Modules are the other
 * users of those and are not part of the image: an exported function is an
 * ordinary function, and a module which mishandles its error is at fault.
 */
static bool is_ksymtab_section(const char *name)
{
	return !strncmp(name, "__ksymtab", 9) || !strncmp(name, "___ksymtab+", 11);
}

static int graph_relocations(Elf *elf, const struct elf_function_list *functions,
			     struct error_graph *g, size_t metadata_ndx,
			     const GElf_Shdr *metadata_shdr,
			     const unsigned char *metadata, size_t *refs,
			     size_t ptr_size, unsigned int encoding, bool audit)
{
	static const char * const tables[] = { "sys_call_table", "compat_sys_call_table",
		"ia32_sys_call_table", "x32_sys_call_table" };
	static const char * const ignored[][2] = {
		{ "__start_mcount_loc", "__stop_mcount_loc" },
		{ "__start_error_injection_whitelist", "__stop_error_injection_whitelist" },
	};
	struct symbol_range roots[4] = {}, skip[2] = {}, jump_table = {};
	Elf_Scn *scn = NULL;
	GElf_Ehdr ehdr;
	size_t shstrndx, i;
	int err;

	if (!gelf_getehdr(elf, &ehdr))
		return -1;
	if (elf_getshdrstrndx(elf, &shstrndx))
		return -1;
	if (audit) {
		if (ehdr.e_machine == EM_X86_64 || ehdr.e_machine == EM_386)
			for (i = 0; i < g->nr_nodes; i++)
				g->nodes[i].terminal |= x86_syscall_entry(&g->nodes[i]);
		for (i = 0; i < 4; i++) {
			err = get_symbol_range(elf, tables[i], NULL, &roots[i]);
			if (err)
				return err;
		}
		for (i = 0; i < 2; i++) {
			err = get_symbol_range(elf, ignored[i][0], ignored[i][1], &skip[i]);
			if (err)
				return err;
		}
		err = get_symbol_range(elf, "__start___jump_table",
				       "__stop___jump_table", &jump_table);
		if (err)
			return err;
	}
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr, target;
		Elf_Data *data, *symbols;
		Elf_Scn *target_scn, *symtab;
		const char *name;
		bool is_metadata;

		if (!gelf_getshdr(scn, &shdr))
			return -1;
		if (shdr.sh_type != SHT_RELA && shdr.sh_type != SHT_REL)
			continue;
		is_metadata = shdr.sh_info == metadata_ndx;
		if (audit == is_metadata || !shdr.sh_info)
			continue;
		target_scn = elf_getscn(elf, shdr.sh_info);
		if (!target_scn || !gelf_getshdr(target_scn, &target))
			return -1;
		if (audit && !(target.sh_flags & SHF_ALLOC))
			continue;
		if (audit && (target.sh_flags & SHF_EXECINSTR) && shdr.sh_size)
			g->audited_text = true;
		name = elf_strptr(elf, shstrndx, target.sh_name);
		if (!name)
			return -1;
		if (audit && (!strcmp(name, "__mcount_loc") ||
			      !strcmp(name, "__patchable_function_entries") ||
			      !strcmp(name, "_error_injection_whitelist") ||
			      is_ksymtab_section(name)))
			continue;
		if (!shdr.sh_entsize || shdr.sh_size % shdr.sh_entsize)
			return -EINVAL;
		data = elf_getdata(scn, NULL);
		symtab = elf_getscn(elf, shdr.sh_link);
		symbols = symtab ? elf_getdata(symtab, NULL) : NULL;
		if (!data || !symbols || elf_getdata(scn, data))
			return -1;
		for (i = 0; i < shdr.sh_size / shdr.sh_entsize; i++) {
			GElf_Rela rela;
			GElf_Sym sym;
			GElf_Addr address, site;
			size_t offset, node, caller, j;
			unsigned int type;
			bool handled = false;

			if (shdr.sh_type == SHT_RELA) {
				if (!gelf_getrela(data, i, &rela))
					return -1;
			} else {
				GElf_Rel rel;

				if (!gelf_getrel(data, i, &rel))
					return -1;
				rela = (GElf_Rela){ .r_offset = rel.r_offset, .r_info = rel.r_info };
				// REL metadata addends are stored in the pointer itself.
				if (!audit) {
					if (!relocation_offset(metadata_shdr, rel.r_offset, ptr_size, &offset))
						return -EINVAL;
					rela.r_addend = read_elf_value(metadata + offset, ptr_size, encoding);
				}
			}
			if (!gelf_getsym(symbols, GELF_R_SYM(rela.r_info), &sym))
				return -1;
			if (sym.st_shndx == SHN_UNDEF || sym.st_shndx >= SHN_LORESERVE)
				continue;
			address = sym.st_value + rela.r_addend;
			type = GELF_R_TYPE(rela.r_info);
			if (audit && (target.sh_flags & SHF_EXECINSTR)) {
				// x86 encodes displacement relative to the end of its field.
				if ((ehdr.e_machine == EM_X86_64 &&
				     (type == R_X86_64_PC32 || type == R_X86_64_PLT32)) ||
				    (ehdr.e_machine == EM_386 && type == R_386_PC32))
					address += 4;
			}
			if (audit && GELF_ST_TYPE(sym.st_info) == STT_FUNC)
				address = sym.st_value;
			if (audit) {
				if (!relocation_offset(&target, rela.r_offset, 1, &offset))
					return -EINVAL;
				site = target.sh_addr + offset;
				caller = target.sh_flags & SHF_EXECINSTR ?
					graph_function(functions, shdr.sh_info, site, true) : NO_NODE;
			}
			if (audit && shdr.sh_type == SHT_REL &&
			    GELF_ST_TYPE(sym.st_info) == STT_SECTION) {
				/* Instruction addends in REL are architecture-specific.
				 * Do not miss a caller by guessing an instruction encoding.
				 */
				for (j = 0; j < functions->nr; j++)
					if (functions->functions[j].shndx == sym.st_shndx)
						record_unmodelled_reference(g, functions->functions[j].node,
							"unsupported-REL-section-addend", name, site, caller);
				continue;
			}
			node = graph_function(functions, sym.st_shndx, address, audit);
			if (!audit) {
				if (!relocation_offset(metadata_shdr, rela.r_offset, ptr_size, &offset) ||
				    offset % ptr_size)
					return -EINVAL;
				refs[offset / ptr_size] = node;
				continue;
			}
			if (node == NO_NODE)
				continue;
			for (j = 0; j < 4; j++)
				if (in_symbol_range(&roots[j], shdr.sh_info, site) &&
				    !(offset % ptr_size)) {
					g->nodes[node].terminal = true;
					handled = true;
				}
			for (j = 0; j < 2; j++)
				handled |= in_symbol_range(&skip[j], shdr.sh_info, site);
			if (handled || jump_label_reference(&ehdr, &jump_table,
							   shdr.sh_info, site, type, ptr_size))
				continue;
			if (ehdr.e_machine == EM_AARCH64 && type == R_AARCH64_PREL32 &&
			    arm64_code_metadata_reference(elf, name, target_scn, &target,
							  offset, &sym, rela.r_addend, encoding,
							  functions, node))
				continue;
			if (ehdr.e_machine == EM_X86_64 && type == R_X86_64_PC32 &&
			    x86_code_metadata_reference(elf, name, target_scn,
							&target, offset, &sym, rela.r_addend,
							functions, node))
				continue;
			if (!described_call(g, caller, node) &&
			    !described_callback_argument(g, caller, node))
				record_unmodelled_reference(g, node,
					target.sh_flags & SHF_EXECINSTR ?
					"unmodelled-code-reference" : "runtime-data-reference",
					name, site, caller);
		}
	}
	return 0;
}

static size_t metadata_reference(Elf *elf, const struct elf_function_list *functions,
				 const unsigned char *buf, const size_t *refs,
				 size_t offset, size_t ptr_size,
				 unsigned int encoding)
{
	GElf_Ehdr ehdr;
	Elf64_Section section;
	GElf_Addr value;

	if (refs[offset / ptr_size] != NO_NODE)
		return refs[offset / ptr_size];
	if (!gelf_getehdr(elf, &ehdr) || ehdr.e_type == ET_REL)
		return NO_NODE;
	value = read_elf_value(buf + offset, ptr_size, encoding);
	if (!value || section_for_address(elf, value, &section))
		return NO_NODE;
	return graph_function(functions, section, value, false);
}

static void print_function_flags(const struct error_node *node, size_t offset,
				 unsigned int flags)
{
	static const struct {
		unsigned int flag;
		const char *name;
	} names[] = {
		{ FMODRET_FN_DEFINED, "defined" },
		{ FMODRET_FN_LOCAL, "local" },
		{ FMODRET_FN_CLEAN_SEED, "atomic_clean" },
		{ FMODRET_FN_ESCAPED, "escaped" },
		{ FMODRET_FN_WEAK, "weak" },
		{ FMODRET_FN_INTEGER, "integer" },
		{ FMODRET_FN_ERRPTR, "error_pointer" },
		{ FMODRET_FN_RET64, "integer_return64" },
		{ FMODRET_FN_ADDRESS_TAKEN, "address_taken" },
		{ FMODRET_FN_EXPORTED, "exported" },
	};
	size_t i;

	fprintf(stderr, "fmodret input: %s section=%u address=%#llx record=%#zx flags=%#x [",
		node ? node->name : "<unresolved reference>",
		node ? (unsigned int)node->shndx : 0,
		node ? (unsigned long long)node->value : 0, offset, flags);
	for (i = 0; i < ARRAY_SIZE(names); i++)
		if (flags & names[i].flag)
			fprintf(stderr, " %s", names[i].name);
	fprintf(stderr, " ]\n");
}

static int parse_error_graph(Elf *elf, const struct elf_function_list *functions,
			     struct error_graph *g, const unsigned char *buf,
			     size_t size, const size_t *refs, size_t ptr_size,
			     unsigned int encoding, int verbose)
{
	size_t offset = 0;

	while (offset < size) {
		size_t end, pos, node;
		unsigned int flags, calls, params, length, i;

		if (size - offset < FMODRET_META_HEADER_SIZE(ptr_size) ||
		    read_elf_value(buf + offset, 4, encoding) != FMODRET_META_MAGIC ||
		    read_elf_value(buf + offset + 4, 4, encoding) != FMODRET_META_VERSION)
			goto invalid;
		length = read_elf_value(buf + offset + 8, 4, encoding);
		flags = read_elf_value(buf + offset + 12, 4, encoding);
		if (length < FMODRET_META_HEADER_SIZE(ptr_size) || length > size - offset ||
		    length % ptr_size || flags & ~FMODRET_FN_FLAGS)
			goto invalid;
		end = offset + length;
		calls = read_elf_value(buf + offset + 16 + ptr_size, 4, encoding);
		params = read_elf_value(buf + offset + 20 + ptr_size, 4, encoding);
		node = metadata_reference(elf, functions, buf, refs, offset + 16, ptr_size, encoding);
		if (node == NO_NODE && (flags & FMODRET_FN_DEFINED))
			goto invalid;
		g->nr_records++;
		if (flags & FMODRET_FN_DEFINED)
			g->nr_defined_records++;
		else
			g->nr_reference_records++;
		if (verbose)
			print_function_flags(node == NO_NODE ? NULL : &g->nodes[node], offset, flags);
		if (node != NO_NODE) {
			if (flags & FMODRET_FN_DEFINED) {
				struct error_node *n = &g->nodes[node];

				if (flags & FMODRET_FN_WEAK) {
					n->weak_definitions++;
					n->weak_flags |= flags;
				} else {
					n->strong_definitions++;
					n->strong_flags |= flags;
				}
				n->flags |= flags & (FMODRET_FN_ESCAPED | FMODRET_FN_ADDRESS_TAKEN);
			} else {
				g->nodes[node].flags |= flags &
					(FMODRET_FN_ESCAPED | FMODRET_FN_ADDRESS_TAKEN);
			}
		}
		if ((calls || params) && !(flags & FMODRET_FN_DEFINED))
			goto invalid;
		pos = offset + FMODRET_META_HEADER_SIZE(ptr_size);
		if (params > (end - pos) / FMODRET_META_PARAM_SIZE)
			goto invalid;
		{
			struct error_node *n = node == NO_NODE ? NULL : &g->nodes[node];
			struct callback_parameters *p = NULL;

			if (n && (flags & FMODRET_FN_DEFINED)) {
				if ((flags & FMODRET_FN_WEAK) && n->weak_definitions == 1)
					p = &n->weak_params;
				else if (!(flags & FMODRET_FN_WEAK) && n->strong_definitions == 1)
					p = &n->strong_params;
			}
			if (p && params) {
				p->flags = calloc(params, sizeof(*p->flags));
				if (!p->flags)
					return -ENOMEM;
				p->nr = params;
			}
			for (i = 0; i < params; i++, pos += FMODRET_META_PARAM_SIZE) {
				unsigned int pf = read_elf_value(buf + pos, 4, encoding);

				if ((pf & ~FMODRET_PARAM_CLOSED) ||
				    read_elf_value(buf + pos + 4, 4, encoding))
					goto invalid;
				if (p)
					p->flags[i] = pf;
			}
		}
		for (i = 0; i < calls; i++) {
			unsigned int nr_cases, call_flags, callee_param, bindings, j;
			struct error_call *c;
			size_t callee, call_offset = pos;
			int err;

			if (end - pos < FMODRET_META_CALL_SIZE(ptr_size))
				goto invalid;
			callee = metadata_reference(elf, functions, buf, refs, pos, ptr_size, encoding);
			call_flags = read_elf_value(buf + pos + ptr_size, 4, encoding);
			nr_cases = read_elf_value(buf + pos + ptr_size + 4, 4, encoding);
			callee_param = read_elf_value(buf + pos + ptr_size + 8, 4, encoding);
			bindings = read_elf_value(buf + pos + ptr_size + 12, 4, encoding);
			if (callee_param != FMODRET_NO_PARAM &&
			    (callee != NO_NODE || callee_param >= params || bindings ||
			     (call_flags & FMODRET_CALL_NULL_ALLOCATOR)))
				goto invalid;
			pos += FMODRET_META_CALL_SIZE(ptr_size);
			if (nr_cases > (end - pos) / FMODRET_META_CASE_SIZE)
				goto invalid;
			err = add_error_call(g, node, callee, call_flags, nr_cases, buf + pos,
					     encoding, call_offset, i + 1,
					     flags & FMODRET_FN_WEAK);
			if (err)
				return err;
			pos += nr_cases * FMODRET_META_CASE_SIZE;
			c = &g->calls[g->nr_calls - 1];
			c->callee_param = callee_param;
			if (bindings > (end - pos) / FMODRET_META_BINDING_SIZE(ptr_size))
				goto invalid;
			if (bindings) {
				c->bindings = calloc(bindings, sizeof(*c->bindings));
				if (!c->bindings)
					return -ENOMEM;
				c->nr_bindings = bindings;
			}
			for (j = 0; j < bindings; j++, pos += FMODRET_META_BINDING_SIZE(ptr_size)) {
				struct callback_binding *b = &c->bindings[j];

				b->function = metadata_reference(elf, functions, buf, refs, pos,
							 ptr_size, encoding);
				b->argument = read_elf_value(buf + pos + ptr_size, 4, encoding);
				b->source_param = read_elf_value(buf + pos + ptr_size + 4, 4, encoding);
				if (b->source_param != FMODRET_NO_PARAM &&
				    (b->source_param >= params || b->function != NO_NODE))
					goto invalid;
			}
		}
		if (pos != end)
			goto invalid;
		offset = end;
	}
	return 0;
invalid:
	fprintf(stderr, "invalid or old fmodret metadata at offset %#zx; rebuild all plugin objects\n", offset);
	return -EINVAL;
}

/* A weak definition reference is interposable: after linking it can point
 * at the winning strong body. Select descriptions before constructing either
 * adjacency list, so losing clean seeds and calls cannot affect either pass.
 * Preserve escape evidence from every input record; it can describe a use
 * outside the losing weak body. Weak-only and ambiguous bodies stay unproved.
 */
static void select_error_descriptions(struct error_graph *g)
{
	size_t i;

	for (i = 0; i < g->nr_nodes; i++) {
		struct error_node *n = &g->nodes[i];

		if (n->strong_definitions) {
			n->flags |= n->strong_flags;
			n->definitions = n->strong_definitions;
			n->params = &n->strong_params;
			g->nr_overridden_weak += n->weak_definitions;
		} else {
			n->flags |= n->weak_flags;
			n->definitions = n->weak_definitions;
			n->params = &n->weak_params;
		}
	}
	for (i = 0; i < g->nr_calls; i++) {
		struct error_call *c = &g->calls[i];
		struct error_node *caller = &g->nodes[c->caller];

		if (c->weak_definition && caller->strong_definitions) {
			g->nr_discarded_calls++;
			continue;
		}
		c->next_out = caller->outgoing;
		caller->outgoing = i;
		if (c->callee != NO_NODE) {
			c->next_in = g->nodes[c->callee].incoming;
			g->nodes[c->callee].incoming = i;
		}
	}
}

static bool graph_node_known(const struct error_node *n)
{
	/* ADDRESS_TAKEN is not a veto. ESCAPED, unresolved argument flows and
	 * unmodelled linked references describe the remaining coverage gaps.
	 */
	return n->definitions == 1 &&
	       (n->flags & (FMODRET_FN_INTEGER | FMODRET_FN_ERRPTR)) &&
	       !(n->flags & (FMODRET_FN_ESCAPED | FMODRET_FN_WEAK)) &&
	       !n->incomplete && !n->callback_unresolved;
}

struct callback_edge {
	size_t call, function;
};

struct callback_walk {
	struct callback_edge *edges;
	size_t nr, capacity;
	struct {
		size_t node;
		unsigned int param;
	} path[64];
	unsigned int budget;
	const char *reason;
	size_t failed_node;
	unsigned int failed_param;
};

static int add_callback_edge(struct callback_walk *walk, size_t call, size_t function)
{
	if (walk->nr == walk->capacity) {
		size_t cap = walk->capacity ? walk->capacity * 2 : 64;
		void *edges;

		if (cap < walk->capacity || cap > SIZE_MAX / sizeof(*walk->edges))
			return -E2BIG;
		edges = realloc(walk->edges, cap * sizeof(*walk->edges));
		if (!edges)
			return -ENOMEM;
		walk->edges = edges;
		walk->capacity = cap;
	}
	walk->edges[walk->nr++] = (struct callback_edge){ call, function };
	return 1;
}

/* Resolve one concrete function address through formal parameters. This
 * proves coverage of that address; other, unknown callback values reaching
 * the same dispatcher need not be assigned to this function. Return 0 for
 * incomplete coverage and a negative value only for allocation failures.
 */
static int walk_callback_parameter(const struct error_graph *g,
				   struct callback_walk *walk, size_t node,
				   unsigned int param, size_t function,
				   unsigned int depth)
{
	const struct error_node *n;
	size_t e;
	unsigned int i;
	int err;

	walk->failed_node = node;
	walk->failed_param = param;
	if (depth == ARRAY_SIZE(walk->path) || !walk->budget) {
		walk->reason = "callback-walk-limit";
		return 0;
	}
	if (node == NO_NODE || g->nodes[node].definitions != 1 ||
	    (g->nodes[node].flags & FMODRET_FN_WEAK)) {
		walk->reason = "missing-or-ambiguous-dispatcher-body";
		return 0;
	}
	n = &g->nodes[node];
	if (!n->params || param >= n->params->nr ||
	    !(n->params->flags[param] & FMODRET_PARAM_CLOSED)) {
		walk->reason = "unmodelled-parameter-use";
		return 0;
	}
	for (i = 0; i < depth; i++)
		if (walk->path[i].node == node && walk->path[i].param == param) {
			walk->reason = "callback-forwarding-cycle";
			return 0;
		}
	walk->path[depth].node = node;
	walk->path[depth].param = param;
	for (e = n->outgoing; e != NO_NODE; e = g->calls[e].next_out) {
		const struct error_call *c = &g->calls[e];

		if (!walk->budget) {
			walk->reason = "callback-walk-limit";
			walk->failed_node = node;
			walk->failed_param = param;
			return 0;
		}
		walk->budget--;
		if (c->callee_param == param) {
			const struct error_node *f = &g->nodes[function];
			unsigned int result = f->flags & FMODRET_FN_ERRPTR ?
				FMODRET_CALL_RESULT_PTR : f->flags & FMODRET_FN_INTEGER ?
				(f->flags & FMODRET_FN_RET64 ? FMODRET_CALL_RESULT64 :
				 FMODRET_CALL_RESULT32) : 0;

			if (!result || (c->flags & FMODRET_CALL_RESULT_MASK) != result) {
				walk->reason = "incompatible-callback-result";
				walk->failed_node = node;
				walk->failed_param = param;
				return 0;
			}
			err = add_callback_edge(walk, e, function);
			if (err < 0)
				return err;
		}
		for (i = 0; i < c->nr_bindings; i++) {
			const struct callback_binding *b = &c->bindings[i];

			if (b->source_param != param)
				continue;
			err = walk_callback_parameter(g, walk, c->callee, b->argument,
						      function, depth + 1);
			if (err <= 0)
				return err;
		}
	}
	return 1;
}

static int cmp_callback_edge(const void *left, const void *right)
{
	const struct callback_edge *a = left, *b = right;

	if (a->call != b->call)
		return a->call < b->call ? -1 : 1;
	return a->function < b->function ? -1 : a->function != b->function;
}

static int materialize_callback_edge(struct error_graph *g,
				     const struct callback_edge *edge)
{
	struct error_call source = g->calls[edge->call], *c;
	struct error_case *cases;

	cases = malloc(source.nr_cases * sizeof(*cases));
	if (!cases)
		return -ENOMEM;
	memcpy(cases, source.cases, source.nr_cases * sizeof(*cases));
	if (g->nr_calls == g->capacity) {
		size_t cap = g->capacity ? g->capacity * 2 : 1024;
		void *calls;

		if (cap < g->capacity || cap > SIZE_MAX / sizeof(*c)) {
			free(cases);
			return -E2BIG;
		}
		calls = realloc(g->calls, cap * sizeof(*c));
		if (!calls) {
			free(cases);
			return -ENOMEM;
		}
		g->calls = calls;
		g->capacity = cap;
	}
	c = &g->calls[g->nr_calls];
	*c = source;
	c->callee = edge->function;
	c->callee_param = FMODRET_NO_PARAM;
	c->resolved_callback = true;
	c->nr_bindings = 0;
	c->bindings = NULL;
	c->cases = cases;
	c->next_out = g->nodes[c->caller].outgoing;
	c->next_in = g->nodes[c->callee].incoming;
	g->nodes[c->caller].outgoing = g->nr_calls;
	g->nodes[c->callee].incoming = g->nr_calls++;
	g->nr_callback_edges++;
	return 0;
}

static int resolve_callback_arguments(struct error_graph *g, int verbose)
{
	struct callback_walk walk = {};
	size_t e, i;
	int err = 0;

	g->nr_input_calls = g->nr_calls;
	/* Finish all parameter walks before growing CALLS or adding adjacency
	 * entries, so templates and forwarding paths stay stable during closure.
	 */
	for (e = 0; e < g->nr_input_calls; e++) {
		const struct error_call *c = &g->calls[e];
		unsigned int j;

		if (c->weak_definition && g->nodes[c->caller].strong_definitions)
			continue;
		for (j = 0; j < c->nr_bindings; j++) {
			const struct callback_binding *b = &c->bindings[j];
			size_t before = walk.nr;

			if (b->source_param != FMODRET_NO_PARAM || b->function == NO_NODE)
				continue;
			g->nr_callback_bindings++;
			walk.budget = 4096;
			walk.reason = "proven";
			if (g->nodes[c->caller].definitions != 1 ||
			    (g->nodes[c->caller].flags & FMODRET_FN_WEAK)) {
				walk.reason = "missing-or-ambiguous-binding-owner";
				walk.failed_node = c->caller;
				walk.failed_param = FMODRET_NO_PARAM;
				err = 0;
			} else {
				err = walk_callback_parameter(g, &walk, c->callee, b->argument,
							      b->function, 0);
			}
			if (err < 0)
				goto out;
			if (!err) {
				walk.nr = before;
				g->nodes[b->function].callback_unresolved = true;
			} else {
				g->nr_resolved_bindings++;
			}
			if (verbose)
				fprintf(stderr, "fmodret callback-binding: function=%s@%#llx "
					"caller=%s dispatcher=%s argument=%u call=%u "
					"metadata=%#zx coverage=%s reason=%s "
					"blocked-at=%s blocked-parameter=%u\n",
					g->nodes[b->function].name,
					(unsigned long long)g->nodes[b->function].value,
					g->nodes[c->caller].name,
					c->callee == NO_NODE ? "<unknown>" : g->nodes[c->callee].name,
					b->argument, c->ordinal, c->metadata_offset,
					err ? "complete" : "incomplete", walk.reason,
					err ? "<none>" : walk.failed_node == NO_NODE ?
					"<missing body>" : g->nodes[walk.failed_node].name,
					err ? FMODRET_NO_PARAM : walk.failed_param);
		}
	}
	if (walk.nr)
		qsort(walk.edges, walk.nr, sizeof(*walk.edges), cmp_callback_edge);
	for (i = 0; i < walk.nr; i++) {
		if (i && !cmp_callback_edge(&walk.edges[i - 1], &walk.edges[i]))
			continue;
		err = materialize_callback_edge(g, &walk.edges[i]);
		if (err)
			goto out;
		if (verbose) {
			const struct error_call *c = &g->calls[g->nr_calls - 1];

			fprintf(stderr, "fmodret callback-edge: caller=%s callee=%s "
				"parameter=%u call=%u metadata=%#zx\n",
				g->nodes[c->caller].name, g->nodes[c->callee].name,
				g->calls[walk.edges[i].call].callee_param,
				c->ordinal, c->metadata_offset);
		}
	}
	err = 0;
out:
	free(walk.edges);
	return err;
}

static bool error_bit(const uint64_t *bits, int error)
{
	unsigned int bit = -error - 1;

	return bits[bit / 64] & (1ULL << (bit % 64));
}

static void all_errors(uint64_t *bits)
{
	memset(bits, 0xff, ERROR_WORDS * sizeof(*bits));
	bits[ERROR_WORDS - 1] = UINT64_MAX >> (ERROR_WORDS * 64 - FMODRET_META_ERRNOS);
}

static bool all_errors_returned(const struct error_call *c)
{
	unsigned int i;

	for (i = 0; i < c->nr_cases; i++)
		/* An accepted endpoint does not establish a clean return path. */
		if (c->cases[i].kind != FMODRET_ERROR_IDENTITY &&
		    c->cases[i].kind != FMODRET_ERROR_CONSTANT)
			return false;
	return true;
}

static void error_preimage(const struct error_call *c, const uint64_t *parent,
			    uint64_t *result)
{
	unsigned int i, word;

	memset(result, 0, ERROR_WORDS * sizeof(*result));
	for (i = 0; i < c->nr_cases; i++) {
		const struct error_case *e = &c->cases[i];
		unsigned int first = -e->last - 1, last = -e->first - 1;
		unsigned int kind = e->kind & FMODRET_ERROR_RETURN_MASK;

		if (!e->kind || (kind == FMODRET_ERROR_CONSTANT &&
				!error_bit(parent, e->replacement)))
			continue;
		for (word = first / 64; word <= last / 64; word++) {
			uint64_t mask = UINT64_MAX;

			if (word == first / 64)
				mask &= UINT64_MAX << (first % 64);
			if (word == last / 64)
				mask &= UINT64_MAX >> (63 - last % 64);
			result[word] |= mask & (kind == FMODRET_ERROR_IDENTITY ? parent[word] : UINT64_MAX);
		}
	}
}

enum error_rejection {
	ERROR_ACCEPTED,
	ERROR_NO_TEXT_RELOCS,
	ERROR_MISSING_DESCRIPTION,
	ERROR_MULTIPLE_DESCRIPTIONS,
	ERROR_NON_INTEGER,
	ERROR_WEAK,
	ERROR_ESCAPED,
	ERROR_CALLBACK_UNRESOLVED,
	ERROR_INCOMPLETE_CALLERS,
	ERROR_NO_CALLERS,
	ERROR_UNKNOWN_OUTCOME,
	ERROR_CALLER_UNPROVEN,
	ERROR_REJECTION_COUNT,
};

static const char * const error_rejection_names[] = {
	[ERROR_ACCEPTED] = "proven",
	[ERROR_NO_TEXT_RELOCS] = "no-code-relocations-for-caller-audit",
	[ERROR_MISSING_DESCRIPTION] = "missing-function-description",
	[ERROR_MULTIPLE_DESCRIPTIONS] = "multiple-function-descriptions",
	[ERROR_NON_INTEGER] = "non-errno-return-type",
	[ERROR_WEAK] = "weak-definition",
	[ERROR_ESCAPED] = "address-escaped",
	[ERROR_CALLBACK_UNRESOLVED] = "unresolved-callback-argument",
	[ERROR_INCOMPLETE_CALLERS] = "unmodelled-ELF-reference",
	[ERROR_NO_CALLERS] = "no-callers-and-no-userspace-boundary",
	[ERROR_UNKNOWN_OUTCOME] = "unknown-error-outcome",
	[ERROR_CALLER_UNPROVEN] = "caller-error-not-proven",
};

static unsigned int error_count(const uint64_t *bits)
{
	unsigned int i, count = 0;

	for (i = 0; i < ERROR_WORDS; i++)
		count += __builtin_popcountll(bits[i]);
	return count;
}

static bool error_set_full(const uint64_t *bits)
{
	unsigned int i;

	for (i = 0; i + 1 < ERROR_WORDS; i++)
		if (bits[i] != UINT64_MAX)
			return false;
	return bits[ERROR_WORDS - 1] ==
	       UINT64_MAX >> (ERROR_WORDS * 64 - FMODRET_META_ERRNOS);
}

/* These are proof limitations, not claims that a function is unsafe. Several
 * direct blockers may apply. The first is used for disjoint summary counts.
 */
static unsigned int error_rejection_mask(const struct error_graph *g, size_t node)
{
	const struct error_node *n = &g->nodes[node];
	unsigned int reasons = 0;
	size_t e;

	if (!g->audited_text)
		reasons |= 1U << ERROR_NO_TEXT_RELOCS;
	if (!n->definitions)
		reasons |= 1U << ERROR_MISSING_DESCRIPTION;
	else if (n->definitions != 1)
		reasons |= 1U << ERROR_MULTIPLE_DESCRIPTIONS;
	if (!(n->flags & (FMODRET_FN_INTEGER | FMODRET_FN_ERRPTR)))
		reasons |= 1U << ERROR_NON_INTEGER;
	if (n->flags & FMODRET_FN_WEAK)
		reasons |= 1U << ERROR_WEAK;
	if (n->flags & FMODRET_FN_ESCAPED)
		reasons |= 1U << ERROR_ESCAPED;
	if (n->callback_unresolved)
		reasons |= 1U << ERROR_CALLBACK_UNRESOLVED;
	if (n->incomplete)
		reasons |= 1U << ERROR_INCOMPLETE_CALLERS;
	if (!n->terminal && n->incoming == NO_NODE)
		reasons |= 1U << ERROR_NO_CALLERS;
	if (reasons || error_set_full(n->good))
		return reasons;
	for (e = n->incoming; e != NO_NODE; e = g->calls[e].next_in) {
		unsigned int i;

		for (i = 0; i < g->calls[e].nr_cases; i++)
			if (g->calls[e].cases[i].kind == FMODRET_ERROR_UNKNOWN)
				return 1U << ERROR_UNKNOWN_OUTCOME;
	}
	/* Following the printed caller edges also exposes unproved cycles. */
	return 1U << ERROR_CALLER_UNPROVEN;
}

static enum error_rejection primary_rejection(unsigned int mask)
{
	return mask ? (enum error_rejection)__builtin_ctz(mask) : ERROR_ACCEPTED;
}

static void print_rejection_mask(unsigned int mask)
{
	unsigned int i;
	bool separator = false;

	if (!mask) {
		fprintf(stderr, "proven");
		return;
	}
	for (i = 1; i < ERROR_REJECTION_COUNT; i++) {
		if (!(mask & (1U << i)))
			continue;
		fprintf(stderr, "%s%s", separator ? "," : "", error_rejection_names[i]);
		separator = true;
	}
}

/* Count missing members of one errno interval and return a concrete example.
 * Word masks avoid enumerating 4095 values at every call site.
 */
static unsigned int missing_errors(const uint64_t *bits, int first, int last,
				   int *sample)
{
	unsigned int lo = -last - 1, hi = -first - 1, w, count = 0;

	for (w = lo / 64; w <= hi / 64; w++) {
		uint64_t missing = ~bits[w];

		if (w == lo / 64)
			missing &= UINT64_MAX << (lo % 64);
		if (w == hi / 64)
			missing &= UINT64_MAX >> (63 - hi % 64);
		if (missing && !count)
			*sample = -(int)(w * 64 + __builtin_ctzll(missing) + 1);
		count += __builtin_popcountll(missing);
	}
	return count;
}

static void print_blocked_call(const struct error_graph *g,
			       const struct error_call *call,
			       const struct error_case *c)
{
	const struct error_node *caller = &g->nodes[call->caller];
	const struct error_node *callee = &g->nodes[call->callee];
	unsigned int missing;
	unsigned int kind = c->kind & FMODRET_ERROR_RETURN_MASK;
	int sample = c->first;

	if (kind == FMODRET_ERROR_IDENTITY) {
		missing = missing_errors(caller->good, c->first, c->last, &sample);
	} else if (kind == FMODRET_ERROR_CONSTANT) {
		missing = error_bit(caller->good, c->replacement) ? 0 :
			  c->last - c->first + 1;
	} else {
		missing = c->last - c->first + 1;
	}
	if (!missing)
		return;
	fprintf(stderr, "fmodret call-rejected: callee=%s@%#llx caller=%s@%#llx "
		"call=%u metadata=%#zx call-kind=%s prefix=%s input=[%d,%d] "
		"unproven=%u sample=%d map=",
		callee->name, (unsigned long long)callee->value,
		caller->name, (unsigned long long)caller->value,
		call->ordinal, call->metadata_offset,
		call->resolved_callback ? "callback" : "direct",
		call->flags & FMODRET_CALL_CLEAN_PREFIX ? "clean" : "dirty",
		c->first, c->last, missing, sample);
	if (kind == FMODRET_ERROR_IDENTITY)
		fprintf(stderr, "identity caller-errno=%d", sample);
	else if (kind == FMODRET_ERROR_CONSTANT)
		fprintf(stderr, "constant(%d) caller-errno=%d", c->replacement, c->replacement);
	else
		fprintf(stderr, "unknown (discarded/unsupported/loop not distinguished in metadata)");
	fprintf(stderr, " caller-reasons=");
	print_rejection_mask(error_rejection_mask(g, call->caller));
	fprintf(stderr, "\n");
}

static void print_function_resolution(const struct error_graph *g, size_t node)
{
	const struct error_node *n = &g->nodes[node];
	unsigned int mask = error_rejection_mask(g, node);
	size_t e;

	fprintf(stderr, "fmodret function: %s section=%u address=%#llx flags=%#x "
		"definitions=%u strong-descriptions=%u weak-descriptions=%u "
		"linkage=%s address-taken=%s clean=%s candidate=%s "
		"errno-proven=%u/%u syscall=%s propagation-reasons=",
		n->name, (unsigned int)n->shndx, (unsigned long long)n->value,
		n->flags, n->definitions, n->strong_definitions, n->weak_definitions,
		n->flags & FMODRET_FN_LOCAL ? "local" : "global",
		n->flags & FMODRET_FN_ADDRESS_TAKEN ? "yes" : "no",
		!n->clean ? "no" : n->clean_via == NO_NODE ? "atomic" : "constructed",
		!n->clean ? "no:not-clean" : !(n->flags & FMODRET_FN_INTEGER) ?
		"no:pointer-return-relay" : mask ? "no:unproven" :
		n->terminal ? "no:syscall-entry" : "yes",
		error_count(n->good), FMODRET_META_ERRNOS, n->terminal ? "yes" : "no");
	print_rejection_mask(mask);
	fprintf(stderr, "\n");
	if (n->clean_via != NO_NODE) {
		const struct error_call *c = &g->calls[n->clean_via];

		fprintf(stderr, "fmodret clean-source: %s@%#llx callee=%s@%#llx "
			"call=%u metadata=%#zx contract=%s\n", n->name, (unsigned long long)n->value,
			c->callee == NO_NODE ? "<allocator>" : g->nodes[c->callee].name,
			c->callee == NO_NODE ? 0ULL : (unsigned long long)g->nodes[c->callee].value,
			c->ordinal, c->metadata_offset,
			c->flags & FMODRET_CALL_NULL_ERROR ? "allocator-NULL-error" : "errno-return");
	}
	if (n->incomplete)
		fprintf(stderr, "fmodret coverage-rejected: %s@%#llx references=%zu "
			"first-reason=%s section=%s site=%#llx owner=%s\n",
			n->name, (unsigned long long)n->value, n->nr_unmodelled_refs,
			n->reference_reason, n->reference_section,
			(unsigned long long)n->reference_site,
			n->reference_caller == NO_NODE ? "<unknown>" :
			g->nodes[n->reference_caller].name);
	if (!mask || !graph_node_known(n) || !g->audited_text)
		return;
	/* Print immediate failed edges for dirty intermediate functions too, so
	 * a callee rejection can be followed through callers to the blocking fact.
	 */
	for (e = n->incoming; e != NO_NODE; e = g->calls[e].next_in) {
		unsigned int i;

		for (i = 0; i < g->calls[e].nr_cases; i++)
			print_blocked_call(g, &g->calls[e], &g->calls[e].cases[i]);
	}
}

static int derive_clean_graph(struct error_graph *g, int verbose)
{
	size_t *queue, head = 0, tail = 0, i, e, atomic, clean = 0, pointers = 0;
	size_t alloc_calls = 0, alloc_errors = 0, alloc_prefixes = 0, alloc_seeds = 0;

	queue = calloc(g->nr_nodes, sizeof(*queue));
	if (g->nr_nodes && !queue)
		return -ENOMEM;
	for (i = 0; i < g->nr_nodes; i++) {
		struct error_node *n = &g->nodes[i];

		if (n->definitions == 1 &&
		    (n->flags & (FMODRET_FN_INTEGER | FMODRET_FN_ERRPTR)) &&
		    !(n->flags & FMODRET_FN_WEAK) &&
		    (n->flags & FMODRET_FN_CLEAN_SEED)) {
			n->clean = true;
			queue[tail++] = i;
		}
	}
	atomic = tail;
	for (e = 0; e < g->nr_input_calls; e++) {
		struct error_call *c = &g->calls[e];
		struct error_node *caller = &g->nodes[c->caller];

		if ((c->weak_definition && caller->strong_definitions) ||
		    !(c->flags & FMODRET_CALL_NULL_ALLOCATOR))
			continue;
		alloc_calls++;
		if (verbose)
			fprintf(stderr, "fmodret allocation-call: caller=%s callee=%s "
				"call=%u prefix=%s NULL-outcome=%s\n", caller->name,
				c->callee == NO_NODE ? "<allocator>" : g->nodes[c->callee].name,
				c->ordinal, c->flags & FMODRET_CALL_CLEAN_PREFIX ? "clean" : "dirty",
				c->flags & FMODRET_CALL_NULL_ERROR ? "negative-return" : "unknown");
		if (!(c->flags & FMODRET_CALL_NULL_ERROR))
			continue;
		alloc_errors++;
		if (!(c->flags & FMODRET_CALL_CLEAN_PREFIX))
			continue;
		alloc_prefixes++;
		if (!caller->clean && caller->definitions == 1 &&
		    !(caller->flags & FMODRET_FN_WEAK) &&
		    (caller->flags & (FMODRET_FN_INTEGER | FMODRET_FN_ERRPTR))) {
			caller->clean = true;
			caller->clean_via = e;
			queue[tail++] = c->caller;
			alloc_seeds++;
		}
	}
	while (head < tail) {
		size_t node = queue[head++];

		for (e = g->nodes[node].incoming; e != NO_NODE; e = g->calls[e].next_in) {
			struct error_call *c = &g->calls[e];
			struct error_node *caller = &g->nodes[c->caller];

			if (!caller->clean && caller->definitions == 1 &&
			    !(caller->flags & FMODRET_FN_WEAK) &&
			    (caller->flags & (FMODRET_FN_INTEGER | FMODRET_FN_ERRPTR)) &&
			    (c->flags & FMODRET_CALL_CLEAN_PREFIX) && all_errors_returned(c)) {
				caller->clean = true;
				caller->clean_via = e;
				queue[tail++] = c->caller;
			}
		}
	}
	for (i = 0; i < g->nr_nodes; i++) {
		clean += g->nodes[i].clean;
		pointers += g->nodes[i].clean && !(g->nodes[i].flags & FMODRET_FN_INTEGER);
	}
	if (verbose) {
		fprintf(stderr, "fmodret clean: %zu atomic, %zu constructed, %zu total\n",
			atomic, clean - atomic, clean);
		fprintf(stderr, "fmodret clean-types: %zu integers, %zu error-pointer relays\n",
			clean - pointers, pointers);
		fprintf(stderr, "fmodret clean-allocations: %zu allocator calls, "
			"%zu NULL-to-error returns, %zu clean prefixes, %zu seeded callers\n",
			alloc_calls, alloc_errors, alloc_prefixes, alloc_seeds);
	}
	free(queue);
	return 0;
}

static int resolve_error_graph(struct error_graph *g,
			       struct elf_function_list *functions, int verbose)
{
	size_t *queue, head = 0, tail = 0, count, i, e, candidates = 0, proven = 0, roots = 0, proven_roots = 0;
	size_t rejections[ERROR_REJECTION_COUNT] = {};
	uint64_t full[ERROR_WORDS];

	if (!g->nr_nodes)
		return 0;
	queue = calloc(g->nr_nodes, sizeof(*queue));
	if (!queue)
		return -ENOMEM;
	all_errors(full);
	head = tail = 0;
	for (i = 0; i < g->nr_nodes; i++) {
		if (g->nodes[i].terminal)
			memcpy(g->nodes[i].good, full, sizeof(full));
		queue[tail++] = i;
		g->nodes[i].queued = true;
	}
	count = tail;
	tail %= g->nr_nodes;
	while (count) {
		size_t node = queue[head];
		struct error_node *n = &g->nodes[node];
		uint64_t next[ERROR_WORDS], edge[ERROR_WORDS];
		unsigned int w;

		head = (head + 1) % g->nr_nodes;
		count--;
		n->queued = false;
		if (n->terminal || !g->audited_text || !graph_node_known(n) ||
		    n->incoming == NO_NODE)
			continue;
		memcpy(next, full, sizeof(next));
		for (e = n->incoming; e != NO_NODE; e = g->calls[e].next_in) {
			struct error_call *c = &g->calls[e];

			error_preimage(c, g->nodes[c->caller].good, edge);
			for (w = 0; w < ERROR_WORDS; w++)
				next[w] &= edge[w];
		}
		if (!memcmp(next, n->good, sizeof(next)))
			continue;
		memcpy(n->good, next, sizeof(next));
		for (e = n->outgoing; e != NO_NODE; e = g->calls[e].next_out) {
			size_t callee = g->calls[e].callee;

			if (callee == NO_NODE || g->nodes[callee].queued)
				continue;
			queue[tail] = callee;
			tail = (tail + 1) % g->nr_nodes;
			count++;
			g->nodes[callee].queued = true;
		}
	}
	for (i = 0; i < functions->nr; i++) {
		struct elf_function *f = &functions->functions[i];
		struct error_node *n = &g->nodes[f->node];

		/* Syscall entries are fmod_ret targets by their static rules and
		 * stay proof roots; tag only the functions the proof adds.
		 */
		f->candidate = n->clean && (n->flags & FMODRET_FN_INTEGER) &&
			       graph_node_known(n) && !n->terminal &&
			       !memcmp(n->good, full, sizeof(full));
	}
	if (verbose) {
		for (i = 0; i < g->nr_nodes; i++) {
			const struct error_node *n = &g->nodes[i];

			roots += n->terminal;
			if (n->clean && (n->flags & FMODRET_FN_INTEGER)) {
				unsigned int mask = error_rejection_mask(g, i);

				candidates++;
				proven += !mask;
				proven_roots += !mask && n->terminal;
				if (mask)
					rejections[primary_rejection(mask)]++;
			}
			print_function_resolution(g, i);
		}
		fprintf(stderr, "fmodret propagation: %zu clean candidate bodies, "
			"%zu failed, %zu passed (%zu of them syscall entries, not tagged); "
			"%zu syscall entries\n",
			candidates, candidates - proven, proven, proven_roots, roots);
		for (i = 1; i < ERROR_REJECTION_COUNT; i++)
			fprintf(stderr, "fmodret rejection-primary: %s=%zu\n",
				error_rejection_names[i], rejections[i]);
	}
	free(queue);
	return 0;
}

static int read_error_metadata(Elf *elf, Elf_Scn *scn, size_t ptr_size,
			       unsigned int encoding, struct elf_function_list *functions,
			       int verbose)
{
	struct error_graph g = {};
	unsigned char *buf = NULL;
	size_t *refs = NULL;
	GElf_Shdr shdr;
	size_t i;
	int err;

	if (!gelf_getshdr(scn, &shdr))
		return -1;
	if (shdr.sh_size % ptr_size || shdr.sh_size > SIZE_MAX / sizeof(*refs))
		return -EINVAL;
	err = init_error_graph(&g, functions);
	if (err)
		goto out;
	err = copy_section_data(scn, &shdr, &buf);
	if (err)
		goto out;
	refs = malloc(shdr.sh_size / ptr_size * sizeof(*refs));
	if (shdr.sh_size && !refs) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < shdr.sh_size / ptr_size; i++)
		refs[i] = NO_NODE;
	err = graph_relocations(elf, functions, &g, elf_ndxscn(scn), &shdr,
				buf, refs, ptr_size, encoding, false);
	if (err)
		goto out;
	err = parse_error_graph(elf, functions, &g, buf, shdr.sh_size, refs, ptr_size,
				encoding, verbose);
	if (err)
		goto out;
	select_error_descriptions(&g);
	if (verbose) {
		size_t exported = 0;

		for (i = 0; i < g.nr_nodes; i++)
			exported += !!(g.nodes[i].flags & FMODRET_FN_EXPORTED);
		fprintf(stderr, "fmodret exports: %zu exported functions\n", exported);
	}
	err = resolve_callback_arguments(&g, verbose);
	if (err)
		goto out;
	err = graph_relocations(elf, functions, &g, elf_ndxscn(scn), &shdr,
				buf, refs, ptr_size, encoding, true);
	if (err)
		goto out;
	err = derive_clean_graph(&g, verbose);
	if (!err)
		err = resolve_error_graph(&g, functions, verbose);
out:
	free(refs);
	free(buf);
	free_error_graph(&g);
	return err;
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
	size_t i = 0;

	qsort(functions->functions, functions->nr, sizeof(*functions->functions),
	      cmp_elf_function_name);
	while (i < functions->nr) {
		struct fmodret_symbol *symbol;
		size_t nr_candidates = 0;
		size_t nr_traceable = 0;
		size_t j;
		int err;

		for (j = i; j < functions->nr &&
		     !strcmp(functions->functions[i].name,
			     functions->functions[j].name); j++) {
			nr_candidates += functions->functions[j].candidate;
			nr_traceable += functions->functions[j].traceable;
		}

		if (!nr_candidates) {
			i = j;
			continue;
		}
		err = append_fmodret_symbol(symbols,
					    functions->functions[i].name);
		if (err)
			return err;
		symbol = &symbols->symbols[symbols->nr - 1];
		symbol->nr_functions = j - i;
		symbol->nr_candidates = nr_candidates;
		symbol->nr_traceable = nr_traceable;
		i = j;
	}
	return 0;
}

static int read_fmodret_candidates(Elf *elf,
				   struct fmodret_symbol_list *list, int verbose)
{
	struct elf_function_list functions = {};
	Elf_Scn *candidate_scn = NULL;
	unsigned char *ident;
	size_t shstrndx;
	size_t ptr_size;
	int err = -1;

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
	if (!candidate_scn) {
		err = 0;
		goto out;
	}
	err = read_error_metadata(elf, candidate_scn, ptr_size, ident[EI_DATA], &functions, verbose);
	if (err)
		goto out;

	err = read_ftrace_sites(elf, shstrndx, ptr_size, ident[EI_DATA],
				&functions);
	if (err)
		goto out;
	if (verbose) {
		size_t i;

		for (i = 0; i < functions.nr; i++) {
			const struct elf_function *f = &functions.functions[i];

			if (f->candidate && !f->traceable)
				fprintf(stderr, "fmodret attach-rejected: %s section=%u address=%#llx reason=%s\n",
					f->name, (unsigned int)f->shndx,
					(unsigned long long)f->value, f->attach_rejection);
		}
	}
	err = summarize_elf_functions(&functions, list);
out:
	if (err == -1)
		fprintf(stderr, "failed to read %s: %s\n",
			FMODRET_CANDIDATES_SECTION, elf_errmsg(-1));
	free_elf_functions(&functions);
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

static int find_fmodret_ids(Elf *elf, const struct btf *btf,
			    struct fmodret_id_pair **pairs, size_t *nr_pairs,
			    int verbose)
{
	struct fmodret_id_pair *result;
	struct fmodret_symbol_list list = {};
	size_t nr_result = 0;
	size_t nr_not_attachable = 0;
	size_t nr_without_btf = 0;
	size_t i;
	int err;

	*pairs = NULL;
	*nr_pairs = 0;
	err = read_fmodret_candidates(elf, &list, verbose);
	if (err)
		goto out_symbols;

	result = calloc(list.nr, sizeof(*result));
	if (list.nr && !result) {
		err = -ENOMEM;
		goto out_symbols;
	}

	for (i = 0; i < list.nr; i++) {
		const struct fmodret_symbol *symbol = &list.symbols[i];
		int id;

		if (symbol->nr_functions != 1 ||
		    symbol->nr_traceable != symbol->nr_functions ||
		    symbol->nr_candidates != symbol->nr_functions) {
			nr_not_attachable++;
			if (verbose)
				fprintf(stderr,
					"fmodret: rejected %s: reason=%s %zu/%zu candidate "
					"definitions, %zu/%zu traceable definitions\n",
					symbol->name,
					symbol->nr_candidates != symbol->nr_functions ?
					"ambiguous-or-unproven-definitions" : "not-attachable",
					symbol->nr_candidates,
					symbol->nr_functions, symbol->nr_traceable,
					symbol->nr_functions);
			continue;
		}
		id = 0;
		for (uint32_t type_id = btf__base_btf(btf) ?
		     btf__type_cnt(btf__base_btf(btf)) : 1; type_id < btf__type_cnt(btf); type_id++) {
			const struct btf_type *type = btf__type_by_id(btf, type_id);

			if (!btf_is_func(type) ||
			    strcmp(btf__name_by_offset(btf, type->name_off), symbol->name))
				continue;
			if (id) {
				id = -EINVAL;
				break;
			}
			id = type_id;
		}
		if (id <= 0) {
			nr_without_btf++;
			if (verbose)
				fprintf(stderr,
					"fmodret: rejected %s: reason=no-BTF-FUNC-ID\n",
					symbol->name);
			continue;
		}

		result[nr_result++].id = id;
		if (verbose)
			fprintf(stderr, "fmodret: added %s: BTF ID %d\n",
				symbol->name, id);
	}

	if (nr_result)
		qsort(result, nr_result, sizeof(*result), cmp_fmodret_ids);
	if (verbose)
		fprintf(stderr,
			"fmodret: %zu candidate names, %zu added, %zu not added "
			"(%zu unattachable or ambiguous, %zu without BTF)\n",
			list.nr, nr_result, list.nr - nr_result,
			nr_not_attachable, nr_without_btf);

	free_fmodret_symbols(&list);
	*pairs = result;
	*nr_pairs = nr_result;
	return 0;

out_symbols:
	free_fmodret_symbols(&list);
	return err;
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

int fmodret_analyse_collect(Elf *elf, const struct btf *btf,
			     struct btf_id_set8 **result, int verbose)
{
	struct fmodret_id_pair *pairs = NULL;
	struct btf_id_set8 *set;
	size_t nr, size, i;
	int err;

	*result = NULL;
	err = find_fmodret_ids(elf, btf, &pairs, &nr, verbose);
	if (err)
		return err;
	if (!nr) {
		free(pairs);
		return 0;
	}
	if (nr > UINT32_MAX || nr > (SIZE_MAX - sizeof(*set)) / sizeof(set->pairs[0])) {
		free(pairs);
		return -E2BIG;
	}
	size = sizeof(*set) + nr * sizeof(set->pairs[0]);
	set = calloc(1, size);
	if (!set) {
		free(pairs);
		return -ENOMEM;
	}
	set->cnt = nr;
	for (i = 0; i < nr; i++) {
		set->pairs[i].id = pairs[i].id;
		set->pairs[i].flags = pairs[i].flags;
	}
	free(pairs);
	*result = set;
	return 0;
}
