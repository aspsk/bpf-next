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

#define FMODRET_CANDIDATES_SECTION ".BTF_fmodret_candidates"

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define ELFDATANATIVE ELFDATA2LSB
#elif __BYTE_ORDER == __BIG_ENDIAN
# define ELFDATANATIVE ELFDATA2MSB
#else
# error "Unknown machine endianness!"
#endif

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

	for (i = 0; i < sizeof(sections) / sizeof(sections[0]); i++) {
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

struct error_call {
	size_t caller, callee;
	size_t next_in, next_out, metadata_offset;
	unsigned int flags, nr_cases, ordinal;
	bool weak_definition;
	struct error_case *cases;
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
	bool clean, terminal, incomplete, queued;
	uint64_t good[ERROR_WORDS];
};

struct error_graph {
	struct error_node *nodes;
	struct error_call *calls;
	size_t nr_nodes, nr_calls, capacity;
	size_t nr_records, nr_defined_records, nr_reference_records;
	size_t nr_overridden_weak, nr_discarded_calls;
	bool audited_text;
};

static void free_error_graph(struct error_graph *g)
{
	size_t i;

	for (i = 0; i < g->nr_calls; i++)
		free(g->calls[i].cases);
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

	if (!nr_cases || nr_cases > FMODRET_META_ERRNOS ||
	    (flags & ~FMODRET_CALL_CLEAN_PREFIX))
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
		.next_in = NO_NODE, .next_out = NO_NODE };
	c->cases = calloc(nr_cases, sizeof(*c->cases));
	if (!c->cases)
		return -ENOMEM;
	/* Count immediately so the common teardown also handles malformed cases. */
	g->nr_calls++;
	for (i = 0; i < nr_cases; i++, p += FMODRET_META_CASE_SIZE) {
		struct error_case *e = &c->cases[i];

		e->first = (int32_t)read_elf_value(p, 4, encoding);
		e->last = (int32_t)read_elf_value(p + 4, 4, encoding);
		e->kind = read_elf_value(p + 8, 4, encoding);
		e->replacement = (int32_t)read_elf_value(p + 12, 4, encoding);
		if (e->first != expected || e->last < e->first || e->last >= 0 ||
		    e->kind > FMODRET_ERROR_CONSTANT ||
		    (e->kind == FMODRET_ERROR_CONSTANT &&
		     (e->replacement >= 0 || e->replacement < -FMODRET_META_ERRNOS)) ||
		    (e->kind != FMODRET_ERROR_CONSTANT && e->replacement))
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

/* Read pointer relocations before parsing records, then audit the other ELF
 * references after the call graph exists. An unmodelled caller blocks proof.
 * In particular, assembly and objects built without the plugin are not assumed
 * to propagate errors. Actual syscall table entries are the only roots.
 */
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
	struct symbol_range roots[4] = {}, skip[2] = {};
	Elf_Scn *scn = NULL;
	GElf_Ehdr ehdr;
	size_t shstrndx, i;
	int err;

	if (!gelf_getehdr(elf, &ehdr))
		return -1;
	if (elf_getshdrstrndx(elf, &shstrndx))
		return -1;
	if (audit) {
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
			      !strcmp(name, "_error_injection_whitelist")))
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
			if (handled)
				continue;
			if (!described_call(g, caller, node))
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
	};
	size_t i;

	fprintf(stderr, "fmodret input: %s section=%u address=%#llx record=%#zx flags=%#x [",
		node ? node->name : "<unresolved reference>",
		node ? (unsigned int)node->shndx : 0,
		node ? (unsigned long long)node->value : 0, offset, flags);
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
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
		unsigned int flags, calls, length, i;

		if (size - offset < FMODRET_META_HEADER_SIZE(ptr_size) ||
		    read_elf_value(buf + offset, 4, encoding) != FMODRET_META_MAGIC ||
		    read_elf_value(buf + offset + 4, 4, encoding) != FMODRET_META_VERSION)
			goto invalid;
		length = read_elf_value(buf + offset + 8, 4, encoding);
		flags = read_elf_value(buf + offset + 12, 4, encoding);
		if (length < FMODRET_META_HEADER_SIZE(ptr_size) || length > size - offset ||
		    length % ptr_size || flags & ~FMODRET_FN_FLAGS ||
		    read_elf_value(buf + offset + 20 + ptr_size, 4, encoding))
			goto invalid;
		end = offset + length;
		calls = read_elf_value(buf + offset + 16 + ptr_size, 4, encoding);
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
				n->flags |= flags & FMODRET_FN_ESCAPED;
			} else {
				g->nodes[node].flags |= flags & FMODRET_FN_ESCAPED;
			}
		}
		if (calls && !(flags & FMODRET_FN_DEFINED))
			goto invalid;
		pos = offset + FMODRET_META_HEADER_SIZE(ptr_size);
		for (i = 0; i < calls; i++) {
			unsigned int nr_cases, call_flags;
			size_t callee;
			int err;

			if (end - pos < FMODRET_META_CALL_SIZE(ptr_size))
				goto invalid;
			callee = metadata_reference(elf, functions, buf, refs, pos, ptr_size, encoding);
			call_flags = read_elf_value(buf + pos + ptr_size, 4, encoding);
			nr_cases = read_elf_value(buf + pos + ptr_size + 4, 4, encoding);
			pos += FMODRET_META_CALL_SIZE(ptr_size);
			if (nr_cases > (end - pos) / FMODRET_META_CASE_SIZE)
				goto invalid;
			err = add_error_call(g, node, callee, call_flags, nr_cases, buf + pos,
					     encoding, pos - FMODRET_META_CALL_SIZE(ptr_size), i + 1,
					     flags & FMODRET_FN_WEAK);
			if (err)
				return err;
			pos += nr_cases * FMODRET_META_CASE_SIZE;
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
			g->nr_overridden_weak += n->weak_definitions;
		} else {
			n->flags |= n->weak_flags;
			n->definitions = n->weak_definitions;
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
	return n->definitions == 1 && (n->flags & FMODRET_FN_INTEGER) &&
	       !(n->flags & (FMODRET_FN_ESCAPED | FMODRET_FN_WEAK)) && !n->incomplete;
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

static bool all_errors_known(const struct error_call *c)
{
	unsigned int i;

	for (i = 0; i < c->nr_cases; i++)
		if (!c->cases[i].kind)
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

		if (!e->kind || (e->kind == FMODRET_ERROR_CONSTANT &&
				!error_bit(parent, e->replacement)))
			continue;
		for (word = first / 64; word <= last / 64; word++) {
			uint64_t mask = UINT64_MAX;

			if (word == first / 64)
				mask &= UINT64_MAX << (first % 64);
			if (word == last / 64)
				mask &= UINT64_MAX >> (63 - last % 64);
			result[word] |= mask & (e->kind == FMODRET_ERROR_IDENTITY ? parent[word] : UINT64_MAX);
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
	if (!(n->flags & FMODRET_FN_INTEGER))
		reasons |= 1U << ERROR_NON_INTEGER;
	if (n->flags & FMODRET_FN_WEAK)
		reasons |= 1U << ERROR_WEAK;
	if (n->flags & FMODRET_FN_ESCAPED)
		reasons |= 1U << ERROR_ESCAPED;
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
	int sample = c->first;

	if (c->kind == FMODRET_ERROR_IDENTITY) {
		missing = missing_errors(caller->good, c->first, c->last, &sample);
	} else if (c->kind == FMODRET_ERROR_CONSTANT) {
		missing = error_bit(caller->good, c->replacement) ? 0 :
			  c->last - c->first + 1;
	} else {
		missing = c->last - c->first + 1;
	}
	if (!missing)
		return;
	fprintf(stderr, "fmodret call-rejected: callee=%s@%#llx caller=%s@%#llx "
		"call=%u metadata=%#zx prefix=%s input=[%d,%d] "
		"unproven=%u sample=%d map=",
		callee->name, (unsigned long long)callee->value,
		caller->name, (unsigned long long)caller->value,
		call->ordinal, call->metadata_offset,
		call->flags & FMODRET_CALL_CLEAN_PREFIX ? "clean" : "dirty",
		c->first, c->last, missing, sample);
	if (c->kind == FMODRET_ERROR_IDENTITY)
		fprintf(stderr, "identity caller-errno=%d", sample);
	else if (c->kind == FMODRET_ERROR_CONSTANT)
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
		"linkage=%s clean=%s candidate=%s "
		"errno-proven=%u/%u syscall=%s propagation-reasons=",
		n->name, (unsigned int)n->shndx, (unsigned long long)n->value,
		n->flags, n->definitions, n->strong_definitions, n->weak_definitions,
		n->flags & FMODRET_FN_LOCAL ? "local" : "global",
		!n->clean ? "no" : n->clean_via == NO_NODE ? "atomic" : "constructed",
		n->clean && !mask ? "yes" : !n->clean ? "no:not-clean" : "no:unproven",
		error_count(n->good), FMODRET_META_ERRNOS, n->terminal ? "yes" : "no");
	print_rejection_mask(mask);
	fprintf(stderr, "\n");
	if (n->clean_via != NO_NODE) {
		const struct error_call *c = &g->calls[n->clean_via];

		fprintf(stderr, "fmodret clean-source: %s@%#llx callee=%s@%#llx "
			"call=%u metadata=%#zx\n", n->name, (unsigned long long)n->value,
			g->nodes[c->callee].name, (unsigned long long)g->nodes[c->callee].value,
			c->ordinal, c->metadata_offset);
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

static int resolve_error_graph(struct error_graph *g,
			       struct elf_function_list *functions, int verbose)
{
	size_t *queue, head = 0, tail = 0, count = 0;
	size_t i, e, atomic = 0, clean = 0, proven = 0, roots = 0, described = 0;
	size_t candidates = 0, failed = 0, local = 0, global = 0;
	size_t rejections[ERROR_REJECTION_COUNT] = {};
	uint64_t full[ERROR_WORDS];

	for (i = 0; i < g->nr_nodes; i++)
		described += g->nodes[i].definitions != 0;
	if (verbose)
		fprintf(stderr, "fmodret input: %zu function records (%zu definitions, "
			"%zu references), %zu described bodies, %zu ELF bodies, %zu calls\n",
			g->nr_records, g->nr_defined_records, g->nr_reference_records,
			described, g->nr_nodes, g->nr_calls);
	if (verbose)
		fprintf(stderr, "fmodret definitions: %zu overridden weak descriptions, "
			"%zu discarded call sites\n", g->nr_overridden_weak, g->nr_discarded_calls);
	if (!g->nr_nodes) {
		if (verbose) {
			fprintf(stderr, "fmodret clean: 0 atomic, 0 constructed, 0 total\n");
			fprintf(stderr, "fmodret propagation: 0 clean candidate bodies, "
				"0 failed, 0 passed; 0 syscall entries\n");
		}
		return 0;
	}
	queue = calloc(g->nr_nodes, sizeof(*queue));
	if (!queue)
		return -ENOMEM;
	all_errors(full);
	/* Least fixed point: unseeded recursive components never become clean. */
	for (i = 0; i < g->nr_nodes; i++) {
		struct error_node *n = &g->nodes[i];

		if (n->definitions == 1 && !(n->flags & FMODRET_FN_WEAK) &&
		    (n->flags & FMODRET_FN_CLEAN_SEED)) {
			n->clean = true;
			queue[tail++] = i;
		}
	}
	atomic = tail;
	while (head < tail) {
		size_t node = queue[head++];

		for (e = g->nodes[node].incoming; e != NO_NODE; e = g->calls[e].next_in) {
			struct error_call *c = &g->calls[e];
			struct error_node *caller = &g->nodes[c->caller];

			if (!caller->clean && caller->definitions == 1 &&
			    !(caller->flags & FMODRET_FN_WEAK) &&
			    (caller->flags & FMODRET_FN_INTEGER) &&
			    (c->flags & FMODRET_CALL_CLEAN_PREFIX) && all_errors_known(c)) {
				caller->clean = true;
				caller->clean_via = e;
				queue[tail++] = c->caller;
			}
		}
	}
	/* Separate least fixed point of errno sets reaching userspace along EVERY
	 * incoming edge. Cleanup effects are absent from this computation.
	 */
	head = tail = 0;
	for (i = 0; i < g->nr_nodes; i++) {
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
		if (!g->audited_text || !graph_node_known(n) ||
		    (!n->terminal && n->incoming == NO_NODE))
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
	for (i = 0; i < g->nr_nodes; i++) {
		clean += g->nodes[i].clean;
		roots += g->nodes[i].terminal;
		if (g->nodes[i].clean) {
			bool passed = graph_node_known(&g->nodes[i]) &&
				      !memcmp(g->nodes[i].good, full, sizeof(full));

			candidates++;
			local += !!(g->nodes[i].flags & FMODRET_FN_LOCAL);
			global += !(g->nodes[i].flags & FMODRET_FN_LOCAL);
			proven += passed;
			failed += !passed;
			if (!passed)
				rejections[primary_rejection(error_rejection_mask(g, i))]++;
		}
	}
	for (i = 0; i < functions->nr; i++) {
		struct elf_function *f = &functions->functions[i];
		struct error_node *n = &g->nodes[f->node];

		f->candidate = n->clean &&
			       graph_node_known(n) && !memcmp(n->good, full, sizeof(full));
	}
	if (verbose) {
		fprintf(stderr, "fmodret clean: %zu atomic, %zu constructed, %zu total\n",
			atomic, clean - atomic, clean);
		fprintf(stderr, "fmodret candidates: %zu clean bodies (%zu local, %zu global)\n",
			candidates, local, global);
		fprintf(stderr, "fmodret propagation: %zu clean candidate bodies, "
			"%zu failed, %zu passed; %zu syscall entries\n",
			candidates, failed, proven, roots);
		for (i = 1; i < ERROR_REJECTION_COUNT; i++)
			fprintf(stderr, "fmodret rejection-primary: %s=%zu\n",
				error_rejection_names[i], rejections[i]);
		for (i = 0; i < g->nr_nodes; i++)
			print_function_resolution(g, i);
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
	err = graph_relocations(elf, functions, &g, elf_ndxscn(scn), &shdr,
				buf, refs, ptr_size, encoding, true);
	if (err)
		goto out;
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

static int read_fmodret_candidates(const char *path,
				   struct fmodret_symbol_list *list, int verbose)
{
	struct elf_function_list functions = {};
	Elf_Scn *candidate_scn = NULL;
	unsigned char *ident;
	size_t shstrndx;
	size_t ptr_size;
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
	if (!candidate_scn) {
		if (verbose) {
			fprintf(stderr, "fmodret input: 0 function records, %zu ELF functions; no metadata section\n",
				functions.nr);
			fprintf(stderr, "fmodret clean: 0 atomic, 0 constructed, 0 total\n");
			fprintf(stderr, "fmodret propagation: 0 clean candidate bodies, "
				"0 failed, 0 passed; 0 syscall entries\n");
		}
		goto attachability;
	}
	err = read_error_metadata(elf, candidate_scn, ptr_size, ident[EI_DATA], &functions, verbose);
	if (err)
		goto out;

attachability:
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
		fprintf(stderr, "failed to read %s from %s: %s\n",
			FMODRET_CANDIDATES_SECTION, path, elf_errmsg(-1));
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

static int find_fmodret_ids(const char *elf_file, const struct btf *btf,
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
	err = read_fmodret_candidates(elf_file, &list, verbose);
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

		/*
		 * BTF lookup is name-based and cannot select one of several local
		 * ELF functions with the same name. Only admit the name when every
		 * such ELF function is mechanically attachable and independently
		 * marked as a candidate.
		 */
		if (!symbol->nr_functions ||
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
		id = btf__find_by_name_kind_own(btf, symbol->name,
						BTF_KIND_FUNC);
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

static int write_set_data(const char *path, uint32_t *words,
			  size_t nr_words, int elf_encoding)
{
	FILE *file;
	size_t i;
	int err = 0;

	if (elf_encoding != ELFDATA2LSB && elf_encoding != ELFDATA2MSB)
		return -EINVAL;
	if (elf_encoding != ELFDATANATIVE)
		for (i = 0; i < nr_words; i++)
			words[i] = __builtin_bswap32(words[i]);

	file = fopen(path, "wb");
	if (!file)
		return -errno;
	if (fwrite(words, sizeof(*words), nr_words, file) != nr_words)
		err = -EIO;
	if (fclose(file) && !err)
		err = -EIO;
	if (err)
		unlink(path);
	return err;
}

int fmodret_ids_generate(const char *elf_path, const struct btf *btf,
			 int elf_encoding, const char *out_path,
			 int verbose)
{
	struct fmodret_id_pair *pairs = NULL;
	size_t nr_pairs, nr_words;
	uint32_t *words;
	int err;

	err = find_fmodret_ids(elf_path, btf, &pairs, &nr_pairs, verbose);
	if (err)
		return err;
	if (!nr_pairs) {
		free(pairs);
		if (unlink(out_path) && errno != ENOENT)
			return -errno;
		return 0;
	}

	err = build_set_data(pairs, nr_pairs, &words, &nr_words);
	free(pairs);
	if (err)
		return err;
	err = write_set_data(out_path, words, nr_words, elf_encoding);
	free(words);
	if (err)
		fprintf(stderr, "failed to write %s: %s\n", out_path,
			strerror(-err));
	return err;
}
