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

struct symbol_range {
	GElf_Sym start;
	GElf_Addr end;
	bool valid;
};


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


static void free_error_graph(struct error_graph *g)
{
	size_t i;

	for (i = 0; i < g->nr_calls; i++)
		free(g->calls[i].cases);
	free(g->calls);
	free(g->nodes);
}


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
		{ FMODRET_FN_ERRPTR, "error_pointer" },
		{ FMODRET_FN_RET64, "integer_return64" },
		{ FMODRET_FN_ADDRESS_TAKEN, "address_taken" },
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
		if (params || (calls && !(flags & FMODRET_FN_DEFINED)))
			goto invalid;
		pos = offset + FMODRET_META_HEADER_SIZE(ptr_size);
		for (i = 0; i < calls; i++) {
			unsigned int nr_cases, call_flags, callee_param, bindings;
			size_t callee, call_offset = pos;
			int err;

			if (end - pos < FMODRET_META_CALL_SIZE(ptr_size))
				goto invalid;
			callee = metadata_reference(elf, functions, buf, refs, pos, ptr_size, encoding);
			call_flags = read_elf_value(buf + pos + ptr_size, 4, encoding);
			nr_cases = read_elf_value(buf + pos + ptr_size + 4, 4, encoding);
			callee_param = read_elf_value(buf + pos + ptr_size + 8, 4, encoding);
			bindings = read_elf_value(buf + pos + ptr_size + 12, 4, encoding);
			if (callee_param != FMODRET_NO_PARAM || bindings)
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


int fmodret_analyse(Elf *elf, int verbose)
{
	struct elf_function_list functions = {};
	struct error_graph g = {};
	unsigned char *buf = NULL;
	size_t *refs = NULL;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	GElf_Ehdr ehdr;
	size_t shstrndx, ptr_size, i;
	int err;

	if (!gelf_getehdr(elf, &ehdr) || elf_getshdrstrndx(elf, &shstrndx))
		return -EINVAL;
	err = find_section(elf, shstrndx, FMODRET_CANDIDATES_SECTION, &scn);
	if (err || !scn)
		return err;
	if (!gelf_getshdr(scn, &shdr))
		return -EINVAL;
	ptr_size = gelf_getclass(elf) == ELFCLASS64 ? 8 : 4;
	if (shdr.sh_size % ptr_size || shdr.sh_size > SIZE_MAX / sizeof(*refs))
		return -EINVAL;
	err = collect_elf_functions(elf, &functions);
	if (err)
		goto out;
	err = init_error_graph(&g, &functions);
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
	err = graph_relocations(elf, &functions, &g, elf_ndxscn(scn), &shdr,
				buf, refs, ptr_size, ehdr.e_ident[EI_DATA], false);
	if (err)
		goto out;
	err = parse_error_graph(elf, &functions, &g, buf, shdr.sh_size, refs, ptr_size,
				ehdr.e_ident[EI_DATA], verbose);
	if (err)
		goto out;
	select_error_descriptions(&g);
	err = graph_relocations(elf, &functions, &g, elf_ndxscn(scn), &shdr,
				buf, refs, ptr_size, ehdr.e_ident[EI_DATA], true);
	if (!err && verbose)
		fprintf(stderr, "fmodret descriptions: %zu records, %zu linked bodies, %zu calls\n",
			g.nr_records, g.nr_nodes, g.nr_calls);
out:
	free(refs);
	free(buf);
	free_error_graph(&g);
	free_elf_functions(&functions);
	return err;
}
