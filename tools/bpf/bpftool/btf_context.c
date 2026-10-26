// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "../../lib/bpf/btf_context.h"
#include "json_writer.h"
#include "main.h"

struct context_ref { __u32 target, tag; };

static int compare_context_refs(const void *a, const void *b)
{
	const struct context_ref *x = a, *y = b;

	if (x->target != y->target)
		return x->target < y->target ? -1 : 1;
	return x->tag < y->tag ? -1 : x->tag != y->tag;
}

struct context_var {
	const char *name;
	__u32 type;
};

struct context_token {
	const char *name;
};

struct context_printer {
	const struct btf *btf;
	struct btf_dump *dump;
	struct context_var *vars;
	unsigned int nr_vars, nr_tokens;
	struct context_token *tokens;
	bool *capabilities;
	char *text;
	size_t len, capacity;
	int error;
};

struct context_location {
	__u32 type;
	long long offset;
	bool pointer;
	char name[BTF_CONTEXT_TAG_MAX];
};

static void context_printf(void *ctx, const char *fmt, va_list args)
{
	struct context_printer *p = ctx;
	va_list copy;
	char *text;
	int n;

	if (p->error)
		return;
	va_copy(copy, args);
	n = vsnprintf(NULL, 0, fmt, copy);
	va_end(copy);
	if (n < 0 || (size_t)n >= SIZE_MAX - p->len) {
		p->error = -EOVERFLOW;
		return;
	}
	if (p->len + n + 1 > p->capacity) {
		size_t capacity = p->len + n + 1;

		if (p->capacity <= SIZE_MAX / 2 && capacity < p->capacity * 2)
			capacity = p->capacity * 2;
		text = realloc(p->text, capacity);
		if (!text) {
			p->error = -ENOMEM;
			return;
		}
		p->text = text;
		p->capacity = capacity;
	}
	vsnprintf(p->text + p->len, p->capacity - p->len, fmt, args);
	p->len += n;
}

static const char *context_type(struct context_printer *p, __u32 id, const char *name)
{
	LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts, .field_name = name);

	p->len = 0;
	p->error = 0;
	if (btf_dump__emit_type_decl(p->dump, id, &opts) || p->error)
		return NULL;
	return p->text;
}

static int compare_context_vars(const void *a, const void *b)
{
	const struct context_var *x = a, *y = b;

	return strcmp(x->name, y->name);
}

static const struct btf_type *context_unqualified(const struct btf *btf, __u32 *id)
{
	const struct btf_type *t;
	unsigned int depth;

	for (depth = 0; depth < 32 && *id; ++depth) {
		t = btf__type_by_id(btf, *id);
		if (!t)
			return NULL;
		if (!btf_is_mod(t) && !btf_is_typedef(t) && !btf_is_type_tag(t))
			return t;
		*id = t->type;
	}
	return NULL;
}

static bool context_member(struct context_printer *p, struct context_location *loc,
			   unsigned int depth, bool pointer_field);

static bool context_location(struct context_printer *p, const struct btf_type *proto,
			     const char **expr, struct context_location *loc,
			     unsigned int depth)
{
	const char *s = *expr;
	char *end;

	if (depth > 24)
		return false;
	if (!strncmp(s, "arg(", 4)) {
		const struct btf_type *t;
		const struct btf_param *param;
		unsigned long arg;
		__u32 id;
		int n;

		errno = 0;
		arg = strtoul(s + 4, &end, 10);
		if (errno || end == s + 4 || *end != ')' || !proto || arg >= btf_vlen(proto))
			return false;
		param = &btf_params(proto)[arg];
		id = param->type;
		t = context_unqualified(p->btf, &id);
		if (!t || !btf_is_ptr(t))
			return false;
		loc->type = t->type;
		loc->pointer = true;
		if (!param->name_off)
			return false;
		n = snprintf(loc->name, sizeof(loc->name), "%s",
			     btf__name_by_offset(p->btf, param->name_off));
		if (n < 0 || (size_t)n >= sizeof(loc->name))
			return false;
		*expr = end + 1;
		return true;
	}
	if (!strncmp(s, "global(", 7)) {
		const char *close = strchr(s + 7, ')');
		struct context_var key, *v;
		unsigned int i;
		size_t len;

		if (!close || close == s + 7)
			return false;
		len = close - s - 7;
		if (len >= sizeof(loc->name))
			return false;
		memcpy(loc->name, s + 7, len);
		loc->name[len] = 0;
		key.name = loc->name;
		v = bsearch(&key, p->vars, p->nr_vars, sizeof(*p->vars), compare_context_vars);
		if (!v)
			return false;
		i = v - p->vars;
		if ((i && !strcmp(v[-1].name, v->name)) ||
		    (i + 1 < p->nr_vars && !strcmp(v[1].name, v->name)))
			return false;
		loc->type = v->type;
		*expr = close + 1;
		return true;
	}
	if (!strncmp(s, "add(", 4)) {
		long long offset;

		*expr = s + 4;
		if (!context_location(p, proto, expr, loc, depth + 1) || **expr != ',')
			return false;
		errno = 0;
		offset = strtoll(*expr + 1, &end, 10);
		if (errno || end == *expr + 1 || *end != ')' ||
		    (offset > 0 && loc->offset > LLONG_MAX - offset) ||
		    (offset < 0 && loc->offset < LLONG_MIN - offset))
			return false;
		loc->offset += offset;
		*expr = end + 1;
		return true;
	}
	if (!strncmp(s, "load(", 5)) {
		const struct btf_type *t;
		__u32 id;

		*expr = s + 5;
		if (!context_location(p, proto, expr, loc, depth + 1) || **expr != ')' ||
		    !context_member(p, loc, depth + 1, true))
			return false;
		id = loc->type;
		t = context_unqualified(p->btf, &id);
		if (!t || !btf_is_ptr(t))
			return false;
		loc->type = t->type;
		loc->offset = 0;
		loc->pointer = true;
		++*expr;
		return true;
	}
	return false;
}

/* Resolve an object address to a unique capability/member path. Do not pick
 * one of several overlapping union members just because it has a useful type.
 */
static bool context_member(struct context_printer *p, struct context_location *loc,
			   unsigned int depth, bool pointer_field)
{
	const struct btf_type *t;
	__u32 id = loc->type;
	unsigned int i, matches = 0;
	struct context_location found = {};

	if (depth > 24 || loc->offset < 0 || !(t = context_unqualified(p->btf, &id)))
		return false;
	if (!loc->offset && (pointer_field ? btf_is_ptr(t) : p->capabilities[id]))
		return true;
	if (btf_is_array(t)) {
		const struct btf_array *a = btf_array(t);
		long long size = btf__resolve_size(p->btf, a->type);
		char name[sizeof(loc->name)];
		int n;

		if (size <= 0 || loc->offset / size >= a->nelems)
			return false;
		if (loc->pointer)
			n = snprintf(name, sizeof(name), "(*%s)[%lld]", loc->name, loc->offset / size);
		else
			n = snprintf(name, sizeof(name), "%s[%lld]", loc->name, loc->offset / size);
		if (n < 0 || (size_t)n >= sizeof(name))
			return false;
		strcpy(loc->name, name);
		loc->type = a->type;
		loc->offset %= size;
		loc->pointer = false;
		return context_member(p, loc, depth + 1, pointer_field);
	}
	if (!btf_is_composite(t))
		return false;
	for (i = 0; i < btf_vlen(t); ++i) {
		const struct btf_member *m = &btf_members(t)[i];
		const char *name = btf__name_by_offset(p->btf, m->name_off);
		long long bits = btf_member_bit_offset(t, i), size;
		struct context_location next = *loc;
		int n;

		if (bits % 8 || btf_member_bitfield_size(t, i))
			continue;
		size = btf__resolve_size(p->btf, m->type);
		if (size <= 0 || loc->offset < bits / 8 || loc->offset - bits / 8 >= size)
			continue;
		/* An overlapping alternative makes a field name ambiguous even if
		 * that alternative cannot itself be resolved to a capability.
		 */
		if (++matches > 1)
			return false;
		if (*name) {
			n = snprintf(next.name, sizeof(next.name), "%s%s%s", loc->name,
				     loc->pointer ? "->" : ".", name);
			if (n < 0 || (size_t)n >= sizeof(next.name))
				return false;
			next.pointer = false;
		}
		next.type = m->type;
		next.offset -= bits / 8;
		if (!context_member(p, &next, depth + 1, pointer_field))
			return false;
		found = next;
	}
	if (matches != 1)
		return false;
	*loc = found;
	return true;
}

static void print_context_lock(struct context_printer *p, const struct btf_type *proto,
			       const char *expr)
{
	struct context_location loc = {};
	const char *s = expr, *type;
	unsigned int i;

	if (!strncmp(expr, "token(", 6))
		for (i = 0; i < p->nr_tokens; ++i) {
			const char *name = p->tokens[i].name;
			size_t len = strlen(name);

			if (strlen(expr) == len + 7 && !strncmp(expr + 6, name, len) &&
			    expr[6 + len] == ')') {
				printf("%s [context token]", name);
				return;
			}
		}
	if (context_location(p, proto, &s, &loc, 0) && !*s && context_member(p, &loc, 0, false) &&
	    (type = context_type(p, loc.type, "")))
		printf("%s [%s]", loc.name, type);
	else
		printf("%s", expr);
}


/* Guards are scalar member addresses. Keep capability resolution unchanged. */
static bool context_scalar_member(struct context_printer *p, struct context_location *loc,
				  unsigned int depth)
{
	__u32 id = loc->type;
	const struct btf_type *t = context_unqualified(p->btf, &id);
	unsigned int i;

	if (!t || depth > 24 || loc->offset < 0)
		return false;
	if (!loc->offset && (btf_is_int(t) || btf_is_enum(t) || btf_is_enum64(t)))
		return true;
	if (!btf_is_struct(t))
		return false;
	for (i = 0; i < btf_vlen(t); ++i) {
		const struct btf_member *m = &btf_members(t)[i];
		long long offset = btf_member_bit_offset(t, i) / 8;
		long long size = btf__resolve_size(p->btf, m->type);
		const char *name = btf__name_by_offset(p->btf, m->name_off);
		char path[sizeof(loc->name)];
		int n;

		if (size <= 0 || loc->offset < offset || loc->offset - offset >= size ||
		    btf_member_bit_offset(t, i) % 8 || btf_member_bitfield_size(t, i))
			continue;
		n = snprintf(path, sizeof(path), "%s%s%s", loc->name,
			     *name ? (loc->pointer ? "->" : ".") : "", name);
		if (n < 0 || (size_t)n >= sizeof(path))
			return false;
		strcpy(loc->name, path);
		loc->type = m->type;
		loc->offset -= offset;
		loc->pointer = false;
		return context_scalar_member(p, loc, depth + 1);
	}
	return false;
}

static void print_witness_condition(struct context_printer *p, const struct btf_type *proto,
				    const char *condition)
{
	struct context_location loc = {};
	char text[BTF_CONTEXT_TAG_MAX], *fields[3], *comma, *end;
	const char *expr;
	unsigned long long bits, mask, value;
	unsigned int i;

	if (!strcmp(condition, "always"))
		return;
	if (strncmp(condition, "bits_eq(", 8) || strlen(condition) >= sizeof(text))
		goto raw;
	strcpy(text, condition + 8);
	text[strlen(text) - 1] = 0;
	for (i = 3; i > 0; --i) {
		comma = strrchr(text, ',');
		if (!comma)
			goto raw;
		fields[i - 1] = comma + 1;
		*comma = 0;
	}
	errno = 0;
	bits = strtoull(fields[0], &end, 10);
	if (errno || *end || !bits || bits > 64)
		goto raw;
	mask = strtoull(fields[1], &end, 10);
	if (errno || *end)
		goto raw;
	value = strtoull(fields[2], &end, 10);
	if (errno || *end)
		goto raw;
	expr = text;
	if (!context_location(p, proto, &expr, &loc, 0) || *expr ||
	    !context_scalar_member(p, &loc, 0))
		goto raw;
	printf(" when (%s & 0x%llx) == 0x%llx", loc.name, mask, value);
	return;
raw:
	printf(" when %s", condition);
}

static void print_context_tag(struct context_printer *p, const struct btf_type *proto,
			      const struct btf *btf, __u32 id)
{
	const struct btf_type *t = btf__type_by_id(btf, id);
	const char *raw = btf__name_by_offset(btf, t->name_off);
	struct btf_context_tag tag;

	if (!btf_context_parse_tag(raw, &tag))
		return;
	if (json_output) {
		jsonw_start_object(json_wtr);
		jsonw_uint_field(json_wtr, "tag_id", id);
		jsonw_string_field(json_wtr, "tag", raw);
		if (tag.source)
			jsonw_string_field(json_wtr, "source", tag.source);
	}
	switch (tag.kind) {
	case BTF_CONTEXT_WITNESS:
	case BTF_CONTEXT_EFFECT:
		if (json_output) {
			jsonw_string_field(json_wtr, "fact", tag.effect);
			jsonw_string_field(json_wtr, "mode", tag.mode);
			jsonw_string_field(json_wtr, "lock", tag.lock);
			jsonw_string_field(json_wtr, "condition", tag.condition);
			if (tag.kind == BTF_CONTEXT_WITNESS) {
				jsonw_string_field(json_wtr, "evidence", "path");
				jsonw_string_field(json_wtr, "via", tag.via);
			} else if (!strcmp(tag.effect, "may_acquire")) {
				jsonw_string_field(json_wtr, "evidence", "candidate");
			}
		} else {
			printf("  %s %s %s ", tag.source, tag.effect, tag.mode);
			print_context_lock(p, proto, tag.lock);
			if (tag.kind == BTF_CONTEXT_WITNESS) {
				print_witness_condition(p, proto, tag.condition);
				printf(" via %s", tag.via);
			} else {
				if (strcmp(tag.condition, "always"))
					printf(" when %s", tag.condition);
				if (!strcmp(tag.effect, "may_acquire"))
					printf(" [unproven path]");
			}
			putchar('\n');
		}
		break;
	case BTF_CONTEXT_TOKEN:
		if (json_output) jsonw_string_field(json_wtr, "token", tag.token);
		else printf("  token %s\n", tag.token);
		break;
	case BTF_CONTEXT_COMPLETE:
		if (json_output) jsonw_string_field(json_wtr, "fact", "lock_summary_complete");
		else printf("  complete locking summary\n");
		break;
	case BTF_CONTEXT_CAPABILITY:
		if (json_output) jsonw_string_field(json_wtr, "capability", tag.capability);
		else printf("  capability %s\n", tag.capability);
		break;
	case BTF_CONTEXT_REENTRANT:
		if (json_output) jsonw_bool_field(json_wtr, "reentrant", true);
		else printf("  reentrant\n");
		break;
	case BTF_CONTEXT_SCOPED:
		if (json_output) jsonw_bool_field(json_wtr, "scoped", true);
		else printf("  scoped\n");
		break;
	default:
		break;
	}
	if (json_output)
		jsonw_end_object(json_wtr);
}

int do_btf_context_analysis(int argc, char **argv)
{
	struct context_ref *refs = NULL;
	struct context_printer printer = {};
	struct btf *btf = NULL, *base = NULL;
	const char *function = NULL;
	unsigned int nr = 0, i, j, first;
	bool found = false;
	int err = -EINVAL;

	if (argc < 2) {
		p_err("expected context-analysis { file FILE | id BTF_ID } [func NAME]");
		return err;
	}
	if (!strcmp(argv[0], "file")) {
		struct btf *btf_base = base_btf;

		if (!btf_base && !strncmp(argv[1], "/sys/kernel/btf/", 16) &&
		    strcmp(argv[1], "/sys/kernel/btf/vmlinux")) {
			base = btf__parse("/sys/kernel/btf/vmlinux", NULL);
			if (!base) { err = -errno; goto out; }
			btf_base = base;
		}
		btf = btf__parse_split(argv[1], btf_base);
	} else if (!strcmp(argv[0], "id")) {
		char *end;
		unsigned long id;

		errno = 0;
		id = strtoul(argv[1], &end, 0);
		if (errno || end == argv[1] || *end || !id || id > UINT_MAX)
			goto out;
		btf = btf__load_from_kernel_by_id_split(id, base_btf);
	} else {
		p_err("expected file or id, got %s", argv[0]);
		goto out;
	}
	if (!btf) { err = -errno; goto out; }
	argc -= 2; argv += 2;
	if (argc) {
		if (argc != 2 || strcmp(argv[0], "func")) {
			p_err("expected func NAME");
			goto out;
		}
		function = argv[1];
	}
	/* Index once, then group facts by native type. No quadratic BTF scans. */
	first = btf__base_btf(btf) ? btf__type_cnt(btf__base_btf(btf)) : 1;
	refs = calloc(btf__type_cnt(btf) - first, sizeof(*refs));
	if (!refs) { err = -ENOMEM; goto out; }
	if (!json_output) {
		printer.btf = btf;
		printer.dump = btf_dump__new(btf, context_printf, &printer, NULL);
		printer.vars = calloc(btf__type_cnt(btf), sizeof(*printer.vars));
		printer.capabilities = calloc(btf__type_cnt(btf), sizeof(*printer.capabilities));
		if (!printer.dump || !printer.vars || !printer.capabilities) {
			err = -ENOMEM;
			goto out;
		}
	}
	for (i = 1; i < btf__type_cnt(btf); ++i) {
		const struct btf_type *t = btf__type_by_id(btf, i), *target;
		struct btf_context_tag tag;

		if (!json_output && btf_is_var(t))
			printer.vars[printer.nr_vars++] = (struct context_var){
				btf__name_by_offset(btf, t->name_off), t->type,
			};
		if (!btf_is_decl_tag(t) || btf_decl_tag(t)->component_idx != -1 ||
		    !btf_context_parse_tag(btf__name_by_offset(btf, t->name_off), &tag))
			continue;
		target = btf__type_by_id(btf, t->type);
		if (!target || (!btf_is_func(target) && !btf_is_composite(target)))
			continue;
		if (!json_output && btf_is_composite(target) && tag.kind == BTF_CONTEXT_CAPABILITY)
			printer.capabilities[t->type] = true;
		if (!json_output && btf_is_composite(target) && tag.kind == BTF_CONTEXT_TOKEN) {
			struct context_token *tokens;

			tokens = realloc(printer.tokens, (printer.nr_tokens + 1) * sizeof(*tokens));
			if (!tokens) {
				err = -ENOMEM;
				goto out;
			}
			printer.tokens = tokens;
			printer.tokens[printer.nr_tokens++].name =
				btf__name_by_offset(btf, t->name_off) + sizeof(BTF_CONTEXT_PREFIX) - 1 + 6;
		}
		if (i < first)
			continue;
		if (function && (!btf_is_func(target) ||
		    strcmp(function, btf__name_by_offset(btf, target->name_off))))
			continue;
		refs[nr++] = (struct context_ref){ t->type, i };
	}
	qsort(refs, nr, sizeof(*refs), compare_context_refs);
	if (!json_output)
		qsort(printer.vars, printer.nr_vars, sizeof(*printer.vars), compare_context_vars);
	if (json_output)
		jsonw_start_array(json_wtr);
	for (i = 0; i < nr; i = j) {
		const struct btf_type *t = btf__type_by_id(btf, refs[i].target);
		const struct btf_type *proto = btf_is_func(t) ? btf__type_by_id(btf, t->type) : NULL;
		const char *name = btf__name_by_offset(btf, t->name_off);
		const char *kind = btf_is_func(t) ? "FUNC" : btf_is_struct(t) ? "STRUCT" : "UNION";

		if (proto && !btf_is_func_proto(proto))
			proto = NULL;
		found = true;
		if (json_output) {
			jsonw_start_object(json_wtr);
			jsonw_uint_field(json_wtr, "type_id", refs[i].target);
			jsonw_string_field(json_wtr, "name", name);
			jsonw_string_field(json_wtr, "kind", kind);
			jsonw_name(json_wtr, "facts");
			jsonw_start_array(json_wtr);
		} else {
			const char *signature = proto ? context_type(&printer, t->type, name) : NULL;

			printf("[%u] %s %s\n", refs[i].target, kind, signature ?: name);
		}
		for (j = i; j < nr && refs[j].target == refs[i].target; ++j)
			print_context_tag(&printer, proto, btf, refs[j].tag);
		if (json_output) {
			jsonw_end_array(json_wtr);
			jsonw_end_object(json_wtr);
		}
	}
	if (json_output)
		jsonw_end_array(json_wtr);
	if (function && !found && !json_output)
		printf("%s: no context-analysis facts recorded\n", function);
	err = 0;
out:
	if (err)
		p_err("context-analysis: %s", strerror(-err));
	btf_dump__free(printer.dump);
	free(printer.text); free(printer.vars); free(printer.capabilities); free(printer.tokens);
	free(refs); btf__free(btf); btf__free(base);
	return err;
}
