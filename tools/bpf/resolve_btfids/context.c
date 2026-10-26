// SPDX-License-Identifier: GPL-2.0-only
/* Linked context analysis. No dependency on the fmodret resolver. */
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/btf.h>
#include <linux/btf.h>

#include "context.h"
#include "context_json.h"
#include "../../../scripts/llvm-plugins/bpf_context_metadata.h"

#define MAX_PATHS 2048
#define MAX_ROUNDS 128
#define MAX_EXPR 1024
#define MAX_EXPRESSIONS 262144

enum operation { ACQUIRE, RELEASE, REQUIRE, EXCLUDE, MAY_ACQUIRE, ENTRY_HELD };
enum mode { EXCLUSIVE, SHARED, GENERIC };
enum condition { ALWAYS, ZERO, NONZERO };

struct expression {
	struct expression *next;
	unsigned int hash, id, len;
	bool has_local, has_load, has_arg, has_snapshot, is_token;
	char text[];
};

struct fact {
	enum operation op;
	enum mode mode;
	enum condition cond;
	const struct expression *lock;
};

struct facts {
	struct fact *v;
	unsigned int n, capacity;
	unsigned int *slots, nr_slots;
	bool indexed;
};

struct clobber {
	const struct expression *address;
	unsigned int width;
	bool release;
};

struct clobbers {
	struct clobber *v;
	unsigned int n;
	bool unknown;
};

struct substitution {
	const struct expression *input, *result;
};

struct site {
	char *dispatch_key, *signature;
	struct function **dispatch_targets;
	unsigned int nr_dispatch_targets;
	unsigned int id;
	int reference;
	struct function *callee, *caller;
	const struct expression **args;
	unsigned int nargs, propagated_may;
	bool unrepresentable_may;
	bool interface_covered, witness_prefix_safe;
	struct facts held;
	struct substitution *substitutions;
	unsigned int nr_substitutions, substitution_slots;
	bool visited;
	bool write;
	const struct expression *address;
	unsigned int width;
	bool capture;
	unsigned int snapshot;
};

enum value_kind { VALUE_UNKNOWN, VALUE_INTEGER, VALUE_CALL, VALUE_TEST, VALUE_PHI, VALUE_LOAD, VALUE_AND };

struct value;
struct phi_input {
	unsigned int block;
	struct value *value;
};

struct value {
	enum value_kind kind;
	long long number;
	unsigned int call, nr_incoming, bits;
	const struct expression *address;
	bool eq, number_valid;
	struct value *left, *right;
	struct phi_input *incoming;
};

struct edge {
	unsigned int block;
	bool truth;
	struct value *test;
};

struct block {
	struct site *sites;
	unsigned int nr_sites, nr_edges;
	struct edge *edges;
	struct value *ret;
	bool witness_tail_safe;
};

/* A sufficient, consistent equality on one input scalar. No opaque effects
 * precede the acquisition. This is independent of the may-acquire superset.
 */
struct acquisition_witness {
	const struct expression *lock, *guard;
	unsigned long long mask, value;
	unsigned int bits;
	enum mode mode;
	bool emitted;
	char *via;
};

struct function {
	struct cj_doc *doc;
	char *name, *signature;
	unsigned int id, nargs, nr_blocks, nr_sites, native_proto;
	bool local, weak, defined, live, escaped, covered, raw_complete, complete;
	bool entry_closed;
	bool known_contract, exit_complete;
	bool memory_covered, witness_covered;
	unsigned int witness_state, nr_witnesses;
	struct acquisition_witness *witnesses;
	bool may_incomplete, may_budget;
	unsigned int loaded_may;
	struct clobbers memory_clobbers, spin_clobbers;
	const struct expression **snapshots;
	unsigned int nr_snapshots;
	bool dirty, body_dirty, entry_dirty, notify_callers, notify_body;
	struct function *definition;
	struct facts declared, effects, may, entry;
	struct block *blocks;
	struct site **incoming, **visited_sites;
	unsigned int nr_visited_sites;
	unsigned int nr_incoming;
	const char *reason;
};

struct document {
	struct cj_doc json;
	struct document *next;
};

struct name_id {
	const char *name;
	unsigned int id;
	unsigned long long address, size;
	unsigned int section;
};

struct emitted_tag {
	unsigned int type, hash;
	char *name;
	struct emitted_tag *next;
};

struct entry_reference {
	char *target, *caller;
	bool call, code, dispatch, dispatch_metadata;
	unsigned int source_section;
	unsigned long long source_address;
};

struct dispatch_binding {
	char *holder, *target, *table;
	unsigned long long address, offset, size;
};

struct dispatch_key {
	char *name, *table;
	unsigned long long offset, address, size;
	long long trampoline_address;
	unsigned int nr_sites;
	bool closed, resolved;
};

struct context_token {
	const struct expression *expr;
	char *name, *capability;
	bool reentrant, valid;
	unsigned int type;
};

struct context {
	struct function *functions;
	unsigned int nr_functions;
	struct dispatch_binding *dispatch_bindings;
	struct dispatch_key *dispatch_keys;
	unsigned int nr_dispatch_bindings, nr_dispatch_keys;
	struct document *documents;
	struct name_id *names, *btf_names, *elf_names;
	struct entry_reference *entry_references;
	unsigned int nr_entry_references, entry_reference_capacity;
	bool native_calls_covered, native_reference_contract;
	bool kernel_image;
	unsigned int nr_btf_names, nr_elf_names;
	struct btf *btf;
	bool *capabilities, *spin_capabilities, *reentrant;
	bool *embedded_storage;
	bool storage_layout_complete;
	struct context_token *tokens;
	unsigned int nr_tokens;
	struct emitted_tag **emitted;
	unsigned int emitted_slots;
	struct expression **expressions;
	unsigned int nr_expressions, expression_slots;
	bool deriving, expression_limited;
	unsigned long long substitution_hits, substitution_misses;
	unsigned long long analyses, ownership_visits;
	const char *trace_filter;
	int verbose;
	unsigned int tags, matched, complete, incomplete, entries, witness_tags, witness_functions;
};

static void *resize(void *p, size_t count, size_t size)
{
	void *q;

	if (size && count > SIZE_MAX / size)
		q = NULL;
	else
		q = realloc(p, count * size ?: 1);
	if (!q) {
		fprintf(stderr, "context-analysis: out of memory\n");
		exit(EXIT_FAILURE);
	}
	return q;
}

static char *copy_string(const char *s)
{
	char *p = resize(NULL, strlen(s) + 1, 1);

	strcpy(p, s);
	return p;
}

static char *string_field(const struct cj_doc *d, unsigned int o, const char *key)
{
	char *s = cj_string(d, cj_get(d, o, key));

	if (!s) {
		fprintf(stderr, "context-analysis: out of memory\n");
		exit(EXIT_FAILURE);
	}
	return s;
}

/* Exact interning gives expressions stable identities for the entire link. */
static const struct expression *intern_expression(struct context *c, const char *s)
{
	struct expression *e;
	unsigned int hash = 2166136261U, i, len = strlen(s), slot;

	if (!len || len >= MAX_EXPR)
		return NULL;
	for (i = 0; i < len; ++i)
		hash = (hash ^ (unsigned char)s[i]) * 16777619U;
	if (c->expression_slots) {
		slot = hash & (c->expression_slots - 1);
		for (e = c->expressions[slot]; e; e = e->next)
			if (e->hash == hash && e->len == len && !memcmp(e->text, s, len))
				return e;
	}
	if (c->deriving && c->nr_expressions >= MAX_EXPRESSIONS) {
		c->expression_limited = true;
		return NULL;
	}
	if (c->nr_expressions == UINT_MAX) {
		fprintf(stderr, "context-analysis: too many lock expressions\n");
		exit(EXIT_FAILURE);
	}
	if (!c->expression_slots || c->nr_expressions >= c->expression_slots) {
		unsigned int slots = c->expression_slots ? c->expression_slots * 2 : 1024;
		struct expression **table;

		if (slots < c->expression_slots) {
			fprintf(stderr, "context-analysis: lock expression table overflow\n");
			exit(EXIT_FAILURE);
		}
		table = resize(NULL, slots, sizeof(*table));
		memset(table, 0, slots * sizeof(*table));
		for (i = 0; i < c->expression_slots; ++i) {
			e = c->expressions[i];
			while (e) {
				struct expression *next = e->next;

				slot = e->hash & (slots - 1);
				e->next = table[slot];
				table[slot] = e;
				e = next;
			}
		}
		free(c->expressions);
		c->expressions = table;
		c->expression_slots = slots;
	}
	e = resize(NULL, sizeof(*e) + len + 1, 1);
	e->hash = hash;
	e->id = c->nr_expressions++;
	e->len = len;
	e->has_local = strstr(s, "local(") != NULL;
	e->has_load = strstr(s, "load(") != NULL;
	e->has_arg = strstr(s, "arg(") != NULL;
	e->has_snapshot = strstr(s, "snapshot(") != NULL;
	e->is_token = !strncmp(s, "token(", 6);
	memcpy(e->text, s, len + 1);
	slot = hash & (c->expression_slots - 1);
	e->next = c->expressions[slot];
	c->expressions[slot] = e;
	return e;
}

static struct context_token *context_token(struct context *c, const struct expression *expr)
{
	unsigned int i;

	if (!expr->is_token)
		return NULL;
	for (i = 0; i < c->nr_tokens; ++i)
		if (c->tokens[i].expr == expr)
			return &c->tokens[i];
	return NULL;
}

static bool symbolic_name(const char *name)
{
	const unsigned char *p = (const unsigned char *)name;

	if (!*p || strlen(name) >= MAX_EXPR - 64)
		return false;
	for (; *p; ++p)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' || *p == '$'))
			return false;
	return true;
}

static int read_tokens(struct context *c, struct cj_doc *d, unsigned int array)
{
	unsigned int i;

	cj_each(d, array, i) {
		char *name = string_field(d, i, "name");
		char *cap = string_field(d, i, "capability");
		bool reentrant = cj_bool(d, cj_get(d, i, "reentrant"));
		struct context_token *token;
		const struct expression *expr;
		char text[MAX_EXPR];

		if (!symbolic_name(name) || !symbolic_name(cap)) {
			free(name); free(cap);
			return -EINVAL;
		}
		snprintf(text, sizeof(text), "token(%s)", name);
		expr = intern_expression(c, text);
		token = context_token(c, expr);
		if (token) {
			token->valid &= !strcmp(token->capability, cap) && token->reentrant == reentrant;
			free(name); free(cap);
			continue;
		}
		c->tokens = resize(c->tokens, c->nr_tokens + 1, sizeof(*c->tokens));
		c->tokens[c->nr_tokens++] = (struct context_token){
			.expr = expr, .name = name, .capability = cap,
			.reentrant = reentrant, .valid = true,
		};
	}
	return 0;
}

static bool reentrant_expression(struct context *c, struct function *f,
				 const struct expression *expr);

static void clear(struct facts *s)
{
	free(s->v);
	free(s->slots);
	memset(s, 0, sizeof(*s));
}

static bool same(const struct fact *a, const struct fact *b)
{
	return a->op == b->op && a->mode == b->mode && a->cond == b->cond &&
		a->lock == b->lock;
}

static unsigned int fact_hash(const struct fact *f)
{
	unsigned int h = f->lock->id;

	h = (h ^ f->op) * 16777619U;
	h = (h ^ f->mode) * 16777619U;
	h = (h ^ f->cond) * 16777619U;
	return h ^ (h >> 16);
}

static void index_facts(struct facts *s, unsigned int needed)
{
	unsigned int slots = s->nr_slots ?: 16, i;

	while (needed > slots / 2) {
		if (slots > UINT_MAX / 2) {
			fprintf(stderr, "context-analysis: fact set overflow\n");
			exit(EXIT_FAILURE);
		}
		slots *= 2;
	}
	if (slots == s->nr_slots && s->indexed)
		return;
	s->slots = resize(s->slots, slots, sizeof(*s->slots));
	s->nr_slots = slots;
	memset(s->slots, 0, slots * sizeof(*s->slots));
	for (i = 0; i < s->n; ++i) {
		unsigned int pos = fact_hash(&s->v[i]) & (slots - 1);

		while (s->slots[pos])
			pos = (pos + 1) & (slots - 1);
		s->slots[pos] = i + 1;
	}
	s->indexed = true;
}

static bool contains(struct facts *s, const struct fact *f)
{
	unsigned int i;

	/* Tiny sets are common on CFG paths and need no separate index. */
	if (s->n < 8) {
		for (i = 0; i < s->n; ++i)
			if (same(&s->v[i], f))
				return true;
		return false;
	}
	index_facts(s, s->n);
	i = fact_hash(f) & (s->nr_slots - 1);
	while (s->slots[i]) {
		if (same(&s->v[s->slots[i] - 1], f))
			return true;
		i = (i + 1) & (s->nr_slots - 1);
	}
	return false;
}

static bool insert(struct facts *s, struct fact f)
{
	if (!f.lock || contains(s, &f))
		return false;
	if (s->n == s->capacity) {
		unsigned int capacity = s->capacity ? s->capacity * 2 : 4;

		if (capacity < s->capacity) {
			fprintf(stderr, "context-analysis: fact vector overflow\n");
			exit(EXIT_FAILURE);
		}
		s->v = resize(s->v, capacity, sizeof(*s->v));
		s->capacity = capacity;
	}
	if (s->n >= 8) {
		unsigned int pos;

		index_facts(s, s->n + 1);
		pos = fact_hash(&f) & (s->nr_slots - 1);
		while (s->slots[pos])
			pos = (pos + 1) & (s->nr_slots - 1);
		s->slots[pos] = s->n + 1;
	} else {
		s->indexed = false;
	}
	s->v[s->n++] = f;
	return true;
}

static void merge(struct facts *to, const struct facts *from)
{
	unsigned int i;

	for (i = 0; i < from->n; ++i)
		insert(to, from->v[i]);
}

static void remove_lock(struct facts *s, const struct expression *lock)
{
	unsigned int i = 0;

	while (i < s->n) {
		if (s->v[i].lock != lock) {
			++i;
			continue;
		}
		s->v[i] = s->v[--s->n];
		s->indexed = false;
	}
}

/* Intersect ownership guarantees, allowing exclusive ownership to satisfy
 * shared ownership. Generic release mode never establishes ownership.
 */
static void intersect_ownership(struct facts *a, const struct facts *b)
{
	unsigned int i = 0, j;

	while (i < a->n) {
		bool found = false;

		for (j = 0; j < b->n; ++j) {
			if (a->v[i].lock != b->v[j].lock)
				continue;
			if (a->v[i].mode == b->v[j].mode) {
				found = true;
				break;
			}
			if (a->v[i].mode != GENERIC && b->v[j].mode != GENERIC) {
				a->v[i].mode = SHARED;
				a->indexed = false;
				found = true;
				break;
			}
		}
		if (found) {
			++i;
		} else {
			a->v[i] = a->v[--a->n];
			a->indexed = false;
		}
	}
}

static bool equal_sets(const struct facts *a, struct facts *b)
{
	unsigned int i;

	if (a->n != b->n)
		return false;
	for (i = 0; i < a->n; ++i) {
		if (!contains(b, &a->v[i]))
			return false;
	}
	return true;
}

static bool equal_order(const struct facts *a, const struct facts *b)
{
	unsigned int i;

	if (a->n != b->n)
		return false;
	for (i = 0; i < a->n; ++i)
		if (!same(&a->v[i], &b->v[i]))
			return false;
	return true;
}

static int compare_names(const void *a, const void *b)
{
	return strcmp(((const struct name_id *)a)->name, ((const struct name_id *)b)->name);
}

/* Return the entire equal-name range; never choose a duplicate arbitrarily. */
static unsigned int name_range(struct name_id *v, unsigned int n, const char *name,
			       unsigned int *end)
{
	unsigned int lo = 0, hi = n;

	while (lo < hi) {
		unsigned int mid = lo + (hi - lo) / 2;

		if (strcmp(v[mid].name, name) < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	*end = lo;
	while (*end < n && !strcmp(v[*end].name, name))
		++*end;
	return lo;
}

static bool unique_symbol(struct context *c, const char *name)
{
	unsigned int end, start = name_range(c->elf_names, c->nr_elf_names, name, &end);

	return end == start + 1;
}

static bool native_expression(struct context *c, const struct expression *expr, bool allow_load)
{
	const char *p;
	const char *s = expr->text;

	if (expr->has_local || expr->has_snapshot || (expr->has_load && !allow_load))
		return false; /* Mutable indirections need memory-version identity. */
	if (expr->is_token) {
		struct context_token *token = context_token(c, expr);

		return token && token->valid;
	}
	for (p = s; (p = strstr(p, "global(")); ++p) {
		const char *end = strchr(p + 7, ')');
		char name[MAX_EXPR];

		if (!end || end - p - 7 >= MAX_EXPR)
			return false;
		memcpy(name, p + 7, end - p - 7);
		name[end - p - 7] = 0;
		if (!unique_symbol(c, name))
			return false;
	}
	return *s != 0;
}

static const struct expression *substitute_uncached(struct context *c,
						  const struct expression *input,
						  const struct site *site)
{
	char out[MAX_EXPR];
	size_t used = 0;
	const char *s = input->text;
	const char *arg;

	while ((arg = strstr(s, "arg("))) {
		size_t prefix = arg - s;

		if (used + prefix >= sizeof(out))
			return NULL;
		memcpy(out + used, s, prefix);
		used += prefix;
		s = arg;
		{
			char *end;
			unsigned long n = strtoul(s + 4, &end, 10);
			size_t len;

			if (end == s + 4 || *end != ')' || n >= site->nargs || !site->args[n])
				return NULL;
			len = site->args[n]->len;
			if (used + len >= sizeof(out))
				return NULL;
			memcpy(out + used, site->args[n]->text, len);
			used += len;
			s = end + 1;
		}
	}
	{
		size_t tail = input->len - (s - input->text);

		if (used + tail >= sizeof(out))
			return NULL;
		memcpy(out + used, s, tail);
		used += tail;
	}
	out[used] = 0;
	return intern_expression(c, out);
}

static const struct expression *substitute(struct context *c,
					 const struct expression *input, struct site *site)
{
	unsigned int pos;
	const struct expression *result;

	if (input->has_local || input->has_snapshot)
		return NULL;
	if (!input->has_arg)
		return input;
	if (site->substitution_slots) {
		pos = input->hash & (site->substitution_slots - 1);
		while (site->substitutions[pos].input) {
			if (site->substitutions[pos].input == input) {
				++c->substitution_hits;
				return site->substitutions[pos].result;
			}
			pos = (pos + 1) & (site->substitution_slots - 1);
		}
	}
	++c->substitution_misses;
	result = substitute_uncached(c, input, site);
	if (!site->substitution_slots || site->nr_substitutions >= site->substitution_slots / 2) {
		unsigned int slots = site->substitution_slots ? site->substitution_slots * 2 : 4, i;
		struct substitution *table;

		if (slots < site->substitution_slots) {
			fprintf(stderr, "context-analysis: substitution table overflow\n");
			exit(EXIT_FAILURE);
		}
		table = resize(NULL, slots, sizeof(*table));
		memset(table, 0, slots * sizeof(*table));
		for (i = 0; i < site->substitution_slots; ++i) {
			struct substitution old = site->substitutions[i];

			if (!old.input)
				continue;
			pos = old.input->hash & (slots - 1);
			while (table[pos].input)
				pos = (pos + 1) & (slots - 1);
			table[pos] = old;
		}
		free(site->substitutions);
		site->substitutions = table;
		site->substitution_slots = slots;
	}
	pos = input->hash & (site->substitution_slots - 1);
	while (site->substitutions[pos].input)
		pos = (pos + 1) & (site->substitution_slots - 1);
	site->substitutions[pos] = (struct substitution){ input, result };
	++site->nr_substitutions;
	return result;
}

/* Inverse substitution only at complete expression roots, never substrings. */
static const struct expression *relative(struct context *c, const struct expression *input,
					const struct site *site, unsigned int depth)
{
	unsigned int i;
	char out[MAX_EXPR];
	const char *s = input->text;

	if (depth > 24 || input->has_load)
		return NULL;
	if (context_token(c, input))
		return input;
	for (i = 0; i < site->nargs; ++i)
		if (input == site->args[i]) {
			snprintf(out, sizeof(out), "arg(%u)", i);
			return intern_expression(c, out);
		}
	if (!strncmp(s, "global(", 7))
		return input;
	if (!strncmp(s, "add(", 4)) {
		const char *comma = strrchr(s, ',');
		const struct expression *base, *part;
		int n;

		if (!comma || comma - s - 4 >= MAX_EXPR)
			return NULL;
		memcpy(out, s + 4, comma - s - 4);
		out[comma - s - 4] = 0;
		part = intern_expression(c, out);
		base = part ? relative(c, part, site, depth + 1) : NULL;
		if (!base)
			return NULL;
		n = snprintf(out, sizeof(out), "add(%s,%s", base->text, comma + 1);
		return n > 0 && n < MAX_EXPR ? intern_expression(c, out) : NULL;
	}
	return NULL;
}

static const struct expression *expand_snapshots(struct context *c, const struct function *f,
					       const struct expression *input)
{
	char text[MAX_EXPR];
	const char *s, *next;
	size_t used = 0;

	if (!input || !input->has_snapshot)
		return input;
	s = input->text;
	while ((next = strstr(s, "snapshot("))) {
		char *end;
		unsigned long id = strtoul(next + 9, &end, 10);
		const struct expression *path;
		size_t prefix = next - s;

		if (end == next + 9 || *end != ')' || id >= f->nr_snapshots ||
		    !(path = f->snapshots[id]) || path->has_snapshot ||
		    used + prefix + path->len >= sizeof(text))
			return NULL;
		memcpy(text + used, s, prefix);
		used += prefix;
		memcpy(text + used, path->text, path->len);
		used += path->len;
		s = end + 1;
	}
	if (used + strlen(s) >= sizeof(text))
		return NULL;
	strcpy(text + used, s);
	return intern_expression(c, text);
}

static bool read_contracts(struct context *c, struct function *f, unsigned int array)
{
	struct cj_doc *d = f->doc;
	unsigned int i;

	cj_each(d, array, i) {
		char *op = string_field(d, i, "op");
		char *mode = string_field(d, i, "mode");
		char *cond = string_field(d, i, "condition");
		char *lock = string_field(d, i, "lock");
		struct fact fact = { .lock = intern_expression(c, lock) };
		bool valid = (!strcmp(op, "acquire") || !strcmp(op, "release") ||
			!strcmp(op, "require") || !strcmp(op, "exclude")) &&
			(!strcmp(mode, "exclusive") || !strcmp(mode, "shared") || !strcmp(mode, "generic")) &&
			(!strcmp(cond, "always") || !strcmp(cond, "ret_eq(0)") || !strcmp(cond, "ret_ne(0)")) &&
			*lock;

		fact.op = !strcmp(op, "acquire") ? ACQUIRE : !strcmp(op, "release") ? RELEASE :
			!strcmp(op, "require") ? REQUIRE : EXCLUDE;
		fact.mode = !strcmp(mode, "shared") ? SHARED : !strcmp(mode, "generic") ? GENERIC : EXCLUSIVE;
		fact.cond = !strcmp(cond, "ret_eq(0)") ? ZERO : !strcmp(cond, "ret_ne(0)") ? NONZERO : ALWAYS;
		if (valid)
			insert(&f->declared, fact);
		free(op); free(mode); free(cond); free(lock);
		if (!valid)
			return false;
	}
	return true;
}

/* Decode the hot CFG fields once; JSON is only a transport format. */
static struct value *read_value(struct context *c, struct cj_doc *d, unsigned int id)
{
	struct value *v;
	unsigned int kind, a, i, n = 0;

	if (!id)
		return NULL;
	v = resize(NULL, 1, sizeof(*v));
	memset(v, 0, sizeof(*v));
	kind = cj_get(d, id, "kind");
	if (cj_equal(d, kind, "integer")) {
		v->kind = VALUE_INTEGER;
		v->number = cj_number(d, cj_get(d, id, "value"), 0);
		v->number_valid = cj_number(d, cj_get(d, id, "value"), 1) == v->number;
	} else if (cj_equal(d, kind, "call")) {
		v->kind = VALUE_CALL;
		v->call = cj_number(d, cj_get(d, id, "call"), UINT_MAX);
	} else if (cj_equal(d, kind, "scalar_load")) {
		char *address = string_field(d, id, "address");

		v->kind = VALUE_LOAD;
		v->address = intern_expression(c, address);
		free(address);
		v->bits = cj_number(d, cj_get(d, id, "bits"), 0);
	} else if (cj_equal(d, kind, "and")) {
		v->kind = VALUE_AND;
		v->left = read_value(c, d, cj_get(d, id, "left"));
		v->right = read_value(c, d, cj_get(d, id, "right"));
	} else if (cj_equal(d, kind, "test")) {
		v->kind = VALUE_TEST;
		v->eq = cj_equal(d, cj_get(d, id, "predicate"), "eq");
		v->left = read_value(c, d, cj_get(d, id, "left"));
		v->right = read_value(c, d, cj_get(d, id, "right"));
	} else if (cj_equal(d, kind, "phi")) {
		v->kind = VALUE_PHI;
		a = cj_get(d, id, "incoming");
		v->nr_incoming = a ? d->tokens[a].children : 0;
		v->incoming = resize(NULL, v->nr_incoming, sizeof(*v->incoming));
		cj_each(d, a, i) {
			v->incoming[n].block = cj_number(d, cj_get(d, i, "block"), UINT_MAX);
			v->incoming[n++].value = read_value(c, d, cj_get(d, i, "value"));
		}
	}
	return v;
}

static void free_value(struct value *v)
{
	unsigned int i;

	if (!v)
		return;
	free_value(v->left);
	free_value(v->right);
	for (i = 0; i < v->nr_incoming; ++i)
		free_value(v->incoming[i].value);
	free(v->incoming);
	free(v);
}

/* Function bodies have been decoded; retain only the type descriptions. */
static int retain_types(struct cj_doc *d, unsigned int root)
{
	unsigned int types = cj_get(d, root, "types");
	size_t len = types ? d->tokens[types].end - d->tokens[types].start : 2;
	char *text = resize(NULL, len + 11, 1);
	size_t pos = 0;

	memcpy(text, "{\"types\":", 9);
	memcpy(text + 9, types ? d->text + d->tokens[types].start : "[]", len);
	memcpy(text + 9 + len, "}", 2);
	free(d->text);
	free(d->tokens);
	d->text = text;
	d->capacity = (len + 10) / 2 + 4;
	d->tokens = resize(NULL, d->capacity, sizeof(*d->tokens));
	memset(d->tokens, 0, sizeof(*d->tokens));
	d->count = 1;
	return cj_parse_value(d, &pos, 0) < 0 ? -EINVAL : 0;
}

static int read_document(struct context *c, const char *data, size_t len)
{
	struct document *doc = resize(NULL, 1, sizeof(*doc));
	struct cj_doc *d = &doc->json;
	unsigned int array, i, base = c->nr_functions;
	size_t pos = 0;
	int root;

	memset(doc, 0, sizeof(*doc));
	doc->next = c->documents;
	c->documents = doc;
	d->text = resize(NULL, len + 1, 1);
	memcpy(d->text, data, len);
	d->text[len] = 0;
	if (len > UINT_MAX / 2)
		return -E2BIG;
	d->capacity = len / 2 + 4;
	d->tokens = resize(NULL, d->capacity, sizeof(*d->tokens));
	memset(d->tokens, 0, sizeof(*d->tokens));
	d->count = 1;
	root = cj_parse_value(d, &pos, 0);
	if (root < 0 || pos != len ||
	    !cj_equal(d, cj_get(d, root, "format"), BPF_CONTEXT_FORMAT) ||
	    (cj_number(d, cj_get(d, root, "version"), -1) != BPF_CONTEXT_VERSION &&
	     cj_number(d, cj_get(d, root, "version"), -1) != 2 &&
	     cj_number(d, cj_get(d, root, "version"), -1) != 3 &&
	     cj_number(d, cj_get(d, root, "version"), -1) != 4))
		return -EINVAL;
	if (read_tokens(c, d, cj_get(d, root, "tokens")))
		return -EINVAL;
	array = cj_get(d, root, "dispatch_bindings");
	cj_each(d, array, i) {
		struct dispatch_binding b = {
			.holder = string_field(d, i, "holder"), .target = string_field(d, i, "target"),
			.table = string_field(d, i, "table"),
			.address = cj_number(d, cj_get(d, i, "address"), 0),
			.offset = cj_number(d, cj_get(d, i, "offset"), 0),
			.size = cj_number(d, cj_get(d, i, "size"), 0),
		};

		c->dispatch_bindings = resize(c->dispatch_bindings, c->nr_dispatch_bindings + 1, sizeof(b));
		c->dispatch_bindings[c->nr_dispatch_bindings++] = b;
	}
	array = cj_get(d, root, "dispatch_keys");
	cj_each(d, array, i) {
		struct dispatch_key k = {
			.name = string_field(d, i, "name"), .table = string_field(d, i, "table"),
			.offset = cj_number(d, cj_get(d, i, "offset"), 0),
			.address = cj_number(d, cj_get(d, i, "address"), 0),
			.size = cj_number(d, cj_get(d, i, "size"), 0),
			.closed = cj_bool(d, cj_get(d, i, "closed")),
			.trampoline_address = cj_number(d, cj_get(d, i, "trampoline_address"), -1),
		};

		c->dispatch_keys = resize(c->dispatch_keys, c->nr_dispatch_keys + 1, sizeof(k));
		c->dispatch_keys[c->nr_dispatch_keys++] = k;
	}
	array = cj_get(d, root, "functions");
	if (!array || d->tokens[array].kind != '[')
		return -EINVAL;
	d->nr_functions = d->tokens[array].children;
	d->functions = resize(NULL, d->nr_functions, sizeof(*d->functions));
	c->functions = resize(c->functions, base + d->nr_functions, sizeof(*c->functions));
	memset(c->functions + base, 0, d->nr_functions * sizeof(*c->functions));
	cj_each(d, array, i) {
		unsigned int id = cj_number(d, cj_get(d, i, "id"), UINT_MAX), a, b;
		struct function *f;

		if (id != c->nr_functions - base)
			return -EINVAL;
		f = &c->functions[c->nr_functions];
		d->functions[id] = c->nr_functions++;
		f->doc = d;
		f->id = id;
		f->name = string_field(d, i, "symbol");
		f->signature = cj_get(d, i, "signature") ? string_field(d, i, "signature") : copy_string("");
		f->nargs = cj_number(d, cj_get(d, i, "nargs"), 0);
		f->local = cj_bool(d, cj_get(d, i, "local"));
		f->weak = cj_bool(d, cj_get(d, i, "weak"));
		f->defined = cj_bool(d, cj_get(d, i, "defined"));
		f->live = cj_bool(d, cj_get(d, i, "live"));
		f->escaped = cj_bool(d, cj_get(d, i, "escaped")) || !symbolic_name(f->name);
		f->covered = cj_bool(d, cj_get(d, i, "covered"));
		f->witness_covered = cj_number(d, cj_get(d, root, "version"), 0) >= 4 &&
			cj_bool(d, cj_get(d, i, "witness_covered"));
		f->raw_complete = cj_bool(d, cj_get(d, i, "complete"));
		f->memory_covered = cj_number(d, cj_get(d, root, "version"), 0) >= 3 &&
			cj_bool(d, cj_get(d, i, "memory_covered"));
		{
			unsigned int list = cj_get(d, i, "snapshots"), entry, n = 0;

			f->nr_snapshots = list ? d->tokens[list].children : 0;
			f->snapshots = resize(NULL, f->nr_snapshots, sizeof(*f->snapshots));
			cj_each(d, list, entry) {
				char *path = cj_string(d, entry);

				if (!path)
					return -EINVAL;
				f->snapshots[n++] = intern_expression(c, path);
				free(path);
			}
		}
		if (!read_contracts(c, f, cj_get(d, i, "contracts")))
			return -EINVAL;
		f->known_contract = f->declared.n && cj_bool(d, cj_get(d, i, "contract_complete"));
		f->exit_complete = f->known_contract;
		a = cj_get(d, i, "blocks");
		f->nr_blocks = a ? d->tokens[a].children : 0;
		f->blocks = resize(NULL, f->nr_blocks, sizeof(*f->blocks));
		memset(f->blocks, 0, f->nr_blocks * sizeof(*f->blocks));
		cj_each(d, a, b) {
			unsigned int bi = cj_number(d, cj_get(d, b, "id"), UINT_MAX), sites, s, k = 0;
			struct block *block;

			if (bi >= f->nr_blocks)
				return -EINVAL;
			block = &f->blocks[bi];
			block->witness_tail_safe = cj_bool(d, cj_get(d, b, "witness_tail_safe"));
			{
				unsigned int edges = cj_get(d, b, "edges"), e, n = 0;

				block->nr_edges = edges ? d->tokens[edges].children : 0;
				block->edges = resize(NULL, block->nr_edges, sizeof(*block->edges));
				cj_each(d, edges, e) {
					block->edges[n].block = cj_number(d, cj_get(d, e, "block"), UINT_MAX);
					block->edges[n].truth = cj_bool(d, cj_get(d, e, "true"));
					block->edges[n++].test = read_value(c, d, cj_get(d, e, "test"));
				}
			}
			block->ret = read_value(c, d, cj_get(d, b, "return"));
			sites = cj_get(d, b, "calls");
			block->nr_sites = sites ? d->tokens[sites].children : 0;
			f->nr_sites += block->nr_sites;
			block->sites = resize(NULL, block->nr_sites, sizeof(*block->sites));
			memset(block->sites, 0, block->nr_sites * sizeof(*block->sites));
			cj_each(d, sites, s) {
				struct site *site = &block->sites[k++];
				unsigned int args = cj_get(d, s, "arguments"), arg, j = 0;

				site->id = cj_number(d, cj_get(d, s, "id"), UINT_MAX);
				site->dispatch_key = cj_get(d, s, "dispatch_key") ? string_field(d, s, "dispatch_key") : copy_string("");
				site->signature = cj_get(d, s, "signature") ? string_field(d, s, "signature") : copy_string("");
				site->witness_prefix_safe = cj_bool(d, cj_get(d, s, "witness_prefix_safe"));
				site->reference = cj_number(d, cj_get(d, s, "callee"), -1);
				site->write = cj_equal(d, cj_get(d, s, "kind"), "write");
				site->capture = cj_equal(d, cj_get(d, s, "kind"), "capture");
				site->snapshot = cj_number(d, cj_get(d, s, "snapshot"), UINT_MAX);
				if (site->write) {
					char *address = string_field(d, s, "address");

					site->address = intern_expression(c, address);
					free(address);
					site->width = cj_number(d, cj_get(d, s, "width"), 0);
				}
				site->nargs = args ? d->tokens[args].children : 0;
				site->args = resize(NULL, site->nargs, sizeof(*site->args));
				cj_each(d, args, arg) {
					char *expr = cj_string(d, arg);

					if (!expr)
						exit(EXIT_FAILURE);
					site->args[j++] = intern_expression(c, expr);
					free(expr);
				}
			}
		}
	}
	return retain_types(d, root);
}

static int compare_addresses(const void *a, const void *b)
{
	const struct name_id *x = a, *y = b;

	if (x->section != y->section)
		return x->section < y->section ? -1 : 1;
	return x->address < y->address ? -1 : x->address != y->address;
}

static const struct name_id *address_function(struct name_id *v, unsigned int n,
					     unsigned int section, unsigned long long address)
{
	unsigned int lo = 0, hi = n;

	while (lo < hi) {
		unsigned int m = lo + (hi - lo) / 2;

		if (v[m].section < section || (v[m].section == section && v[m].address <= address))
			lo = m + 1;
		else
			hi = m;
	}
	if (!lo || v[lo - 1].section != section || address - v[lo - 1].address >= v[lo - 1].size)
		return NULL;
	return &v[lo - 1];
}

struct native_range {
	unsigned long long start, end;
	unsigned int section;
	bool valid;
};

static bool metadata_bound(const char *name)
{
	return name && (!strcmp(name, "__start___jump_table") || !strcmp(name, "__stop___jump_table") ||
		!strcmp(name, "__start_static_call_sites") || !strcmp(name, "__stop_static_call_sites") ||
		!strcmp(name, "__start_mcount_loc") || !strcmp(name, "__stop_mcount_loc"));
}

static struct native_range native_range(struct context *c, const char *begin, const char *end)
{
	const struct name_id *a = NULL, *b = NULL;
	unsigned int i;

	for (i = 0; i < c->nr_elf_names; ++i) {
		if (!strcmp(c->elf_names[i].name, begin)) {
			if (a) return (struct native_range){};
			a = &c->elf_names[i];
		}
		if (!strcmp(c->elf_names[i].name, end)) {
			if (b) return (struct native_range){};
			b = &c->elf_names[i];
		}
	}
	if (!a || !b || a->section != b->section || a->address >= b->address)
		return (struct native_range){};
	return (struct native_range){ a->address, b->address, a->section, true };
}

static bool in_native_range(struct native_range range, unsigned int section, unsigned long long address)
{
	return range.valid && section == range.section && address >= range.start && address < range.end;
}

/* Retained allocated relocations expose direct callers and address uses,
 * including references from assembler objects which have no IR document.
 */
static int collect_entry_references(struct context *c, Elf *elf, size_t strings)
{
	struct name_id *functions = resize(NULL, c->nr_elf_names, sizeof(*functions));
	unsigned int i, n = 0;
	GElf_Ehdr ehdr;
	Elf_Scn *scn = NULL;
	struct native_range jumps = native_range(c, "__start___jump_table", "__stop___jump_table");
	struct native_range statics = native_range(c, "__start_static_call_sites", "__stop_static_call_sites");
	struct native_range mcount = native_range(c, "__start_mcount_loc", "__stop_mcount_loc");

	if (!gelf_getehdr(elf, &ehdr)) {
		free(functions);
		return -EINVAL;
	}
	if ((ehdr.e_type != ET_EXEC && !(ehdr.e_type == ET_DYN && c->kernel_image)) ||
	    (ehdr.e_machine != EM_AARCH64 && ehdr.e_machine != EM_X86_64)) {
		free(functions);
		return 0;
	}
	for (i = 0; i < c->nr_elf_names; ++i)
		if ((c->elf_names[i].id & 255) == STT_FUNC)
			functions[n++] = c->elf_names[i];
	qsort(functions, n, sizeof(*functions), compare_addresses);
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr sh, owner_sh, symbols_sh;
		Elf_Data *relocs, *symbols, *bytes;
		const char *section;

		if (!gelf_getshdr(scn, &sh) || sh.sh_type != SHT_RELA || !sh.sh_entsize)
			continue;
		if (!gelf_getshdr(elf_getscn(elf, sh.sh_info), &owner_sh) ||
		    !(owner_sh.sh_flags & SHF_ALLOC))
			continue;
		section = elf_strptr(elf, strings, owner_sh.sh_name);
		if (!section || !strcmp(section, "__patchable_function_entries") ||
		    !strcmp(section, "__mcount_loc") || !strcmp(section, ".eh_frame") ||
		    !strcmp(section, ".discard.addressable") ||
		    !strcmp(section, "__jump_table") ||
		    !strcmp(section, ".eh_frame_hdr") || !strncmp(section, ".orc_unwind", 11))
			continue;
		if ((owner_sh.sh_flags & SHF_EXECINSTR) && c->native_reference_contract)
			c->native_calls_covered = true;
		if (!gelf_getshdr(elf_getscn(elf, sh.sh_link), &symbols_sh))
			continue;
		relocs = elf_getdata(scn, NULL);
		symbols = elf_getdata(elf_getscn(elf, sh.sh_link), NULL);
		bytes = elf_getdata(elf_getscn(elf, sh.sh_info), NULL);
		for (i = 0; i < sh.sh_size / sh.sh_entsize; ++i) {
			GElf_Rela rel;
			GElf_Sym sym;
			const struct name_id *owner, *target;
			const char *name;
			unsigned int type;
			unsigned long long offset;
			unsigned long long static_offset;
			bool static_site;
			bool call = false, dispatch = false;
			bool dispatch_metadata = false;
			unsigned int source_section = sh.sh_info;
			unsigned long long source_address;
			char dispatch_name[MAX_EXPR];

			if (!gelf_getrela(relocs, i, &rel) ||
			    !gelf_getsym(symbols, GELF_R_SYM(rel.r_info), &sym))
				continue;
			type = GELF_R_TYPE(rel.r_info);
			source_address = rel.r_offset;
			offset = rel.r_offset - owner_sh.sh_addr;
			if (in_native_range(jumps, sh.sh_info, rel.r_offset) ||
			    in_native_range(mcount, sh.sh_info, rel.r_offset))
				continue;
			static_site = !strcmp(section, ".static_call_sites") ||
				in_native_range(statics, sh.sh_info, rel.r_offset);
			static_offset = in_native_range(statics, sh.sh_info, rel.r_offset) ?
				rel.r_offset - statics.start : offset;
			/* Objtool records instruction addresses, not function entries.
			 * The paired key relocation is validated below as a dispatch use.
			 */
			if (ehdr.e_machine == EM_X86_64 && static_site &&
			    static_offset % 8 == 0 && type == R_X86_64_PC32)
				continue;
			if (owner_sh.sh_flags & SHF_EXECINSTR) {
				if (ehdr.e_machine == EM_AARCH64)
					call = type == R_AARCH64_CALL26 || type == R_AARCH64_JUMP26;
				else if ((type == R_X86_64_PLT32 || type == R_X86_64_PC32) &&
					 bytes && offset && offset < bytes->d_size) {
					const unsigned char *data = bytes->d_buf;
					unsigned char opcode = data[offset - 1];

					call = opcode == 0xe8 || opcode == 0xe9;
				}
			}
			if (GELF_ST_TYPE(sym.st_info) == STT_FUNC || GELF_ST_TYPE(sym.st_info) == STT_OBJECT) {
				name = elf_strptr(elf, symbols_sh.sh_link, sym.st_name);
				if (name && !strncmp(name, "__SCK__lsm_static_call_", sizeof("__SCK__lsm_static_call_") - 1))
					dispatch = true;
				else if (name && !strncmp(name, "__SCT__lsm_static_call_", sizeof("__SCT__lsm_static_call_") - 1)) {
					if (snprintf(dispatch_name, sizeof(dispatch_name), "__SCK__%s", name + 7) >= MAX_EXPR)
						continue;
					name = dispatch_name;
					dispatch = true;
				} else if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) {
					continue;
				}
			} else if (GELF_ST_TYPE(sym.st_info) == STT_SECTION) {
				unsigned long long address = sym.st_value + rel.r_addend;

				if (ehdr.e_machine == EM_X86_64 && call)
					address += 4;
				target = address_function(functions, n, sym.st_shndx, address);
				if (!target || target->address != address)
					continue;
				name = target->name;
			} else {
				continue;
			}
			if (!name || !*name)
				continue;
			owner = (owner_sh.sh_flags & SHF_EXECINSTR) ? address_function(functions, n, sh.sh_info,
						       rel.r_offset) : NULL;
			if (dispatch && ehdr.e_machine == EM_X86_64 &&
			    static_site && i &&
			    static_offset % 8 == 4 && type == R_X86_64_PC32 &&
			    rel.r_addend >= 0 && rel.r_addend <= 3) {
				GElf_Rela site;
				GElf_Sym code;
				GElf_Shdr text;

				if (gelf_getrela(relocs, i - 1, &site) &&
				    site.r_offset + 4 == rel.r_offset &&
				    GELF_R_TYPE(site.r_info) == R_X86_64_PC32 &&
				    gelf_getsym(symbols, GELF_R_SYM(site.r_info), &code) &&
				    code.st_shndx < SHN_LORESERVE &&
				    gelf_getshdr(elf_getscn(elf, code.st_shndx), &text) &&
				    (text.sh_flags & SHF_EXECINSTR)) {
					unsigned long long address = code.st_value + site.r_addend;

					owner = address_function(functions, n, code.st_shndx, address);
					source_section = code.st_shndx;
					source_address = address + 1; /* native rel32 operand */
					dispatch_metadata = owner != NULL;
				}
			}
			if (c->nr_entry_references == c->entry_reference_capacity) {
				if (c->entry_reference_capacity > UINT_MAX / 2) {
					free(functions);
					return -E2BIG;
				}
				c->entry_reference_capacity = c->entry_reference_capacity ?
					c->entry_reference_capacity * 2 : 1024;
				c->entry_references = resize(c->entry_references,
							     c->entry_reference_capacity,
							     sizeof(*c->entry_references));
			}
			c->entry_references[c->nr_entry_references++] = (struct entry_reference){
				.target = copy_string(name), .caller = copy_string(owner ? owner->name : ""),
				.call = call, .code = !!(owner_sh.sh_flags & SHF_EXECINSTR) || dispatch_metadata,
				.dispatch = dispatch, .dispatch_metadata = dispatch_metadata,
				.source_section = source_section, .source_address = source_address };
		}
	}
	free(functions);
	return 0;
}

static int collect_elf(struct context *c, const char *path)
{
	Elf_Scn *scn = NULL;
	size_t strings;
	Elf *elf;
	int fd, err = 0;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return -EINVAL;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf || elf_getshdrstrndx(elf, &strings)) {
		err = -EINVAL;
		goto out;
	}
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr sh;
		Elf_Data *data;
		const char *name;

		if (!gelf_getshdr(scn, &sh)) {
			err = -EINVAL;
			break;
		}
		name = elf_strptr(elf, strings, sh.sh_name);
		data = elf_getdata(scn, NULL);
		if (!data)
			continue;
		if (name && !strcmp(name, BPF_CONTEXT_SECTION)) {
			size_t pos = 0;

			while (pos < data->d_size) {
				const char *p = (const char *)data->d_buf + pos;
				const char *end = memchr(p, 0, data->d_size - pos);

				if (!end) { err = -EINVAL; break; }
				if (end != p && (err = read_document(c, p, end - p)))
					break;
				pos += end - p + 1;
			}
		} else if (sh.sh_type == SHT_SYMTAB && sh.sh_entsize) {
			unsigned int i;

			for (i = 0; i < sh.sh_size / sh.sh_entsize; ++i) {
				GElf_Sym sym;
				unsigned int kind;

				if (!gelf_getsym(data, i, &sym)) { err = -EINVAL; break; }
				name = elf_strptr(elf, sh.sh_link, sym.st_name);
				if (name && !strcmp(name, "_stext") && sym.st_shndx != SHN_UNDEF)
					c->kernel_image = true;
				if (name && !strcmp(name, "__bpf_context_native_calls") &&
				    sym.st_shndx == SHN_ABS && sym.st_value == 1)
					c->native_reference_contract = true;
				kind = GELF_ST_TYPE(sym.st_info);
				if (sym.st_shndx == SHN_UNDEF ||
				    (kind != STT_FUNC && kind != STT_OBJECT && !metadata_bound(name)))
					continue;
				name = elf_strptr(elf, sh.sh_link, sym.st_name);
				if (!name || !*name)
					continue;
				c->elf_names = resize(c->elf_names, c->nr_elf_names + 1, sizeof(*c->elf_names));
				c->elf_names[c->nr_elf_names++] = (struct name_id){ copy_string(name),
					kind | GELF_ST_BIND(sym.st_info) << 8,
					sym.st_value, sym.st_size, sym.st_shndx };
			}
		}
		if (err)
			break;
	}
	if (!err)
		err = collect_entry_references(c, elf, strings);
out:
	elf_end(elf);
	close(fd);
	qsort(c->elf_names, c->nr_elf_names, sizeof(*c->elf_names), compare_names);
	return err;
}

static void resolve_functions(struct context *c)
{
	unsigned int i, j, k;

	c->names = resize(NULL, c->nr_functions, sizeof(*c->names));
	for (i = 0; i < c->nr_functions; ++i)
		c->names[i] = (struct name_id){ c->functions[i].name, i };
	qsort(c->names, c->nr_functions, sizeof(*c->names), compare_names);
	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i], *chosen = NULL;
		unsigned int start, end, strong = 0, weak = 0;

		if (f->local) {
			f->definition = f->defined ? f : NULL;
			continue;
		}
		start = name_range(c->names, c->nr_functions, f->name, &end);
		for (j = start; j < end; ++j) {
			struct function *g = &c->functions[c->names[j].id];

			if (g->local || !g->defined)
				continue;
			if (!g->weak) { chosen = g; ++strong; }
			else { ++weak; if (!strong) chosen = g; }
		}
		if (strong == 1 || (!strong && weak == 1)) {
			unsigned int symbol_end, symbol_start = name_range(c->elf_names,
				c->nr_elf_names, f->name, &symbol_end);

			if (symbol_end == symbol_start + 1 && chosen->live &&
			    (c->elf_names[symbol_start].id & 255) == STT_FUNC &&
			    (c->elf_names[symbol_start].id >> 8) == (chosen->weak ? STB_WEAK : STB_GLOBAL))
				f->definition = chosen;
		}
	}
	/* Declarations can supply contracts even when the definition did not opt in. */
	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i];

		if (f->definition && f->definition->nargs == f->nargs) {
			merge(&f->definition->declared, &f->declared);
			f->definition->known_contract |= f->known_contract;
			f->definition->exit_complete |= f->known_contract;
			f->definition->escaped |= f->escaped;
		}
		merge(&f->effects, &f->declared);
		for (j = 0; j < f->nr_blocks; ++j)
			for (k = 0; k < f->blocks[j].nr_sites; ++k) {
				struct site *s = &f->blocks[j].sites[k];

				s->caller = f;
				if (*s->dispatch_key)
					continue;
				if (s->reference >= 0 && (unsigned int)s->reference < f->doc->nr_functions) {
					struct function *ref = &c->functions[f->doc->functions[s->reference]];

					s->interface_covered = ref->memory_covered;
					s->callee = ref->definition;
					/* Keep declaration contracts when no body was collected. */
					if (!s->callee && (ref->declared.n || s->interface_covered))
						s->callee = ref;
					if (s->callee) {
						struct function *g = s->callee;

						g->incoming = resize(g->incoming, g->nr_incoming + 1, sizeof(*g->incoming));
						g->incoming[g->nr_incoming++] = s;
					}
				}
			}
	}
}

static const struct name_id *dispatch_holder(struct context *c, const struct dispatch_binding *b)
{
	unsigned int end, start = name_range(c->elf_names, c->nr_elf_names, b->holder, &end);
	const struct name_id *holder = NULL;

	for (; start < end; ++start) {
		const struct name_id *p = &c->elf_names[start];

		if ((p->id & 255) != STT_OBJECT || p->size != b->size)
			continue;
		if (holder)
			return NULL;
		holder = p;
	}
	return holder && b->address < holder->size ? holder : NULL;
}

static bool registered_reference(struct context *c, const struct entry_reference *ref)
{
	unsigned int i;

	for (i = 0; i < c->nr_dispatch_bindings; ++i) {
		const struct dispatch_binding *b = &c->dispatch_bindings[i];
		const struct name_id *holder;

		if (strcmp(ref->target, b->target) || !(holder = dispatch_holder(c, b)))
			continue;
		if (holder->section == ref->source_section &&
		    ref->source_address == holder->address + b->address) {
			unsigned int k, matched = 0;

			/* A registration can close an address escape only if every
			 * corresponding dispatcher has been represented. Otherwise a
			 * direct locked caller could hide an unmodelled unlocked one.
			 */
			for (k = 0; k < c->nr_dispatch_keys; ++k) {
				const struct dispatch_key *key = &c->dispatch_keys[k];

				if (strcmp(key->table, b->table) || key->offset != b->offset)
					continue;
				if (!key->resolved || !key->nr_sites)
					return false;
				++matched;
			}
			return matched != 0;
		}
	}
	return false;
}

static bool dispatch_key_closed(struct context *c, const struct dispatch_key *key)
{
	unsigned int r, low = 0, high = c->nr_entry_references;

	if (!key->closed)
		return false;
	while (low < high) {
		unsigned int mid = low + (high - low) / 2;

		if (strcmp(c->entry_references[mid].target, key->name) < 0)
			low = mid + 1;
		else
			high = mid;
	}
	for (r = low; r < c->nr_entry_references &&
	     !strcmp(c->entry_references[r].target, key->name); ++r) {
		const struct entry_reference *ref = &c->entry_references[r];
		unsigned int end, start;
		bool found = false;

		if (!ref->dispatch || strcmp(ref->target, key->name))
			continue;
		if (!ref->code) {
			struct dispatch_binding holder_key = { .holder = key->table,
				.size = key->size, .address = key->address };
			const struct name_id *holder = dispatch_holder(c, &holder_key);

			if (!holder || holder->section != ref->source_section ||
			    (holder->address + key->address != ref->source_address &&
			     (key->trampoline_address < 0 || holder->address + key->trampoline_address != ref->source_address)))
				return false;
			continue;
		}
		if (ref->dispatch_metadata) {
			unsigned int paired;

			for (paired = low; paired < c->nr_entry_references &&
			     !strcmp(c->entry_references[paired].target, key->name); ++paired) {
				const struct entry_reference *p = &c->entry_references[paired];

				if (!p->dispatch_metadata && p->call && p->source_section == ref->source_section &&
				    p->source_address == ref->source_address)
					break;
			}
			if (paired == c->nr_entry_references ||
			    strcmp(c->entry_references[paired].target, key->name))
				return false;
		}
		start = name_range(c->names, c->nr_functions, ref->caller, &end);
		for (; start < end; ++start) {
			struct function *f = &c->functions[c->names[start].id];
			unsigned int b, s;

			if (f->definition != f || !f->live || !unique_symbol(c, f->name))
				continue;
			for (b = 0; b < f->nr_blocks; ++b)
				for (s = 0; s < f->blocks[b].nr_sites; ++s)
					found |= !strcmp(f->blocks[b].sites[s].dispatch_key, key->name);
		}
		if (!found)
			return false;
	}
	return true;
}

static void resolve_dispatches(struct context *c)
{
	unsigned int i, j, k, h, bound = 0;

	for (i = 0; i < c->nr_dispatch_keys; ++i)
		c->dispatch_keys[i].resolved = dispatch_key_closed(c, &c->dispatch_keys[i]);
	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i];

		for (j = 0; j < f->nr_blocks; ++j)
			for (k = 0; k < f->blocks[j].nr_sites; ++k) {
				struct site *s = &f->blocks[j].sites[k];
				struct dispatch_key *key = NULL;
				bool valid = true;

				if (!*s->dispatch_key)
					continue;
				for (h = 0; h < c->nr_dispatch_keys; ++h)
					if (!strcmp(s->dispatch_key, c->dispatch_keys[h].name)) {
						if (key) {
							key->resolved = c->dispatch_keys[h].resolved = false;
							valid = false;
							break;
						}
						key = &c->dispatch_keys[h];
					}
				if (!valid || !key || !key->resolved)
					continue;
				++key->nr_sites;
				for (h = 0; h < c->nr_dispatch_bindings; ++h) {
					const struct dispatch_binding *b = &c->dispatch_bindings[h];
					struct function *target = NULL;
					unsigned int end, start, n;

					if (strcmp(key->table, b->table) || key->offset != b->offset ||
					    !dispatch_holder(c, b))
						continue;
					start = name_range(c->names, c->nr_functions, b->target, &end);
					for (; start < end; ++start) {
						struct function *g = &c->functions[c->names[start].id];

						if (g->definition)
							target = g->definition;
					}
					if (!target || !unique_symbol(c, b->target) || target->nargs != s->nargs || !*s->signature ||
					    strcmp(target->signature, s->signature)) {
						valid = false;
						break;
					}
					for (n = 0; n < s->nr_dispatch_targets; ++n)
						if (s->dispatch_targets[n] == target)
							break;
					if (n == s->nr_dispatch_targets) {
						s->dispatch_targets = resize(s->dispatch_targets, n + 1, sizeof(target));
						s->dispatch_targets[s->nr_dispatch_targets++] = target;
					}
				}
				if (!valid) {
					key->resolved = false;
					s->nr_dispatch_targets = 0;
					continue;
				}
				if (!s->nr_dispatch_targets)
					key->resolved = false;
				s->interface_covered = f->memory_covered;
				for (h = 0; h < s->nr_dispatch_targets; ++h) {
					struct function *g = s->dispatch_targets[h];

					g->incoming = resize(g->incoming, g->nr_incoming + 1, sizeof(s));
					g->incoming[g->nr_incoming++] = s;
				}
				bound += !!s->nr_dispatch_targets;
			}
	}
	if (c->verbose)
		fprintf(stderr, "context-analysis: %u static dispatch sites resolved from native registrations\n", bound);
}

static int compare_entry_references(const void *a, const void *b)
{
	const struct entry_reference *x = a, *y = b;
	int order = strcmp(x->target, y->target);

	if (order)
		return order;
	order = strcmp(x->caller, y->caller);
	return order ?: (int)x->call - (int)y->call;
}

static void close_entry_callers(struct context *c)
{
	unsigned int i;

	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i];

		f->entry_closed = f->defined && !f->escaped &&
			(f->local || c->native_calls_covered);
	}

	for (i = 0; i < c->nr_entry_references;) {
		struct entry_reference *ref = &c->entry_references[i];
		unsigned int end, start = name_range(c->names, c->nr_functions, ref->target, &end);
		unsigned int next = i + 1, j;

		while (next < c->nr_entry_references &&
		       !compare_entry_references(ref, &c->entry_references[next]))
			++next;
		if (ref->dispatch) { i = next; continue; }
		if (!ref->call) {
			unsigned int r;

			for (r = i; r < next; ++r)
				if (!registered_reference(c, &c->entry_references[r]))
					break;
			if (r == next) { i = next; continue; }
		}
		for (j = start; j < end; ++j) {
			struct function *f = &c->functions[c->names[j].id];
			unsigned int h, calls = 0;

			if (f->local || !f->entry_closed)
				continue;
			for (h = 0; h < f->nr_incoming; ++h) {
				struct function *caller = f->incoming[h]->caller;

				calls += caller->live && caller->definition == caller &&
					unique_symbol(c, caller->name) &&
					!strcmp(ref->caller, caller->name);
			}
			if (!ref->call || !*ref->caller || calls < next - i) {
				if (c->verbose > 2 && (!c->trace_filter || strstr(f->name, c->trace_filter)))
					fprintf(stderr, "context-analysis: entry-unaccounted-reference %s: caller=%s section=%u address=%#llx call=%u represented=%u native=%u\n",
						f->name, *ref->caller ? ref->caller : "<data>", ref->source_section,
						ref->source_address, ref->call, calls, next - i);
				f->entry_closed = false;
			}
		}
		i = next;
	}
}

static bool add_clobber(struct clobbers *set, struct clobber effect)
{
	unsigned int i;

	if (set->unknown)
		return false;
	if (!effect.address || (!effect.release && !effect.width) ||
	    (effect.address->has_local && effect.address->has_load)) {
		set->unknown = true;
		return true;
	}
	/* This frame's own stack storage cannot be a caller's live lock. */
	if (effect.address->has_local)
		return false;
	for (i = 0; i < set->n; ++i)
		if (set->v[i].address == effect.address &&
		    set->v[i].width == effect.width && set->v[i].release == effect.release)
			return false;
	if (set->n == 128) {
		set->unknown = true;
		return true;
	}
	set->v = resize(set->v, set->n + 1, sizeof(*set->v));
	set->v[set->n++] = effect;
	return true;
}

/* A may-clobber fixed point, independent of exit/acquisition completeness.
 * Cycles are allowed: unknown effects and possible clobbers only accumulate.
 * Trusted interface contracts describe ownership changes across the call.
 */
static void derive_clobbers(struct context *c, bool spin)
{
	unsigned int i, j, k, h, round, known = 0;
	bool changed = false;

	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i];
		struct clobbers *set = spin ? &f->spin_clobbers : &f->memory_clobbers;

		set->unknown = !f->known_contract && (!f->defined || !f->memory_covered);
		if (f->known_contract) {
			for (j = 0; j < f->declared.n; ++j)
				if (f->declared.v[j].op == RELEASE)
					add_clobber(set, (struct clobber){ f->declared.v[j].lock, 0, true });
			continue;
		}
		for (j = 0; j < f->nr_blocks; ++j)
			for (k = 0; k < f->blocks[j].nr_sites; ++k) {
				struct site *s = &f->blocks[j].sites[k];

				if (s->write)
					add_clobber(set, (struct clobber){ expand_snapshots(c, f, s->address), s->width, false });
				else if (!s->capture && !s->callee &&
					 !(spin && s->interface_covered && s->nr_dispatch_targets))
					set->unknown = true;
			}
	}
	for (round = 0; round < MAX_ROUNDS; ++round) {
		changed = false;
		for (i = 0; i < c->nr_functions; ++i) {
			struct function *f = &c->functions[i];
			struct clobbers *set = spin ? &f->spin_clobbers : &f->memory_clobbers;

			if (f->known_contract || set->unknown)
				continue;
			for (j = 0; j < f->nr_blocks && !set->unknown; ++j)
				for (k = 0; k < f->blocks[j].nr_sites && !set->unknown; ++k) {
					struct site *s = &f->blocks[j].sites[k];
					struct function *g = s->callee;
					struct clobbers *from = g ? (spin ? &g->spin_clobbers : &g->memory_clobbers) : NULL;

					if (s->write || s->capture)
						continue;
					if (spin && s->interface_covered && s->nr_dispatch_targets) {
						unsigned int target;

						for (target = 0; target < s->nr_dispatch_targets; ++target) {
							struct function *g = s->dispatch_targets[target];
							struct clobbers *from = &g->spin_clobbers;

							if (g->covered && !g->known_contract) {
								if (from->unknown) { set->unknown = changed = true; break; }
								for (h = 0; h < from->n; ++h) {
									struct clobber effect = from->v[h];

									effect.address = expand_snapshots(c, f, substitute(c, effect.address, s));
									changed |= add_clobber(set, effect);
								}
							} else {
								for (h = 0; h < g->declared.n; ++h)
									if (g->declared.v[h].op == RELEASE)
										changed |= add_clobber(set, (struct clobber){
											substitute(c, g->declared.v[h].lock, s), 0, true });
							}
						}
						continue;
					}
					/* Clang's complete direct-call interface describes
					 * ownership transfers even when a body is unavailable.
					 * This is not a complete memory/acquisition summary.
					 */
					if (spin && s->interface_covered && g && g->defined && !g->covered) {
						for (h = 0; h < g->declared.n; ++h)
							if (g->declared.v[h].op == RELEASE)
								changed |= add_clobber(set, (struct clobber){
									substitute(c, g->declared.v[h].lock, s), 0, true });
						continue;
					}
					if (!from || from->unknown) {
						set->unknown = changed = true;
						break;
					}
					for (h = 0; h < from->n && !set->unknown; ++h) {
						struct clobber effect = from->v[h];

						effect.address = substitute(c, effect.address, s);
						effect.address = expand_snapshots(c, f, effect.address);
						changed |= add_clobber(set, effect);
					}
				}
		}
		if (!changed)
			break;
	}
	for (i = 0; i < c->nr_functions; ++i) {
		struct clobbers *set = spin ? &c->functions[i].spin_clobbers : &c->functions[i].memory_clobbers;

		if (changed)
			set->unknown = true;
		known += !set->unknown;
	}
	if (c->verbose)
		fprintf(stderr, "context-analysis: %sownership preservation: %u tracked summaries, %u unknown; %u rounds\n",
			spin ? "spin " : "", known, c->nr_functions - known, round + 1);
}

struct pending {
	struct fact fact;
	unsigned int site;
};

struct ownership {
	const struct expression *lock;
	enum mode mode;
	unsigned int depth;
	int delta;
};

struct state {
	struct facts held, delta;
	struct ownership *ownership;
	unsigned int nr_ownership;
	bool ownership_only;
	struct pending *pending;
	unsigned int nr_pending;
};

static void destroy_state(struct state *s)
{
	bool ownership_only = s->ownership_only;

	clear(&s->held); clear(&s->delta);
	free(s->pending); free(s->ownership);
	memset(s, 0, sizeof(*s));
	s->ownership_only = ownership_only;
}

static struct state clone_state(const struct state *s)
{
	struct state out = { .ownership_only = s->ownership_only };
	unsigned int i;

	merge(&out.held, &s->held); merge(&out.delta, &s->delta);
	out.nr_ownership = s->nr_ownership;
	out.ownership = out.nr_ownership ? resize(NULL, out.nr_ownership, sizeof(*out.ownership)) : NULL;
	if (out.nr_ownership)
		memcpy(out.ownership, s->ownership, out.nr_ownership * sizeof(*out.ownership));
	out.pending = s->nr_pending ? resize(NULL, s->nr_pending, sizeof(*out.pending)) : NULL;
	out.nr_pending = s->nr_pending;
	for (i = 0; i < s->nr_pending; ++i)
		out.pending[i] = s->pending[i];
	return out;
}

static struct ownership *ownership(struct state *s, const struct expression *lock)
{
	unsigned int i;

	for (i = 0; i < s->nr_ownership; ++i)
		if (s->ownership[i].lock == lock)
			return &s->ownership[i];
	s->ownership = resize(s->ownership, s->nr_ownership + 1, sizeof(*s->ownership));
	s->ownership[s->nr_ownership] = (struct ownership){ .lock = lock };
	return &s->ownership[s->nr_ownership++];
}

static void forget_ownership(struct state *s, const struct expression *lock)
{
	unsigned int i;

	remove_lock(&s->held, lock);
	remove_lock(&s->delta, lock);
	for (i = 0; i < s->nr_ownership; ++i)
		if (s->ownership[i].lock == lock) {
			s->ownership[i] = s->ownership[--s->nr_ownership];
			return;
		}
}

static bool clobber_aliases(struct context *c, struct function *f,
			    const struct expression *lock, struct clobber effect);
static bool spin_expression(struct context *c, struct function *f,
			    const struct expression *lock);

static void invalidate_clobber(struct context *c, struct function *f, struct state *s,
			       struct clobber effect)
{
	unsigned int i = 0;

	while (i < s->held.n) {
		const struct expression *lock = s->held.v[i].lock;

		if (clobber_aliases(c, f, lock, effect))
			forget_ownership(s, lock);
		else
			++i;
	}
	i = 0;
	while (i < s->nr_pending) {
		if (clobber_aliases(c, f, s->pending[i].fact.lock, effect))
			s->pending[i] = s->pending[--s->nr_pending];
		else
			++i;
	}
}

static bool call_clobbers(struct context *c, struct function *f, struct site *site,
			  const struct expression *lock)
{
	unsigned int i;
	struct function *g = site->callee;
	bool spin = spin_expression(c, f, lock);
	struct clobbers *set;

	if (spin && site->interface_covered && site->nr_dispatch_targets) {
		for (i = 0; i < site->nr_dispatch_targets; ++i) {
			struct site direct = *site;
			bool clobbered;

			direct.callee = site->dispatch_targets[i];
			direct.nr_dispatch_targets = 0;
			clobbered = call_clobbers(c, f, &direct, lock);
			site->substitutions = direct.substitutions;
			site->nr_substitutions = direct.nr_substitutions;
			site->substitution_slots = direct.substitution_slots;
			if (clobbered)
				return true;
		}
		return false;
	}
	if (!g)
		return true;
	if (spin && site->interface_covered && g->defined && !g->covered) {
		for (i = 0; i < g->declared.n; ++i)
			if (g->declared.v[i].op == RELEASE &&
			    clobber_aliases(c, f, lock, (struct clobber){
				    substitute(c, g->declared.v[i].lock, site), 0, true }))
				return true;
		return false;
	}
	set = spin ? &g->spin_clobbers : &g->memory_clobbers;
	if (set->unknown)
		return true;
	for (i = 0; i < set->n; ++i) {
		struct clobber effect = set->v[i];

		effect.address = substitute(c, effect.address, site);
		if (clobber_aliases(c, f, lock, effect))
			return true;
	}
	return false;
}

static void preserve_call(struct context *c, struct function *f, struct state *s,
			  struct site *site)
{
	unsigned int i = 0;

	while (i < s->held.n) {
		const struct expression *lock = s->held.v[i].lock;

		if (call_clobbers(c, f, site, lock))
			forget_ownership(s, lock);
		else
			++i;
	}
	for (i = 0; i < s->nr_pending;)
		if (call_clobbers(c, f, site, s->pending[i].fact.lock))
			s->pending[i] = s->pending[--s->nr_pending];
		else
			++i;
}

static void initialize_ownership(struct state *s)
{
	unsigned int i;

	for (i = 0; i < s->held.n; ++i) {
		struct ownership *o = ownership(s, s->held.v[i].lock);

		if (!o->depth || s->held.v[i].mode == EXCLUSIVE)
			o->mode = s->held.v[i].mode;
		o->depth = 1; /* entry_held guarantees at least one level. */
	}
	clear(&s->held);
	for (i = 0; i < s->nr_ownership; ++i)
		insert(&s->held, (struct fact){ ENTRY_HELD, s->ownership[i].mode,
			ALWAYS, s->ownership[i].lock });
}

static struct state entry_state(struct function *f)
{
	struct state state = {};
	unsigned int i;

	merge(&state.held, &f->entry);
	for (i = 0; i < f->declared.n; ++i)
		if (f->declared.v[i].op == REQUIRE) {
			struct fact held = f->declared.v[i];

			held.op = ENTRY_HELD;
			insert(&state.held, held);
		}
	initialize_ownership(&state);
	return state;
}

static void apply_effect(struct context *c, struct function *f, struct state *s,
			 struct fact effect, bool *complete)
{
	struct context_token *token = context_token(c, effect.lock);
	struct ownership *o;
	unsigned int i = 0;

	if (effect.op != ACQUIRE && effect.op != RELEASE)
		return;
	/* Physical pointers can alias. Abstract tokens are disjoint from
	 * physical locks and other named tokens, so unrelated releases preserve
	 * them. Unknown calls still invalidate all ownership in process_call().
	 */
	if (effect.op == RELEASE && !(token && token->valid)) {
		while (i < s->held.n) {
			const struct expression *lock = s->held.v[i].lock;
			struct context_token *other = context_token(c, lock);

			if (lock == effect.lock || (other && other->valid) ||
			    !clobber_aliases(c, f, lock, (struct clobber){ effect.lock, 0, true })) {
				++i;
				continue;
			}
			forget_ownership(s, lock);
			*complete = false;
		}
	}
	o = ownership(s, effect.lock);
	if (!o->depth && !o->delta)
		o->mode = effect.mode;
	if (effect.mode != GENERIC && o->mode != effect.mode) {
		*complete = false;
		forget_ownership(s, effect.lock);
		return;
	}
	if (effect.op == ACQUIRE) {
		if (o->depth && !reentrant_expression(c, f, effect.lock))
			*complete = false;
		if (o->depth == UINT_MAX || o->delta == INT_MAX) {
			*complete = false;
			forget_ownership(s, effect.lock);
			return;
		}
		++o->depth;
		if (!s->ownership_only)
			++o->delta;
	} else {
		if (o->delta == INT_MIN) {
			*complete = false;
			forget_ownership(s, effect.lock);
			return;
		}
		if (o->depth)
			--o->depth;
		if (!s->ownership_only)
			--o->delta;
	}
	remove_lock(&s->held, effect.lock);
	if (o->depth)
		insert(&s->held, (struct fact){ ENTRY_HELD, o->mode, ALWAYS, effect.lock });
	remove_lock(&s->delta, effect.lock);
	if (o->delta)
		insert(&s->delta, (struct fact){ o->delta > 0 ? ACQUIRE : RELEASE,
			o->mode, ALWAYS, effect.lock });
}

static void resolve_pending(struct context *c, struct function *fn, struct state *s,
			    unsigned int site, enum condition cond, bool *complete)
{
	unsigned int i = 0;

	while (i < s->nr_pending) {
		struct pending *p = &s->pending[i];

		if (p->site != site) { ++i; continue; }
		if (p->fact.cond == cond) {
			struct fact f = p->fact;

			f.cond = ALWAYS;
			apply_effect(c, fn, s, f, complete);
		}
		s->pending[i] = s->pending[--s->nr_pending];
	}
}

static enum value_kind value_kind(const struct value *v)
{
	return v ? v->kind : VALUE_UNKNOWN;
}

static const struct value *phi_value(const struct value *v, unsigned int pred)
{
	unsigned int i;

	if (value_kind(v) != VALUE_PHI)
		return v;
	for (i = 0; i < v->nr_incoming; ++i)
		if (v->incoming[i].block == pred)
			return v->incoming[i].value;
	return NULL;
}

struct exit_state {
	struct facts delta;
	enum condition ret;
};

struct analysis {
	struct context *ctx;
	struct function *f;
	struct exit_state *exits;
	unsigned int nr_exits, paths;
	bool complete, exits_known, exhaustive;
	unsigned char *visited;
};

static void insert_may(struct function *f, struct fact fact)
{
	if (!fact.lock || contains(&f->may, &fact))
		return;
	if (f->may_budget || f->may.n >= 128 || (fact.lock->has_load && f->loaded_may >= 8)) {
		f->may_budget = f->may_incomplete = true;
		return;
	}
	if (insert(&f->may, fact) && fact.lock->has_load)
		++f->loaded_may;
}

static void propagate_may(struct context *c, struct function *caller, struct site *site)
{
	struct function *callee = site->callee;

	if (!callee)
		return;
	if (callee->may_incomplete && !caller->may_incomplete) {
		caller->may_incomplete = caller->body_dirty = true;
	}
	if (caller->may_budget) {
		site->propagated_may = callee->may.n;
		return;
	}
	/* May summaries only grow; failed substitutions are sticky too. */
	while (site->propagated_may < callee->may.n) {
		struct fact f = callee->may.v[site->propagated_may++];

		f.lock = substitute(c, f.lock, site);
		f.lock = expand_snapshots(c, caller, f.lock);
		if (!f.lock)
			site->unrepresentable_may = true;
		else {
			f.op = MAY_ACQUIRE;
			f.cond = ALWAYS;
			insert_may(caller, f);
		}
		if (caller->may_budget) {
			site->propagated_may = callee->may.n;
			caller->body_dirty = true;
			break;
		}
	}
}

/* A larger may set does not change any CFG state. Rewalk a body only if
 * propagation discovers a new failure, or an effect/entry input changed.
 * Replay sites in first-visit order to retain deterministic fact order.
 */
static bool refresh_may(struct context *c, struct function *f)
{
	unsigned int old_may = f->may.n, i;

	for (i = 0; i < f->nr_visited_sites; ++i) {
		struct site *s = f->visited_sites[i];
		bool failed = s->unrepresentable_may;

		propagate_may(c, f, s);
		if (!failed && s->unrepresentable_may)
			f->body_dirty = true;
	}
	return old_may != f->may.n;
}

static void process_call_effects(struct analysis *a, struct site *site, struct state *s)
{
	struct function *callee = site->callee;
	unsigned int i;
	bool acquires = false, releases = false, mixed_effects;

	if (!site->visited) {
		merge(&site->held, &s->held);
		site->visited = true;
		a->f->visited_sites[a->f->nr_visited_sites++] = site;
	} else {
		intersect_ownership(&site->held, &s->held);
	}
	if (site->capture) {
		char marker[40];
		unsigned int p = 0;

		if (site->snapshot >= a->f->nr_snapshots) {
			destroy_state(s);
			a->complete = a->exits_known = false;
			return;
		}
		snprintf(marker, sizeof(marker), "snapshot(%u)", site->snapshot);
		/* A loop can execute this SSA definition again with a new object. */
		while (p < s->held.n) {
			const struct expression *lock = s->held.v[p].lock;

			if (strstr(lock->text, marker))
				forget_ownership(s, lock);
			else
				++p;
		}
		for (p = 0; p < s->nr_pending;)
			if (strstr(s->pending[p].fact.lock->text, marker))
				s->pending[p] = s->pending[--s->nr_pending];
			else
				++p;
		return;
	}
	if (site->write) {
		a->complete = a->exits_known = false;
		a->f->reason = "raw write prevents complete exit effects";
		invalidate_clobber(a->ctx, a->f, s,
			(struct clobber){ site->address, site->width, false });
		return;
	}
	if (!callee || !callee->complete) {
		a->complete = false;
		a->f->reason = !callee ? "unresolved/indirect call" : "incomplete callee";
	}
	if (!callee || !callee->exit_complete) {
		a->exits_known = false;
		preserve_call(a->ctx, a->f, s, site);
	}
	if (!callee)
		return;
	/* A set of exit effects does not establish order for possibly aliasing locks. */
	for (i = 0; i < callee->effects.n; ++i) {
		acquires |= callee->effects.v[i].op == ACQUIRE;
		releases |= callee->effects.v[i].op == RELEASE;
	}
	mixed_effects = acquires && releases;
	propagate_may(a->ctx, a->f, site);
	if (site->unrepresentable_may) {
		a->complete = false;
		a->f->reason = "unrepresentable lock argument";
	}
	for (i = 0; i < callee->effects.n; ++i) {
		struct fact f = callee->effects.v[i];
		const struct expression *expr;

		if (f.cond != ALWAYS) {
			struct fact unconditional = f;

			unconditional.cond = ALWAYS;
			if (contains(&callee->effects, &unconditional))
				continue;
		}
		expr = substitute(a->ctx, f.lock, site);
		if (!expr) {
			a->complete = false;
			if (f.op != MAY_ACQUIRE)
				a->exits_known = false;
			if (f.op == RELEASE)
				destroy_state(s);
			a->f->reason = f.op == RELEASE ? "unrepresentable release invalidates ownership" :
				"unrepresentable lock argument";
			continue;
		}
		f.lock = expr;
		if (f.op == ACQUIRE || f.op == MAY_ACQUIRE) {
			struct fact may = f;

			may.op = MAY_ACQUIRE; may.cond = ALWAYS;
			may.lock = expand_snapshots(a->ctx, a->f, may.lock);
			if (!may.lock)
				a->complete = false;
			insert_may(a->f, may);
		}
		/* A path through a pointer read identifies a possible acquisition,
		 * not a stable ownership identity across this call or later reads.
		 */
		if (expr->has_load && f.op != MAY_ACQUIRE) {
			a->complete = a->exits_known = false;
			a->f->reason = "pointer-derived lock needs a stable ownership identity";
			destroy_state(s);
			continue;
		}
		if (f.op == ACQUIRE || f.op == RELEASE) {
			unsigned int j;

			for (j = 0; j < s->nr_pending;) {
				const struct expression *pending = s->pending[j].fact.lock;
				bool alias = pending == f.lock ||
					(f.op == RELEASE && clobber_aliases(a->ctx, a->f, pending,
						(struct clobber){ f.lock, 0, true }));

				if (!alias) {
					++j;
					continue;
				}
				/* An unresolved earlier event cannot be applied after a
				 * later mutation: that could resurrect released ownership.
				 */
				s->pending[j] = s->pending[--s->nr_pending];
				a->complete = a->exits_known = false;
			}
			if (f.op == RELEASE && f.cond != ALWAYS) {
				/* A conditional release may already have consumed the lock
				 * when the callee returns, before its result is tested.
				 */
				apply_effect(a->ctx, a->f, s, f, &a->exits_known);
				forget_ownership(s, f.lock);
				a->complete = a->exits_known = false;
				a->f->reason = "conditional release needs a correlated ownership state";
				continue;
			}
			if (f.cond == ALWAYS)
				apply_effect(a->ctx, a->f, s, f, &a->exits_known);
			else {
				s->pending = resize(s->pending, s->nr_pending + 1, sizeof(*s->pending));
				f.lock = expr;
				s->pending[s->nr_pending++] = (struct pending){ f, site->id };
			}
		}
		if (f.op == REQUIRE || f.op == EXCLUDE) {
			unsigned int j;
			bool satisfied = false;

			satisfied = contains(&a->f->declared, &f);
			if (f.op == REQUIRE)
				for (j = 0; j < site->held.n; ++j)
					if (f.lock == site->held.v[j].lock &&
					    (f.mode == site->held.v[j].mode ||
					     (f.mode == SHARED && site->held.v[j].mode == EXCLUSIVE)))
						satisfied = true;
			if (!satisfied) {
				a->complete = a->exits_known = false;
				a->f->reason = "callee precondition needs a caller contract";
			}
		}
	}
	if (mixed_effects) {
		a->complete = a->exits_known = false;
		a->f->reason = "mixed exit effects need alias and ordering proof";
		destroy_state(s);
	}
}

static void process_call(struct analysis *a, struct site *site, struct state *s)
{
	struct facts before = {};
	const char *filter = a->ctx->trace_filter;
	bool trace = a->ctx->verbose > 2 && (!filter || !strcmp(filter, a->f->name));
	unsigned int i;

	if (trace)
		merge(&before, &s->held);
	process_call_effects(a, site, s);
	if (trace) {
		const char *event = site->write ? "write" : site->capture ? "capture" :
			site->callee ? site->callee->name : "unknown call or assembly";

		for (i = 0; i < before.n; ++i)
			if (!contains(&s->held, &before.v[i]))
				fprintf(stderr, "context-analysis: ownership-lost %s: call=%u event=%s lock=%s\n",
					a->f->name, site->id, event, before.v[i].lock->text);
		clear(&before);
	}
}

static void record_exit(struct analysis *a, const struct state *s, enum condition ret)
{
	struct exit_state *e;
	unsigned int i;

	/* Version 1 exit facts encode one acquisition/release. Balance nested
	 * operations locally, but do not collapse a multi-level exit into one.
	 */
	for (i = 0; i < s->nr_ownership; ++i)
		if (s->ownership[i].delta > 1 || s->ownership[i].delta < -1)
			a->complete = a->exits_known = false;
	for (i = 0; i < s->delta.n; ++i)
		if (s->delta.v[i].lock->has_snapshot) {
			a->complete = a->exits_known = false;
			a->f->reason = "exit ownership depends on a callee-local pointer capture";
		}
	a->exits = resize(a->exits, a->nr_exits + 1, sizeof(*a->exits));
	e = &a->exits[a->nr_exits++];
	memset(e, 0, sizeof(*e));
	e->ret = ret;
	merge(&e->delta, &s->delta);
	if (s->nr_pending)
		a->complete = a->exits_known = false;
}

static void walk(struct analysis *a, unsigned int block, unsigned int pred, struct state *s,
		 unsigned int depth)
{
	struct function *f = a->f;
	struct block *b;
	unsigned int i;

	if (block >= f->nr_blocks || depth > 256 || ++a->paths > MAX_PATHS || a->visited[block]) {
		a->complete = a->exits_known = a->exhaustive = false;
		f->reason = "cyclic CFG or path budget";
		return;
	}
	a->visited[block] = 1;
	b = &f->blocks[block];
	for (i = 0; i < b->nr_sites; ++i)
		process_call(a, &b->sites[i], s);
	if (b->ret) {
		const struct value *v = phi_value(b->ret, pred);
		enum value_kind kind = value_kind(v);

		if (kind == VALUE_CALL) {
			unsigned int site = v->call;
			struct state zero = clone_state(s), nonzero = clone_state(s);

			resolve_pending(a->ctx, f, &zero, site, ZERO, &a->exits_known);
			resolve_pending(a->ctx, f, &nonzero, site, NONZERO, &a->exits_known);
			record_exit(a, &zero, ZERO); record_exit(a, &nonzero, NONZERO);
			destroy_state(&zero); destroy_state(&nonzero);
		} else if (kind == VALUE_TEST) {
			const struct value *left = phi_value(v->left, pred);
			const struct value *right = phi_value(v->right, pred);
			bool eq = v->eq;

			if (value_kind(left) == VALUE_CALL &&
			    value_kind(right) == VALUE_INTEGER &&
			    right->number_valid && right->number == 0) {
				unsigned int site = left->call;
				struct state zero = clone_state(s), nonzero = clone_state(s);

				resolve_pending(a->ctx, f, &zero, site, eq ? NONZERO : ZERO, &a->exits_known);
				resolve_pending(a->ctx, f, &nonzero, site, eq ? ZERO : NONZERO, &a->exits_known);
				record_exit(a, &zero, ZERO); record_exit(a, &nonzero, NONZERO);
				destroy_state(&zero); destroy_state(&nonzero);
			} else record_exit(a, s, ALWAYS);
		} else {
			enum condition cond = ALWAYS;

			if (kind == VALUE_INTEGER)
				cond = v->number ? NONZERO : ZERO;
			record_exit(a, s, cond);
		}
	}
	for (i = 0; i < b->nr_edges; ++i) {
		const struct value *test = phi_value(b->edges[i].test, pred);
		enum value_kind kind = value_kind(test);
		bool truth = b->edges[i].truth;
		struct state next = clone_state(s);

		if (kind == VALUE_INTEGER) {
			bool v = test->number != 0;

			if (v != truth) { destroy_state(&next); continue; }
		} else if (kind == VALUE_CALL) {
			resolve_pending(a->ctx, f, &next, test->call,
					truth ? NONZERO : ZERO, &a->exits_known);
		} else if (kind == VALUE_TEST) {
			const struct value *left = phi_value(test->left, pred);
			const struct value *right = phi_value(test->right, pred);
			bool eq = test->eq;

			if (value_kind(left) == VALUE_CALL &&
			    value_kind(right) == VALUE_INTEGER &&
			    right->number_valid && right->number == 0)
				resolve_pending(a->ctx, f, &next, left->call,
						truth == eq ? ZERO : NONZERO, &a->exits_known);
		}
		walk(a, b->edges[i].block, block, &next, depth + 1);
		destroy_state(&next);
	}
	a->visited[block] = 0;
}

static unsigned int owned_depth(const struct state *s, const struct expression *lock)
{
	unsigned int i;

	for (i = 0; i < s->nr_ownership; ++i)
		if (s->ownership[i].lock == lock)
			return s->ownership[i].depth;
	return 0;
}

static bool has_pending(const struct state *s, const struct pending *pending)
{
	unsigned int i;

	for (i = 0; i < s->nr_pending; ++i)
		if (s->pending[i].site == pending->site && same(&s->pending[i].fact, &pending->fact))
			return true;
	return false;
}

/* A must-analysis meet: ownership mode and minimum nesting depth can only
 * weaken when another predecessor becomes reachable. Pending acquisitions
 * survive only when the same unresolved event reaches every predecessor.
 */
static bool meet_ownership(struct state *old, const struct state *incoming)
{
	struct facts held = {};
	unsigned int i, depth;
	bool changed;

	merge(&held, &old->held);
	intersect_ownership(&held, &incoming->held);
	changed = !equal_sets(&held, &old->held);
	clear(&old->held);
	old->held = held;
	for (i = 0; i < old->nr_ownership; ++i) {
		struct ownership *o = &old->ownership[i];
		struct fact fact = { ENTRY_HELD, o->mode, ALWAYS, o->lock };
		unsigned int j;

		depth = 0;
		for (j = 0; j < old->held.n; ++j)
			if (old->held.v[j].lock == o->lock) {
				fact = old->held.v[j];
				depth = owned_depth(incoming, o->lock);
				if (depth > o->depth)
					depth = o->depth;
				break;
			}
		changed |= o->depth != depth || (depth && o->mode != fact.mode);
		o->depth = depth;
		o->mode = fact.mode;
		o->delta = 0;
	}
	i = 0;
	while (i < old->nr_pending) {
		if (has_pending(incoming, &old->pending[i])) {
			++i;
		} else {
			old->pending[i] = old->pending[--old->nr_pending];
			changed = true;
		}
	}
	return changed;
}

static bool ownership_edge(struct analysis *a, const struct edge *edge, struct state *s)
{
	const struct value *test = phi_value(edge->test, UINT_MAX);
	enum value_kind kind = value_kind(test);

	/* A PHI depending on the predecessor remains unknown after a join. */
	if (kind == VALUE_INTEGER)
		return (test->number != 0) == edge->truth;
	if (kind == VALUE_CALL)
		resolve_pending(a->ctx, a->f, s, test->call,
				edge->truth ? NONZERO : ZERO, &a->exits_known);
	if (kind == VALUE_TEST) {
		const struct value *left = phi_value(test->left, UINT_MAX);
		const struct value *right = phi_value(test->right, UINT_MAX);

		if (value_kind(left) == VALUE_CALL && value_kind(right) == VALUE_INTEGER &&
		    right->number_valid && !right->number)
			resolve_pending(a->ctx, a->f, s, left->call,
					edge->truth == test->eq ? ZERO : NONZERO, &a->exits_known);
	}
	return true;
}

/* Cycles prevent complete exit effects in the bounded path interpreter, but
 * need not destroy must-held entry proofs. Solve ownership separately to a
 * fixed point, visiting all reachable predecessors without certifying exits.
 */
static bool derive_site_ownership(struct context *c, struct function *f)
{
	struct analysis a = { .ctx = c, .f = f };
	struct state *inputs = resize(NULL, f->nr_blocks, sizeof(*inputs));
	bool *reached = resize(NULL, f->nr_blocks, sizeof(*reached));
	bool *queued = resize(NULL, f->nr_blocks, sizeof(*queued));
	unsigned int *queue = resize(NULL, f->nr_blocks, sizeof(*queue));
	unsigned int i, j, head = 0, tail = 0, count = 0, visits = 0;
	const char *reason = f->reason;
	bool complete = true;

	memset(inputs, 0, f->nr_blocks * sizeof(*inputs));
	memset(reached, 0, f->nr_blocks * sizeof(*reached));
	memset(queued, 0, f->nr_blocks * sizeof(*queued));
	for (i = 0; i < f->nr_blocks; ++i)
		for (j = 0; j < f->blocks[i].nr_sites; ++j) {
			clear(&f->blocks[i].sites[j].held);
			f->blocks[i].sites[j].visited = false;
		}
	f->nr_visited_sites = 0;
	if (f->nr_blocks) {
		inputs[0] = entry_state(f);
		inputs[0].ownership_only = true;
		reached[0] = queued[0] = true;
		queue[tail++] = 0;
		tail %= f->nr_blocks;
		count = 1;
	}
	while (count) {
		unsigned int block = queue[head++];
		struct block *b = &f->blocks[block];
		struct state state = clone_state(&inputs[block]);

		head %= f->nr_blocks;
		--count;
		queued[block] = false;
		if (++visits > MAX_PATHS) {
			destroy_state(&state);
			complete = false;
			break;
		}
		for (i = 0; i < b->nr_sites; ++i)
			process_call(&a, &b->sites[i], &state);
		for (i = 0; i < b->nr_edges; ++i) {
			unsigned int next_block = b->edges[i].block;
			struct state next = clone_state(&state);
			bool changed;

			if (!ownership_edge(&a, &b->edges[i], &next)) {
				destroy_state(&next);
				continue;
			}
			if (next_block >= f->nr_blocks) {
				destroy_state(&next);
				complete = false;
				continue;
			}
			if (!reached[next_block]) {
				inputs[next_block] = next;
				reached[next_block] = true;
				changed = true;
			} else {
				changed = meet_ownership(&inputs[next_block], &next);
				destroy_state(&next);
			}
			if (changed && !queued[next_block]) {
				queue[tail++] = next_block;
				tail %= f->nr_blocks;
				++count;
				queued[next_block] = true;
			}
		}
		destroy_state(&state);
	}
	c->ownership_visits += visits;
	for (i = 0; i < f->nr_blocks; ++i) {
		destroy_state(&inputs[i]);
		if (!complete)
			for (j = 0; j < f->blocks[i].nr_sites; ++j)
				clear(&f->blocks[i].sites[j].held);
	}
	f->reason = reason;
	free(inputs); free(reached); free(queued); free(queue);
	return complete;
}

static bool analyze_function(struct context *c, struct function *f)
{
	struct previous_site {
		struct site *site;
		struct facts held;
		bool visited;
	} *previous;
	struct analysis a = { .ctx = c, .f = f, .complete = f->raw_complete,
		.exits_known = f->raw_complete, .exhaustive = true };
	struct state initial = {};
	struct facts effects = {};
	unsigned int i, j, k, nr_previous = 0, old_may = f->may.n;
	bool changed;

	if (!f->defined)
		return false;
	f->notify_callers = false;
	++c->analyses;
	f->nr_visited_sites = 0;
	if (!f->visited_sites && f->nr_sites)
		f->visited_sites = resize(NULL, f->nr_sites, sizeof(*f->visited_sites));
	previous = f->nr_sites ? resize(NULL, f->nr_sites, sizeof(*previous)) : NULL;
	f->reason = !f->covered ? "translation unit did not opt in" :
		!f->raw_complete ? "unsupported IR or contract" : NULL;
	for (i = 0; i < f->nr_blocks; ++i)
		for (j = 0; j < f->blocks[i].nr_sites; ++j) {
			struct site *site = &f->blocks[i].sites[j];

			previous[nr_previous++] = (struct previous_site){ site, site->held, site->visited };
			site->held = (struct facts){};
			site->visited = false;
		}
	initial = entry_state(f);
	a.visited = resize(NULL, f->nr_blocks, 1);
	memset(a.visited, 0, f->nr_blocks);
	if (f->nr_blocks)
		walk(&a, 0, UINT_MAX, &initial, 0);
	if (!a.nr_exits)
		a.complete = a.exits_known = false;
	a.complete &= a.exits_known;
	if (!a.exhaustive)
		derive_site_ownership(c, f);
	if (f->may_incomplete) {
		a.complete = false;
		f->reason = "possible-acquisition propagation is incomplete or budget-limited";
	}
	for (i = 0; i < nr_previous; ++i) {
		struct site *site = previous[i].site;
		struct function *callee = site->callee;

		if (callee && callee->entry_closed &&
		    (site->visited != previous[i].visited ||
		     !equal_order(&site->held, &previous[i].held)))
			callee->entry_dirty = true;
		if (site->visited != previous[i].visited || !equal_order(&site->held, &previous[i].held))
			for (j = 0; j < site->nr_dispatch_targets; ++j)
				site->dispatch_targets[j]->entry_dirty = true;
		clear(&previous[i].held);
	}
	free(previous);
	merge(&effects, &f->declared);
	if (a.exits_known && a.exhaustive) {
		for (i = 0; i < a.nr_exits; ++i)
			for (j = 0; j < a.exits[i].delta.n; ++j) {
				struct fact candidate = a.exits[i].delta.v[j];
				unsigned int condition;

				for (condition = ALWAYS; condition <= NONZERO; ++condition) {
					bool valid = true, seen = false;

					candidate.cond = ALWAYS;
					for (k = 0; k < a.nr_exits; ++k) {
						if (condition && a.exits[k].ret && condition != a.exits[k].ret)
							continue;
						seen = true;
						if (!contains(&a.exits[k].delta, &candidate))
							valid = false;
					}
					if (valid && seen) {
						candidate.cond = condition;
						insert(&effects, candidate);
						if (condition == ALWAYS)
							break;
					}
				}
			}
	}
	f->notify_body = f->complete != a.complete ||
		f->exit_complete != (f->known_contract || a.exits_known) ||
		!equal_order(&f->effects, &effects);
	changed = f->complete != a.complete || f->exit_complete != (f->known_contract || a.exits_known) ||
		!equal_sets(&f->effects, &effects) || old_may != f->may.n;
	f->notify_callers = f->notify_body || old_may != f->may.n;
	f->complete = a.complete;
	f->exit_complete = f->known_contract || a.exits_known;
	clear(&f->effects);
	f->effects = effects;
	for (i = 0; i < a.nr_exits; ++i)
		clear(&a.exits[i].delta);
	free(a.exits); free(a.visited); destroy_state(&initial);
	return changed;
}

static bool derive_entries(struct context *c)
{
	unsigned int i, j;
	bool changed = false;

	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i];
		struct facts entry = {};
		bool seen = false;

		/* C-only caller sets cannot close external/assembly entry paths. */
		if (!f->entry_dirty || !f->entry_closed)
			continue;
		f->entry_dirty = false;
		for (j = 0; j < f->nr_incoming; ++j) {
			struct site *s = f->incoming[j];
			struct facts held = {};
			unsigned int h;

			for (h = 0; h < s->held.n && s->visited; ++h) {
				struct fact fact = s->held.v[h];
				const struct expression *expr = relative(c, fact.lock, s, 0);

				if (expr) { fact.lock = expr; insert(&held, fact); }
			}
			if (!seen) { merge(&entry, &held); seen = true; }
			else intersect_ownership(&entry, &held);
			clear(&held);
		}
		if (!equal_sets(&f->entry, &entry)) {
			changed = true;
			f->dirty = true;
		}
		/* Preserve vector order as well as the logical entry facts. */
		f->dirty |= !equal_order(&f->entry, &entry);
		f->body_dirty |= f->dirty;
		clear(&f->entry);
		f->entry = entry;
	}
	return changed;
}

static int add_tag(struct context *c, unsigned int type, const char *tag)
{
	unsigned int hash = type * 2654435761U, i, slot;
	struct emitted_tag *entry;
	int err;

	for (i = 0; tag[i]; ++i)
		hash = (hash ^ (unsigned char)tag[i]) * 16777619U;
	hash ^= hash >> 16;
	if (!c->emitted_slots || c->tags >= c->emitted_slots * 2) {
		unsigned int slots = c->emitted_slots ? c->emitted_slots * 2 : 4096;
		struct emitted_tag **table = resize(NULL, slots, sizeof(*table));

		memset(table, 0, slots * sizeof(*table));
		for (i = 0; i < c->emitted_slots; ++i) {
			entry = c->emitted[i];
			while (entry) {
				struct emitted_tag *next = entry->next;

				slot = entry->hash & (slots - 1);
				entry->next = table[slot];
				table[slot] = entry;
				entry = next;
			}
		}
		free(c->emitted);
		c->emitted = table;
		c->emitted_slots = slots;
	}
	slot = hash & (c->emitted_slots - 1);
	for (entry = c->emitted[slot]; entry; entry = entry->next)
		if (entry->type == type && !strcmp(entry->name, tag))
			return 0;
	err = btf__add_decl_tag(c->btf, tag, type, -1);

	if (err < 0)
		return err;
	entry = resize(NULL, 1, sizeof(*entry));
	*entry = (struct emitted_tag){ type, hash, copy_string(tag), c->emitted[slot] };
	c->emitted[slot] = entry;
	++c->tags;
	return 0;
}

static int emit_fact(struct context *c, unsigned int type, struct fact f, const char *source)
{
	static const char * const ops[] = { "acquires", "releases", "requires", "excludes", "may_acquire", "entry_held" };
	static const char * const modes[] = { "exclusive", "shared", "generic" };
	static const char * const conds[] = { "always", "ret_eq(0)", "ret_ne(0)" };
	char tag[MAX_EXPR + 128];

	if (!native_expression(c, f.lock, f.op == MAY_ACQUIRE))
		return 0;
	snprintf(tag, sizeof(tag), BPF_CONTEXT_TAG_PREFIX "%s:%s:%s:%s:%s",
		 source, ops[f.op], modes[f.mode], f.lock->text, conds[f.cond]);
	return add_tag(c, type, tag);
}

static unsigned int unique_btf(struct context *c, const char *name, unsigned int kind)
{
	unsigned int end, start = name_range(c->btf_names, c->nr_btf_names, name, &end), id = 0;

	for (; start < end; ++start) {
		const struct btf_type *t = btf__type_by_id(c->btf, c->btf_names[start].id);

		if (btf_kind(t) != kind)
			continue;
		if (kind == BTF_KIND_FUNC && btf__base_btf(c->btf) &&
		    c->btf_names[start].id < btf__type_cnt(btf__base_btf(c->btf)))
			continue;
		if (id)
			return 0;
		id = c->btf_names[start].id;
	}
	return id;
}

static unsigned int unqualified(struct context *c, unsigned int id)
{
	unsigned int depth;

	for (depth = 0; depth < 32 && id; ++depth) {
		const struct btf_type *t = btf__type_by_id(c->btf, id);

		if (!t)
			return 0;
		if (!btf_is_mod(t) && !btf_is_typedef(t) && !btf_is_type_tag(t))
			return id;
		id = t->type;
	}
	return 0;
}

static unsigned int capability_at(struct context *c, unsigned int id, long long offset,
				  unsigned int depth)
{
	const struct btf_type *t;
	unsigned int i, found = 0;

	if (depth > 24 || offset < 0 || !(id = unqualified(c, id)))
		return 0;
	t = btf__type_by_id(c->btf, id);
	if (!offset && c->capabilities[id])
		return id;
	if (btf_is_array(t)) {
		const struct btf_array *a = btf_array(t);
		long long size = btf__resolve_size(c->btf, a->type);

		return size > 0 && offset / size < a->nelems ?
			capability_at(c, a->type, offset % size, depth + 1) : 0;
	}
	if (!btf_is_composite(t))
		return 0;
	for (i = 0; i < btf_vlen(t); ++i) {
		const struct btf_member *m = &btf_members(t)[i];
		long long bits = btf_member_bit_offset(t, i), size;
		unsigned int next;

		if (bits % 8 || btf_member_bitfield_size(t, i))
			continue;
		size = btf__resolve_size(c->btf, m->type);
		if (offset < bits / 8 || size <= 0 || offset - bits / 8 >= size)
			continue;
		next = capability_at(c, m->type, offset - bits / 8, depth + 1);
		if (next && found && next != found)
			return 0;
		if (next)
			found = next;
	}
	return found;
}

struct location { unsigned int type; long long offset; };

/* Find the pointer stored at this address, rejecting overlapping members. */
static unsigned int pointer_at(struct context *c, unsigned int id, long long offset,
			       unsigned int depth)
{
	const struct btf_type *t;
	unsigned int i, found = 0, matches = 0;

	if (depth > 24 || offset < 0 || !(id = unqualified(c, id)))
		return 0;
	t = btf__type_by_id(c->btf, id);
	if (!offset && btf_is_ptr(t))
		return id;
	if (btf_is_array(t)) {
		const struct btf_array *a = btf_array(t);
		long long size = btf__resolve_size(c->btf, a->type);

		return size > 0 && offset / size < a->nelems ?
			pointer_at(c, a->type, offset % size, depth + 1) : 0;
	}
	if (!btf_is_composite(t))
		return 0;
	for (i = 0; i < btf_vlen(t); ++i) {
		const struct btf_member *m = &btf_members(t)[i];
		long long bits = btf_member_bit_offset(t, i), size;

		if (bits % 8 || btf_member_bitfield_size(t, i))
			continue;
		size = btf__resolve_size(c->btf, m->type);
		if (size <= 0 || offset < bits / 8 || offset - bits / 8 >= size)
			continue;
		if (++matches > 1)
			return 0;
		found = pointer_at(c, m->type, offset - bits / 8, depth + 1);
	}
	return found;
}

static bool expression_location(struct context *c, const struct btf_type *proto,
				const char **expr, struct location *loc, unsigned int depth)
{
	const char *s = *expr;
	char *end;

	if (depth > 24)
		return false;
	if (!strncmp(s, "arg(", 4)) {
		unsigned long arg = strtoul(s + 4, &end, 10);
		const struct btf_type *t;
		unsigned int id;

		if (end == s + 4 || *end != ')' || !proto || arg >= btf_vlen(proto))
			return false;
		id = unqualified(c, btf_params(proto)[arg].type);
		t = id ? btf__type_by_id(c->btf, id) : NULL;
		if (!t || !btf_is_ptr(t))
			return false;
		loc->type = t->type;
		loc->offset = 0;
		*expr = end + 1;
		return true;
	}
	if (!strncmp(s, "global(", 7)) {
		char name[MAX_EXPR];
		const char *close = strchr(s + 7, ')');
		unsigned int id;

		if (!close || close - s - 7 >= MAX_EXPR)
			return false;
		memcpy(name, s + 7, close - s - 7);
		name[close - s - 7] = 0;
		id = unique_btf(c, name, BTF_KIND_VAR);
		if (!id)
			return false;
		loc->type = btf__type_by_id(c->btf, id)->type;
		loc->offset = 0;
		*expr = close + 1;
		return true;
	}
	if (!strncmp(s, "add(", 4)) {
		long long offset;

		*expr = s + 4;
		if (!expression_location(c, proto, expr, loc, depth + 1) || **expr != ',')
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
		unsigned int id;

		*expr = s + 5;
		if (!expression_location(c, proto, expr, loc, depth + 1) || **expr != ')')
			return false;
		id = pointer_at(c, loc->type, loc->offset, 0);
		if (!id)
			return false;
		loc->type = btf__type_by_id(c->btf, id)->type;
		loc->offset = 0;
		++*expr;
		return true;
	}
	return false;
}

static bool typed_expression(struct context *c, const struct btf_type *proto,
			     const struct expression *expr, bool allow_load)
{
	struct location loc;
	const char *p = expr->text;
	struct context_token *token = context_token(c, expr);

	if (token)
		return token->valid && token->type;
	return native_expression(c, expr, allow_load) && expression_location(c, proto, &p, &loc, 0) &&
		!*p && capability_at(c, loc.type, loc.offset, 0);
}

static bool spin_expression(struct context *c, struct function *f,
			    const struct expression *lock)
{
	const struct btf_type *proto = f->native_proto ? btf__type_by_id(c->btf, f->native_proto) : NULL;
	struct location loc;
	const char *p;
	unsigned int type;

	/* Classify the captured object without replacing its ownership identity. */
	lock = expand_snapshots(c, f, lock);
	if (!lock)
		return false;
	p = lock->text;
	if (!native_expression(c, lock, true) ||
	    !expression_location(c, proto, &p, &loc, 0) || *p ||
	    !(type = capability_at(c, loc.type, loc.offset, 0)))
		return false;
	return c->spin_capabilities[type];
}

/* A pointer member does not embed its pointee. By-value members and arrays
 * do: a seemingly ordinary object can then overlap an enclosing capability
 * or another union member. Do not use typed separation for those roots.
 */
static void index_embedded_storage(struct context *c)
{
	unsigned int id, i;

	c->storage_layout_complete = true;
	for (id = 1; id < btf__type_cnt(c->btf); ++id) {
		const struct btf_type *t = btf__type_by_id(c->btf, id);

		if (!btf_is_composite(t))
			continue;
		for (i = 0; i < btf_vlen(t); ++i) {
			unsigned int type = btf_members(t)[i].type, depth;

			for (depth = 0; depth < 24; ++depth) {
				if (!(type = unqualified(c, type)))
					break;
				if (!btf_is_array(btf__type_by_id(c->btf, type)))
					break;
				type = btf_array(btf__type_by_id(c->btf, type))->type;
			}
			if (!type || depth == 24) {
				c->storage_layout_complete = false;
				continue;
			}
			if (btf_is_composite(btf__type_by_id(c->btf, type)))
				c->embedded_storage[type] = true;
		}
	}
}

/* Inspect storage, never follow pointer members. All union alternatives count.
 * Unknown layouts, extents and partially modelled arrays may contain a lock.
 */
static bool overlaps_capability_storage(struct context *c, unsigned int type,
					long long offset, long long width, unsigned int depth)
{
	const struct btf_type *t;
	long long size;
	unsigned int i;

	if (depth > 24 || !(type = unqualified(c, type)) || offset < 0 || width <= 0)
		return true;
	t = btf__type_by_id(c->btf, type);
	size = btf__resolve_size(c->btf, type);
	if (size <= 0 || offset > size || width > size - offset || c->capabilities[type])
		return true;
	if (btf_is_array(t)) {
		const struct btf_array *a = btf_array(t);
		long long element = btf__resolve_size(c->btf, a->type), first, last, tail;

		if (element <= 0 || !a->nelems)
			return true;
		first = offset / element;
		last = (offset + width - 1) / element;
		if (last >= a->nelems)
			return true;
		tail = element - offset % element;
		if (overlaps_capability_storage(c, a->type, offset % element,
					       width < tail ? width : tail, depth + 1))
			return true;
		if (last == first)
			return false;
		if (overlaps_capability_storage(c, a->type, 0,
					       (offset + width - 1) % element + 1, depth + 1))
			return true;
		return last > first + 1 &&
			overlaps_capability_storage(c, a->type, 0, element, depth + 1);
	}
	if (!btf_is_composite(t))
		return !(btf_is_int(t) || btf_is_enum(t) || btf_is_enum64(t) ||
			 btf_is_ptr(t) || btf_is_float(t));
	for (i = 0; i < btf_vlen(t); ++i) {
		const struct btf_member *m = &btf_members(t)[i];
		long long start = btf_member_bit_offset(t, i) / 8;
		long long length = btf__resolve_size(c->btf, m->type), begin, end;

		if (length <= 0) {
			if (offset + width > start)
				return true;
			continue;
		}
		if (start >= offset + width || length <= offset - start)
			continue;
		if (btf_member_bitfield_size(t, i) || btf_member_bit_offset(t, i) % 8)
			return true;
		begin = offset > start ? offset : start;
		end = offset + width < start + length ? offset + width : start + length;
		if (overlaps_capability_storage(c, m->type, begin - start, end - begin, depth + 1))
			return true;
	}
	return false;
}

static bool typed_write_disjoint(struct context *c, struct function *f,
				 const struct expression *lock, struct clobber effect)
{
	const struct btf_type *proto = f->native_proto ? btf__type_by_id(c->btf, f->native_proto) : NULL;
	const struct expression *origin;
	struct location owned, written;
	const char *p;
	unsigned int root;

	if (effect.release || !effect.width || !c->storage_layout_complete || !lock->has_snapshot)
		return false;
	/* Expanding a capture recovers its type, not a current pointer value. */
	origin = expand_snapshots(c, f, lock);
	if (!origin)
		return false;
	p = origin->text;
	if (!expression_location(c, proto, &p, &owned, 0) || *p ||
	    !capability_at(c, owned.type, owned.offset, 0))
		return false;
	origin = expand_snapshots(c, f, effect.address);
	if (!origin)
		return false;
	p = origin->text;
	if (!expression_location(c, proto, &p, &written, 0) || *p ||
	    !(root = unqualified(c, written.type)) ||
	    !btf_is_composite(btf__type_by_id(c->btf, root)) || c->embedded_storage[root])
		return false;
	return !overlaps_capability_storage(c, root, written.offset, effect.width, 0);
}

static bool address_base(const struct expression *expr, char *base, long long *offset)
{
	char text[MAX_EXPR];
	char *s = text;

	if (!expr)
		return false;
	strcpy(text, expr->text);
	*offset = 0;
	while (!strncmp(s, "add(", 4)) {
		char *comma = strrchr(s, ','), *end;
		long long n;

		if (!comma)
			return false;
		errno = 0;
		n = strtoll(comma + 1, &end, 10);
		if (errno || end == comma + 1 || strcmp(end, ")") ||
		    (n > 0 && *offset > LLONG_MAX - n) ||
		    (n < 0 && *offset < LLONG_MIN - n))
			return false;
		*offset += n;
		*comma = 0;
		s += 4;
	}
	strcpy(base, s);
	return true;
}

static long long lock_width(struct context *c, struct function *f, const struct expression *expr)
{
	const struct btf_type *proto = f->native_proto ? btf__type_by_id(c->btf, f->native_proto) : NULL;
	struct location loc;
	const char *p;
	unsigned int id;

	expr = expand_snapshots(c, f, expr);
	if (!expr)
		return 0;
	p = expr->text;
	if (!expression_location(c, proto, &p, &loc, 0) || *p)
		return 0;
	id = capability_at(c, loc.type, loc.offset, 0);
	return id ? btf__resolve_size(c->btf, id) : 0;
}

static bool clobber_aliases(struct context *c, struct function *f,
			    const struct expression *lock, struct clobber effect)
{
	struct context_token *left, *right;
	char a[MAX_EXPR], b[MAX_EXPR];
	long long x, y, size, width;

	if (!effect.address)
		return true;
	left = context_token(c, lock);
	right = context_token(c, effect.address);
	if (effect.release && ((left && left->valid) || (right && right->valid)))
		return lock == effect.address;
	/* Raw stores may implement a symbolic context's low-level transition. */
	if (left || right)
		return true;
	if (typed_write_disjoint(c, f, lock, effect))
		return false;
	if (!address_base(lock, a, &x) || !address_base(effect.address, b, &y))
		return true;
	/* A declared release changes ownership of that instance, not every
	 * capability whose storage contains it. Raw writes still use extents.
	 * Equal addresses remain potentially aliased wrapper capabilities.
	 */
	if (effect.release && !strcmp(a, b))
		return x == y;
	width = effect.release ? lock_width(c, f, effect.address) : effect.width;
	size = lock_width(c, f, lock);
	if (strcmp(a, b)) {
		if (!strncmp(a, "global(", 7) && !strncmp(b, "global(", 7) &&
		    x >= 0 && y >= 0 && size > 0 && width > 0) {
			unsigned int ae, be, ai, bi;
			struct name_id *left, *right;
			size_t alen = strlen(a), blen = strlen(b);

			if (alen < 9 || blen < 9 || a[alen - 1] != ')' || b[blen - 1] != ')')
				return true;
			a[alen - 1] = b[blen - 1] = 0;
			ai = name_range(c->elf_names, c->nr_elf_names, a + 7, &ae);
			bi = name_range(c->elf_names, c->nr_elf_names, b + 7, &be);
			if (ae != ai + 1 || be != bi + 1)
				return true;
			left = &c->elf_names[ai]; right = &c->elf_names[bi];
			if ((left->id & 255) != STT_OBJECT || (right->id & 255) != STT_OBJECT ||
			    left->section != right->section ||
			    (unsigned long long)x > left->size || (unsigned long long)size > left->size - x ||
			    (unsigned long long)y > right->size || (unsigned long long)width > right->size - y ||
			    left->address > ULLONG_MAX - left->size || right->address > ULLONG_MAX - right->size)
				return true;
			return !(left->address + left->size <= right->address ||
				 right->address + right->size <= left->address);
		}
		/* Distinct pointer arguments may alias; fresh stack objects cannot. */
		return strncmp(a, "local(", 6) && strncmp(b, "local(", 6);
	}
	if (width > 0 && y <= LLONG_MAX - width && y + width <= x)
		return false;
	if (size > 0 && x <= LLONG_MAX - size && x + size <= y)
		return false;
	return true;
}

static int emit_types(struct context *c)
{
	struct document *doc;

	for (doc = c->documents; doc; doc = doc->next) {
		struct cj_doc *d = &doc->json;
		unsigned int a = cj_get(d, 1, "types"), i;

		cj_each(d, a, i) {
			char *name = string_field(d, i, "name"), *cap = string_field(d, i, "capability");
			bool un = cj_equal(d, cj_get(d, i, "record_kind"), "union");
			unsigned int id = unique_btf(c, name, un ? BTF_KIND_UNION : BTF_KIND_STRUCT);
			const struct btf_type *t = id ? btf__type_by_id(c->btf, id) : NULL;
			unsigned int fields = cj_get(d, i, "fields"), f, n = 0;
			bool matches = t && fields && btf_vlen(t) == d->tokens[fields].children &&
				(long long)t->size * 8 == cj_number(d, cj_get(d, i, "size_bits"), -1);
			char tag[MAX_EXPR];
			int err = 0;

			cj_each(d, fields, f) {
				char *field = string_field(d, f, "name");

				if (matches && (strcmp(field, btf__name_by_offset(c->btf, btf_members(t)[n].name_off)) ||
					btf_member_bit_offset(t, n) != cj_number(d, cj_get(d, f, "offset_bits"), -1)))
					matches = false;
				free(field); ++n;
			}
			if (matches && *cap && strlen(cap) < MAX_EXPR - 64 && !strchr(cap, ':')) {
				c->capabilities[id] = true;
				c->spin_capabilities[id] = !strcmp(cap, "spinlock") || !strcmp(cap, "raw_spinlock");
				snprintf(tag, sizeof(tag), BPF_CONTEXT_TAG_PREFIX "capability:%s", cap);
				err = add_tag(c, id, tag);
				if (!err && cj_bool(d, cj_get(d, i, "reentrant"))) {
					c->reentrant[id] = true;
					err = add_tag(c, id, BPF_CONTEXT_TAG_PREFIX "reentrant");
				}
				if (!err && cj_bool(d, cj_get(d, i, "scoped")))
					err = add_tag(c, id, BPF_CONTEXT_TAG_PREFIX "scoped");
			}
			free(name); free(cap);
			if (err)
				return err;
		}
	}
	return 0;
}

static bool has_tag(struct context *c, unsigned int target, const char *name)
{
	unsigned int i;

	for (i = 1; i < btf__type_cnt(c->btf); ++i) {
		const struct btf_type *t = btf__type_by_id(c->btf, i);

		if (btf_is_decl_tag(t) && t->type == target && btf_decl_tag(t)->component_idx == -1 &&
		    !strcmp(btf__name_by_offset(c->btf, t->name_off), name))
			return true;
	}
	return false;
}

/* Abstract capability instances have BTF identities but no ELF storage. */
static int emit_tokens(struct context *c)
{
	unsigned int i;

	for (i = 0; i < c->nr_tokens; ++i) {
		struct context_token *token = &c->tokens[i];
		char name[MAX_EXPR], tag[MAX_EXPR];
		int id, err;
		bool new_definition = false;

		if (!token->valid)
			continue;
		snprintf(name, sizeof(name), "__bpf_context_token_%s", token->name);
		snprintf(tag, sizeof(tag), BPF_CONTEXT_TAG_PREFIX "token:%s", token->name);
		id = btf__find_by_name_kind(c->btf, name, BTF_KIND_STRUCT);
		if (id >= 0) {
			const struct btf_type *t = btf__type_by_id(c->btf, id);
			bool matches = !t->size && !btf_vlen(t) && has_tag(c, id, tag);

			snprintf(tag, sizeof(tag), BPF_CONTEXT_TAG_PREFIX "capability:%s", token->capability);
			matches &= has_tag(c, id, tag);
			matches &= has_tag(c, id, BPF_CONTEXT_TAG_PREFIX "reentrant") == token->reentrant;
			if (!matches) {
				token->valid = false;
				continue;
			}
		} else {
			if (id != -ENOENT)
				return id;
			id = btf__add_struct(c->btf, name, 0);
			if (id < 0)
				return id;
			new_definition = true;
		}
		/* Local references preserve token identities and properties when a
		 * module's base BTF is distilled. String-only function expressions
		 * would otherwise leave the base token type unreferenced.
		 */
		if (new_definition || (btf__base_btf(c->btf) &&
		    (unsigned int)id < btf__type_cnt(btf__base_btf(c->btf)))) {
			snprintf(tag, sizeof(tag), BPF_CONTEXT_TAG_PREFIX "token:%s", token->name);
			err = add_tag(c, id, tag);
			snprintf(tag, sizeof(tag), BPF_CONTEXT_TAG_PREFIX "capability:%s", token->capability);
			err = err ?: add_tag(c, id, tag);
			if (!err && token->reentrant)
				err = add_tag(c, id, BPF_CONTEXT_TAG_PREFIX "reentrant");
			if (err)
				return err;
		}
		token->type = id;
		c->capabilities[id] = true;
		c->reentrant[id] = token->reentrant;
	}
	return 0;
}

static bool reentrant_expression(struct context *c, struct function *f,
				 const struct expression *expr)
{
	struct context_token *token = context_token(c, expr);
	struct location loc;
	const struct btf_type *proto;
	const char *p = expr->text;
	unsigned int type;

	if (token)
		return token->valid && token->reentrant;
	expr = expand_snapshots(c, f, expr);
	if (!expr)
		return false;
	p = expr->text;
	proto = f->native_proto ? btf__type_by_id(c->btf, f->native_proto) : NULL;
	if (!expression_location(c, proto, &p, &loc, 0) || *p)
		return false;
	type = capability_at(c, loc.type, loc.offset, 0);
	return type && c->reentrant[type];
}

/* Positive path certificates deliberately stop at the first ordinary call.
 * They never inherit the speculative transitive may set. Unsupported prefixes
 * and exhausted budgets withhold witnesses without changing completeness.
 */
static bool merge_witness_guard(struct acquisition_witness *to,
				const struct acquisition_witness *from)
{
	if (!from->guard)
		return true;
	if (!to->guard) {
		to->guard = from->guard;
		to->bits = from->bits;
		to->mask = from->mask;
		to->value = from->value;
		return true;
	}
	if (to->guard != from->guard || to->bits != from->bits ||
	    ((to->value ^ from->value) & to->mask & from->mask))
		return false;
	to->value |= from->value;
	to->mask |= from->mask;
	return true;
}

static bool witness_edge(struct acquisition_witness *guard, const struct edge *edge,
			 unsigned int pred)
{
	const struct value *v = phi_value(edge->test, pred), *left, *right, *load;
	struct acquisition_witness next = {};
	unsigned long long mask, number;
	bool eq;

	if (!v)
		return true;
	if (v->kind == VALUE_INTEGER && v->number_valid)
		return !!v->number == edge->truth;
	if (v->kind != VALUE_TEST)
		return false;
	left = phi_value(v->left, pred);
	right = phi_value(v->right, pred);
	if (!left || !right || right->kind != VALUE_INTEGER || !right->number_valid)
		return false;
	number = right->number;
	/* Only zero comparisons are represented without integer-cast ambiguity. */
	if (number)
		return false;
	load = left;
	mask = ULLONG_MAX;
	if (left->kind == VALUE_AND) {
		load = left->left;
		right = left->right;
		if (load && load->kind == VALUE_INTEGER) {
			load = left->right;
			right = left->left;
		}
		if (!right || right->kind != VALUE_INTEGER || !right->number_valid)
			return false;
		mask = right->number;
	}
	if (!load || load->kind != VALUE_LOAD || !load->bits || load->bits > 64 ||
	    !load->address || !load->address->has_arg || load->address->has_load || load->address->has_snapshot ||
	    load->address->has_local)
		return false;
	if (left->kind == VALUE_AND && load->bits < 64 && (mask >> load->bits))
		return false; /* Do not guess integer extension semantics. */
	mask &= load->bits == 64 ? ULLONG_MAX : (1ULL << load->bits) - 1;
	eq = v->eq == edge->truth;
	if (number & ~mask)
		return !eq;
	if (!eq) {
		/* A one-bit inequality is another equality. Wider disjunctions are
		 * intentionally unsupported rather than guessed to be feasible.
		 */
		if (!mask || (mask & (mask - 1)))
			return false;
		number ^= mask;
	}
	next.guard = load->address;
	next.bits = load->bits;
	next.mask = mask;
	next.value = number;
	return merge_witness_guard(guard, &next);
}

static void save_witness(struct function *f, struct acquisition_witness w)
{
	unsigned int i;

	if (!w.lock || !w.via)
		return;
	for (i = 0; i < f->nr_witnesses; ++i)
		if (f->witnesses[i].lock == w.lock && f->witnesses[i].mode == w.mode) {
			free(w.via);
			return; /* One sufficient path per lock/mode. */
		}
	if (f->nr_witnesses == 8) {
		free(w.via);
		return;
	}
	f->witnesses = resize(f->witnesses, f->nr_witnesses + 1, sizeof(*f->witnesses));
	f->witnesses[f->nr_witnesses++] = w;
}

static void derive_witnesses(struct context *c, struct function *f, unsigned int depth);

static void witness_block(struct context *c, struct function *f, unsigned int block,
			  unsigned int pred, unsigned long long visited,
			  struct acquisition_witness guard, unsigned int *budget,
			  unsigned int depth)
{
	struct block *b;
	unsigned int i, j;

	if (block >= f->nr_blocks || block >= 64 || (visited & (1ULL << block)) || !*budget)
		return;
	--*budget;
	visited |= 1ULL << block;
	b = &f->blocks[block];
	for (i = 0; i < b->nr_sites; ++i) {
		struct site *s = &b->sites[i];
		struct function *g = s->callee;

		if (s->capture)
			continue;
		if (s->write || !s->witness_prefix_safe || !g)
			return;
		derive_witnesses(c, g, depth + 1);
		for (j = 0; j < g->nr_witnesses; ++j) {
			struct acquisition_witness w = g->witnesses[j], combined = guard;
			char via[512];
			int n;

			w.lock = substitute(c, w.lock, s);
			if (w.guard)
				w.guard = substitute(c, w.guard, s);
			if (!w.lock || w.lock->has_load || w.lock->has_snapshot || w.lock->has_local ||
			    (g->witnesses[j].guard && !w.guard) || !merge_witness_guard(&combined, &w))
				continue;
			n = snprintf(via, sizeof(via), "%s@%u/%s", f->name, s->id, w.via);
			if (n < 0 || n >= sizeof(via))
				continue;
			combined.lock = w.lock;
			combined.mode = w.mode;
			combined.via = copy_string(via);
			save_witness(f, combined);
		}
		return; /* Never assume that an earlier call returns or preserves guards. */
	}
	if (!b->witness_tail_safe)
		return;
	for (i = 0; i < b->nr_edges; ++i) {
		struct acquisition_witness next = guard;

		if (witness_edge(&next, &b->edges[i], pred))
			witness_block(c, f, b->edges[i].block, block, visited, next, budget, depth);
	}
}

static void derive_witnesses(struct context *c, struct function *f, unsigned int depth)
{
	unsigned int i, budget = 128;

	if (f->witness_state || depth >= 16 || !symbolic_name(f->name))
		return;
	f->witness_state = 1;
	/* This is the explicit trust boundary: a declared acquisition contract,
	 * not an independently proved implementation of the locking primitive.
	 */
	if (f->known_contract) {
		for (i = 0; i < f->declared.n; ++i)
			if (f->declared.v[i].op == REQUIRE)
				break;
		if (i == f->declared.n)
			for (i = 0; i < f->declared.n; ++i) {
				struct fact fact = f->declared.v[i];
				char via[256];

				if (fact.op != ACQUIRE || fact.cond != ALWAYS || strlen(f->name) > 240)
					continue;
				snprintf(via, sizeof(via), "%s[declared]", f->name);
				save_witness(f, (struct acquisition_witness){ .lock = fact.lock,
					.mode = fact.mode, .via = copy_string(via) });
			}
	}
	if (f->defined && f->witness_covered && f->nr_blocks <= 64)
		witness_block(c, f, 0, UINT_MAX, 0, (struct acquisition_witness){}, &budget, depth);
	f->witness_state = 2;
}

/* Resolve a scalar field exactly; unions and partial/bitfield reads stay unknown. */
static bool witness_scalar(struct context *c, unsigned int type, long long offset,
			   unsigned int bits, unsigned long long value, unsigned int depth)
{
	const struct btf_type *t;
	unsigned int i;

	if (depth > 24 || offset < 0 || !(type = unqualified(c, type)))
		return false;
	t = btf__type_by_id(c->btf, type);
	if (btf_is_int(t) || btf_is_enum(t) || btf_is_enum64(t))
		return !offset && bits == 8 * btf__resolve_size(c->btf, type) &&
			!(btf_is_int(t) && (btf_int_encoding(t) & BTF_INT_BOOL) && value > 1);
	if (!btf_is_struct(t))
		return false;
	for (i = 0; i < btf_vlen(t); ++i) {
		long long start = btf_member_bit_offset(t, i) / 8;
		long long size = btf__resolve_size(c->btf, btf_members(t)[i].type);

		if (offset >= start && size > 0 && offset - start < size &&
		    !(btf_member_bit_offset(t, i) % 8) && !btf_member_bitfield_size(t, i))
			return witness_scalar(c, btf_members(t)[i].type, offset - start, bits, value, depth + 1);
	}
	return false;
}

static int emit_witnesses(struct context *c, struct function *f, unsigned int id)
{
	static const char * const modes[] = { "exclusive", "shared", "generic" };
	unsigned int i, before = c->witness_tags;

	derive_witnesses(c, f, 0);
	for (i = 0; i < f->nr_witnesses; ++i) {
		struct acquisition_witness *w = &f->witnesses[i];
		const struct btf_type *t = btf__type_by_id(c->btf, id);
		const struct btf_type *proto = btf__type_by_id(c->btf, t->type);
		char tag[1280], guard[MAX_EXPR + 128];
		int n, err;

		if (!typed_expression(c, proto, w->lock, false))
			continue;
		strcpy(guard, "always");
		if (w->guard) {
			struct location loc;
			const char *p = w->guard->text;

			if (!native_expression(c, w->guard, false) ||
			    !expression_location(c, proto, &p, &loc, 0) || *p ||
			    !witness_scalar(c, loc.type, loc.offset, w->bits, w->value, 0))
				continue;
			snprintf(guard, sizeof(guard), "bits_eq(%s,%u,%llu,%llu)",
				 w->guard->text, w->bits, w->mask, w->value);
		}
		n = snprintf(tag, sizeof(tag), BPF_CONTEXT_TAG_PREFIX "witness:%s:%s:%s:%s",
			     modes[w->mode], w->lock->text, guard, w->via);
		if (n < 0 || n >= sizeof(tag))
			continue;
		err = add_tag(c, id, tag);
		if (err)
			return err;
		w->emitted = true;
		++c->witness_tags;
	}
	if (c->witness_tags != before)
		++c->witness_functions;
	return 0;
}

static int emit_functions(struct context *c)
{
	unsigned int i, j;
	int err;

	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i];
		unsigned int id;
		const struct btf_type *t, *proto;
		bool representable = true, stable = true;

		if (!f->defined || !f->live || f->definition != f)
			continue;
		id = unique_symbol(c, f->name) ? unique_btf(c, f->name, BTF_KIND_FUNC) : 0;
		if (!id) {
			if (c->verbose && (f->declared.n || f->may.n || f->entry.n))
				fprintf(stderr, "context-analysis: %s: missing or ambiguous native function identity\n", f->name);
			continue;
		}
		t = btf__type_by_id(c->btf, id);
		proto = btf__type_by_id(c->btf, t->type);
		if (!proto || !btf_is_func_proto(proto) || btf_vlen(proto) != f->nargs)
			continue; /* Do not guess through ABI lowering or implicit kfunc arguments. */
		++c->matched;
		if ((err = emit_witnesses(c, f, id)))
			return err;
		t = btf__type_by_id(c->btf, id);
		proto = btf__type_by_id(c->btf, t->type);
		for (j = 0; j < f->effects.n; ++j) {
			bool declared = contains(&f->declared, &f->effects.v[j]);
			if (typed_expression(c, proto, f->effects.v[j].lock, false)) {
				if ((err = emit_fact(c, id, f->effects.v[j], declared ? "declared" : "derived")))
					return err;
			} else representable = false;
			/* Adding a tag can move the BTF type buffer. */
			t = btf__type_by_id(c->btf, id);
			proto = btf__type_by_id(c->btf, t->type);
		}
		for (j = 0; j < f->may.n; ++j) {
			unsigned int k;

			/* Candidates are analysis work, never runtime positive facts.
			 * A complete runtime summary additionally needs every possible
			 * acquisition covered by an unconditional emitted witness.
			 */
			if (!typed_expression(c, proto, f->may.v[j].lock, true))
				representable = false;
			if (f->may.v[j].lock->has_load)
				stable = false;
			for (k = 0; k < f->nr_witnesses; ++k)
				if (f->witnesses[k].emitted &&
				    f->witnesses[k].lock == f->may.v[j].lock &&
				    f->witnesses[k].mode == f->may.v[j].mode &&
				    !f->witnesses[k].guard &&
				    typed_expression(c, proto, f->witnesses[k].lock, false))
					break;
			if (k == f->nr_witnesses)
				stable = false;
			if (c->verbose > 1 && c->trace_filter && strstr(f->name, c->trace_filter))
				fprintf(stderr, "context-analysis: candidate %s: may_acquire %s %s%s\n",
					f->name, f->may.v[j].mode == EXCLUSIVE ? "exclusive" :
					f->may.v[j].mode == SHARED ? "shared" : "generic",
					f->may.v[j].lock->text,
					k == f->nr_witnesses ? " (unproved)" : " (covered by an unconditional witness)");
		}
		for (j = 0; j < f->entry.n; ++j) {
			if (typed_expression(c, proto, f->entry.v[j].lock, false)) {
				if ((err = emit_fact(c, id, f->entry.v[j], "derived")))
					return err;
				++c->entries;
			} else if (c->verbose) {
				fprintf(stderr, "context-analysis: entry-rejected %s: native capability path unavailable: %s\n",
					f->name, f->entry.v[j].lock->text);
			}
			t = btf__type_by_id(c->btf, id);
			proto = btf__type_by_id(c->btf, t->type);
		}
		if (f->complete && representable && stable) {
			++c->complete;
			if ((err = add_tag(c, id, BPF_CONTEXT_TAG_PREFIX "derived:lock_summary_complete")))
				return err;
		} else {
			++c->incomplete;
			if (c->verbose)
				fprintf(stderr, "context-analysis: %s: incomplete: %s\n", f->name,
					!representable ? "lock identity cannot be represented in native BTF" :
					!stable ? "acquisition candidates are not covered by unconditional runtime witnesses" :
					f->reason ?: "unresolved transitive effects");
		}
	}
	return 0;
}

static void destroy_context(struct context *c)
{
	struct document *d = c->documents;
	unsigned int i, j, k;

	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i];

		for (j = 0; j < f->nr_witnesses; ++j)
			free(f->witnesses[j].via);
		free(f->witnesses);
		free(f->signature);
		free(f->name); clear(&f->declared); clear(&f->effects); clear(&f->may); clear(&f->entry);
		for (j = 0; j < f->nr_blocks; ++j) {
			for (k = 0; k < f->blocks[j].nr_sites; ++k) {
				struct site *s = &f->blocks[j].sites[k];

				free(s->dispatch_key); free(s->signature); free(s->dispatch_targets);
				free(s->args); free(s->substitutions); clear(&s->held);
			}
			for (k = 0; k < f->blocks[j].nr_edges; ++k)
				free_value(f->blocks[j].edges[k].test);
			free(f->blocks[j].edges);
			free_value(f->blocks[j].ret);
			free(f->blocks[j].sites);
		}
		free(f->blocks); free(f->incoming); free(f->visited_sites);
		free(f->memory_clobbers.v); free(f->spin_clobbers.v); free(f->snapshots);
	}
	while (d) {
		struct document *next = d->next;

		free(d->json.text); free(d->json.tokens); free(d->json.functions); free(d);
		d = next;
	}
	for (i = 0; i < c->nr_elf_names; ++i)
		free((char *)c->elf_names[i].name);
	for (i = 0; i < c->nr_btf_names; ++i)
		free((char *)c->btf_names[i].name);
	for (i = 0; i < c->emitted_slots; ++i) {
		struct emitted_tag *entry = c->emitted[i];

		while (entry) {
			struct emitted_tag *next = entry->next;

			free(entry->name); free(entry); entry = next;
		}
	}
	free(c->emitted);
	for (i = 0; i < c->expression_slots; ++i) {
		struct expression *e = c->expressions[i];

		while (e) {
			struct expression *next = e->next;

			free(e);
			e = next;
		}
	}
	free(c->expressions);
	for (i = 0; i < c->nr_tokens; ++i) {
		free(c->tokens[i].name);
		free(c->tokens[i].capability);
	}
	free(c->tokens); free(c->reentrant);
	free(c->spin_capabilities);
	free(c->embedded_storage);
	free(c->functions); free(c->names); free(c->elf_names); free(c->btf_names); free(c->capabilities);
	for (i = 0; i < c->nr_entry_references; ++i) {
		free(c->entry_references[i].target);
		free(c->entry_references[i].caller);
	}
	free(c->entry_references);
	for (i = 0; i < c->nr_dispatch_bindings; ++i) {
		free(c->dispatch_bindings[i].holder); free(c->dispatch_bindings[i].target);
		free(c->dispatch_bindings[i].table);
	}
	for (i = 0; i < c->nr_dispatch_keys; ++i) {
		free(c->dispatch_keys[i].name); free(c->dispatch_keys[i].table);
	}
	free(c->dispatch_bindings); free(c->dispatch_keys);
}

static void report_entries(struct context *c)
{
	unsigned int i, j, closed = 0, escaped = 0, live = 0, with_held_call = 0, proven = 0;
	unsigned int external = 0, limited = 0, incomplete = 0;

	if (!c->verbose)
		return;
	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i];
		unsigned int held_calls = 0;

		const char *reason = NULL;

		if (!f->defined)
			continue;
		limited += f->may_budget;
		incomplete += f->may_incomplete;
		if (!f->local && !f->entry_closed) {
			++external;
			if (c->verbose > 1 && f->live)
				fprintf(stderr, "context-analysis: entry-rejected %s: external caller set is not closed\n", f->name);
			continue;
		}
		if (f->escaped) {
			++escaped;
			if (c->verbose > 1 && f->live)
				fprintf(stderr, "context-analysis: entry-rejected %s: address or assembly escape\n", f->name);
			continue;
		}
		++closed;
		if (!f->live || !f->native_proto) {
			if (c->verbose > 1 && (f->live || f->entry.n))
				fprintf(stderr, "context-analysis: entry-rejected %s: no surviving unambiguous native prototype\n", f->name);
			continue;
		}
		++live;
		for (j = 0; j < f->nr_incoming; ++j)
			held_calls += f->incoming[j]->visited && f->incoming[j]->held.n;
		with_held_call += held_calls != 0;
		proven += f->entry.n != 0;
		if (held_calls)
			fprintf(stderr, "context-analysis: entry candidate %s: %u/%u call sites carry ownership, %u common facts\n",
				f->name, held_calls, f->nr_incoming, f->entry.n);
		if (!f->entry.n) {
			reason = !f->nr_incoming ? "no observed callers" :
				!held_calls ? "no caller retains proven ownership" :
				held_calls < f->nr_incoming ? "some callers have no proven ownership" :
				"no common lock expressible in the callee context";
			if (c->verbose > 1) {
				fprintf(stderr, "context-analysis: entry-rejected %s: %s\n", f->name, reason);
				if (held_calls)
					for (j = 0; j < f->nr_incoming; ++j) {
						struct site *s = f->incoming[j];

						fprintf(stderr, "context-analysis: entry-input %s: caller=%s call=%u visited=%s held=%u\n",
							f->name, s->caller->name, s->id, s->visited ? "yes" : "no", s->held.n);
					}
			}
		}
	}
	fprintf(stderr, "context-analysis: entry analysis: %u escaped locals, %u closed functions, "
		"%u native closed functions, %u with an owned call site, %u with common entry ownership\n",
		escaped, closed, live, with_held_call, proven);
	fprintf(stderr, "context-analysis: entry exclusions: %u external definitions; %u definitions reached acquisition budgets, %u definitions affected by those budgets\n",
		external, limited, incomplete);
}

static double elapsed_seconds(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec - start->tv_sec + (now.tv_nsec - start->tv_nsec) / 1e9;
}

int context_btf_generate(const char *path, struct btf *btf, int verbose)
{
	struct context c = {
		.btf = btf, .verbose = verbose,
		.trace_filter = getenv("BPF_CONTEXT_TRACE"),
	};
	unsigned int i, round;
	bool changed = false;
	struct timespec start;
	int err;

	clock_gettime(CLOCK_MONOTONIC, &start);
	err = collect_elf(&c, path);
	if (verbose)
		fprintf(stderr, "context-analysis: collected %u descriptions in %.3fs\n",
			c.nr_functions, elapsed_seconds(&start));
	if (err || !c.nr_functions)
		goto out;
	c.deriving = true;
	resolve_functions(&c);
	qsort(c.entry_references, c.nr_entry_references, sizeof(*c.entry_references), compare_entry_references);
	resolve_dispatches(&c);
	close_entry_callers(&c);
	if (verbose)
		fprintf(stderr, "context-analysis: resolved calls at %.3fs\n", elapsed_seconds(&start));
	c.btf_names = resize(NULL, btf__type_cnt(btf), sizeof(*c.btf_names));
	c.capabilities = resize(NULL, btf__type_cnt(btf) + 5 * c.nr_tokens, sizeof(*c.capabilities));
	memset(c.capabilities, 0, (btf__type_cnt(btf) + 5 * c.nr_tokens) * sizeof(*c.capabilities));
	c.spin_capabilities = resize(NULL, btf__type_cnt(btf) + 5 * c.nr_tokens, sizeof(*c.spin_capabilities));
	memset(c.spin_capabilities, 0, (btf__type_cnt(btf) + 5 * c.nr_tokens) * sizeof(*c.spin_capabilities));
	c.embedded_storage = resize(NULL, btf__type_cnt(btf) + 5 * c.nr_tokens, sizeof(*c.embedded_storage));
	memset(c.embedded_storage, 0, (btf__type_cnt(btf) + 5 * c.nr_tokens) * sizeof(*c.embedded_storage));
	c.reentrant = resize(NULL, btf__type_cnt(btf) + 5 * c.nr_tokens, sizeof(*c.reentrant));
	memset(c.reentrant, 0, (btf__type_cnt(btf) + 5 * c.nr_tokens) * sizeof(*c.reentrant));
	for (i = 1; i < btf__type_cnt(btf); ++i) {
		const struct btf_type *t = btf__type_by_id(btf, i);

		if (btf_is_func(t) || btf_is_struct(t) || btf_is_union(t) || btf_is_var(t))
			c.btf_names[c.nr_btf_names++] = (struct name_id){ copy_string(btf__name_by_offset(btf, t->name_off)), i };
	}
	qsort(c.btf_names, c.nr_btf_names, sizeof(*c.btf_names), compare_names);
	err = emit_tokens(&c);
	err = err ?: emit_types(&c);
	if (err)
		goto out;
	index_embedded_storage(&c);
	for (i = 0; i < c.nr_functions; ++i) {
		struct function *f = &c.functions[i];
		unsigned int id = f->live && unique_symbol(&c, f->name) ?
			unique_btf(&c, f->name, BTF_KIND_FUNC) : 0;
		const struct btf_type *t = id ? btf__type_by_id(btf, id) : NULL;
		const struct btf_type *proto = t ? btf__type_by_id(btf, t->type) : NULL;

		if (proto && btf_is_func_proto(proto) && btf_vlen(proto) == f->nargs)
			f->native_proto = t->type;
	}

	derive_clobbers(&c, false);
	derive_clobbers(&c, true);
	for (i = 0; i < c.nr_functions; ++i)
		c.functions[i].dirty = c.functions[i].body_dirty = c.functions[i].entry_dirty = true;
	for (round = 0; round < MAX_ROUNDS; ++round) {
		changed = false;
		/* Retain the old scan/entry phases and order, but skip bodies whose
		 * inputs have not changed. This also preserves the round budget.
		 */
		for (i = 0; i < c.nr_functions; ++i) {
			struct function *f = &c.functions[i];
			unsigned int j;
			bool may_changed;

			if (!f->dirty)
				continue;
			f->dirty = false;
			/* A body walk already propagates may facts at visited sites. */
			may_changed = !f->body_dirty && refresh_may(&c, f);
			f->notify_callers = f->notify_body = false;
			if (f->body_dirty) {
				f->body_dirty = false;
				changed |= analyze_function(&c, f);
			}
			changed |= may_changed;
			f->notify_callers |= may_changed;
			if (!f->notify_callers)
				continue;
			for (j = 0; j < f->nr_incoming; ++j) {
				struct function *caller = f->incoming[j]->caller;

				caller->dirty = true;
				caller->body_dirty |= f->notify_body;
			}
		}
		changed |= derive_entries(&c);
		if (verbose)
			fprintf(stderr, "context-analysis: round %u at %.3fs, %llu body analyses, %u expressions\n",
				round + 1, elapsed_seconds(&start), c.analyses, c.nr_expressions);
		if (!changed)
			break;
	}
	if (changed)
		for (i = 0; i < c.nr_functions; ++i) {
			c.functions[i].complete = false;
			clear(&c.functions[i].entry);
			c.functions[i].reason = "fixed-point budget exhausted";
		}
	report_entries(&c);
	if (c.expression_limited) {
		for (i = 0; i < c.nr_functions; ++i)
			c.functions[i].complete = false;
		if (verbose)
			fprintf(stderr, "context-analysis: derived expression budget exhausted; complete summaries withheld\n");
	}
	err = err ?: emit_functions(&c);
	if (verbose)
		fprintf(stderr, "context-analysis: %u function descriptions, %u native matches, "
			"%u complete summaries, %u incomplete summaries, %u entry facts, %u tags; %u rounds\n",
			c.nr_functions, c.matched, c.complete, c.incomplete, c.entries, c.tags, round + 1);
	if (verbose)
		fprintf(stderr, "context-analysis: %u acquisition witnesses in %u native functions; "
			"unwitnessed may-acquire candidates remain unproved\n", c.witness_tags, c.witness_functions);
	if (verbose)
		fprintf(stderr, "context-analysis: %u interned expressions, "
			"%llu substitution cache hits, %llu misses\n",
			c.nr_expressions, c.substitution_hits, c.substitution_misses);
	if (verbose)
		fprintf(stderr, "context-analysis: %llu function body analyses, %llu ownership CFG visits\n",
			c.analyses, c.ownership_visits);
out:
	if (err)
		fprintf(stderr, "context-analysis: failed: %s\n", strerror(-err));
	destroy_context(&c);
	return err;
}
