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

struct substitution {
	const struct expression *input, *result;
};

struct site {
	unsigned int id;
	int reference;
	struct function *callee, *caller;
	const struct expression **args;
	unsigned int nargs, propagated_may;
	bool unrepresentable_may;
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

enum value_kind { VALUE_UNKNOWN, VALUE_INTEGER, VALUE_CALL, VALUE_TEST, VALUE_PHI };

struct value;
struct phi_input {
	unsigned int block;
	struct value *value;
};

struct value {
	enum value_kind kind;
	long long number;
	unsigned int call, nr_incoming;
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
};

struct function {
	struct cj_doc *doc;
	char *name;
	unsigned int id, nargs, nr_blocks, nr_sites, native_proto;
	bool local, weak, defined, live, escaped, covered, raw_complete, complete;
	bool known_contract, exit_complete;
	bool memory_covered;
	bool may_incomplete, may_budget;
	unsigned int loaded_may;
	bool clobber_unknown;
	struct clobber *clobbers;
	unsigned int nr_clobbers;
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

struct context_token {
	const struct expression *expr;
	char *name, *capability;
	bool reentrant, valid;
	unsigned int type;
};

struct context {
	struct function *functions;
	unsigned int nr_functions;
	struct document *documents;
	struct name_id *names, *btf_names, *elf_names;
	unsigned int nr_btf_names, nr_elf_names;
	struct btf *btf;
	bool *capabilities, *reentrant;
	struct context_token *tokens;
	unsigned int nr_tokens;
	struct emitted_tag **emitted;
	unsigned int emitted_slots;
	struct expression **expressions;
	unsigned int nr_expressions, expression_slots;
	bool deriving, expression_limited;
	unsigned long long substitution_hits, substitution_misses;
	unsigned long long analyses, ownership_visits;
	int verbose;
	unsigned int tags, matched, complete, incomplete, entries;
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

	if (input->has_local)
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
static struct value *read_value(struct cj_doc *d, unsigned int id)
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
	} else if (cj_equal(d, kind, "test")) {
		v->kind = VALUE_TEST;
		v->eq = cj_equal(d, cj_get(d, id, "predicate"), "eq");
		v->left = read_value(d, cj_get(d, id, "left"));
		v->right = read_value(d, cj_get(d, id, "right"));
	} else if (cj_equal(d, kind, "phi")) {
		v->kind = VALUE_PHI;
		a = cj_get(d, id, "incoming");
		v->nr_incoming = a ? d->tokens[a].children : 0;
		v->incoming = resize(NULL, v->nr_incoming, sizeof(*v->incoming));
		cj_each(d, a, i) {
			v->incoming[n].block = cj_number(d, cj_get(d, i, "block"), UINT_MAX);
			v->incoming[n++].value = read_value(d, cj_get(d, i, "value"));
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
	     cj_number(d, cj_get(d, root, "version"), -1) != 2))
		return -EINVAL;
	if (read_tokens(c, d, cj_get(d, root, "tokens")))
		return -EINVAL;
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
		f->nargs = cj_number(d, cj_get(d, i, "nargs"), 0);
		f->local = cj_bool(d, cj_get(d, i, "local"));
		f->weak = cj_bool(d, cj_get(d, i, "weak"));
		f->defined = cj_bool(d, cj_get(d, i, "defined"));
		f->live = cj_bool(d, cj_get(d, i, "live"));
		f->escaped = cj_bool(d, cj_get(d, i, "escaped")) || !symbolic_name(f->name);
		f->covered = cj_bool(d, cj_get(d, i, "covered"));
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
			{
				unsigned int edges = cj_get(d, b, "edges"), e, n = 0;

				block->nr_edges = edges ? d->tokens[edges].children : 0;
				block->edges = resize(NULL, block->nr_edges, sizeof(*block->edges));
				cj_each(d, edges, e) {
					block->edges[n].block = cj_number(d, cj_get(d, e, "block"), UINT_MAX);
					block->edges[n].truth = cj_bool(d, cj_get(d, e, "true"));
					block->edges[n++].test = read_value(d, cj_get(d, e, "test"));
				}
			}
			block->ret = read_value(d, cj_get(d, b, "return"));
			sites = cj_get(d, b, "calls");
			block->nr_sites = sites ? d->tokens[sites].children : 0;
			f->nr_sites += block->nr_sites;
			block->sites = resize(NULL, block->nr_sites, sizeof(*block->sites));
			memset(block->sites, 0, block->nr_sites * sizeof(*block->sites));
			cj_each(d, sites, s) {
				struct site *site = &block->sites[k++];
				unsigned int args = cj_get(d, s, "arguments"), arg, j = 0;

				site->id = cj_number(d, cj_get(d, s, "id"), UINT_MAX);
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
				kind = GELF_ST_TYPE(sym.st_info);
				if (sym.st_shndx == SHN_UNDEF || (kind != STT_FUNC && kind != STT_OBJECT))
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
		}
		merge(&f->effects, &f->declared);
		for (j = 0; j < f->nr_blocks; ++j)
			for (k = 0; k < f->blocks[j].nr_sites; ++k) {
				struct site *s = &f->blocks[j].sites[k];

				s->caller = f;
				if (s->reference >= 0 && (unsigned int)s->reference < f->doc->nr_functions) {
					struct function *ref = &c->functions[f->doc->functions[s->reference]];

					s->callee = ref->definition;
					/* Keep declaration contracts when no body was collected. */
					if (!s->callee && ref->declared.n)
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

static bool add_clobber(struct function *f, struct clobber effect)
{
	unsigned int i;

	if (f->clobber_unknown)
		return false;
	if (!effect.address || (!effect.release && !effect.width) ||
	    (effect.address->has_local && effect.address->has_load)) {
		f->clobber_unknown = true;
		return true;
	}
	/* This frame's own stack storage cannot be a caller's live lock. */
	if (effect.address->has_local)
		return false;
	for (i = 0; i < f->nr_clobbers; ++i)
		if (f->clobbers[i].address == effect.address &&
		    f->clobbers[i].width == effect.width && f->clobbers[i].release == effect.release)
			return false;
	if (f->nr_clobbers == 128) {
		f->clobber_unknown = true;
		return true;
	}
	f->clobbers = resize(f->clobbers, f->nr_clobbers + 1, sizeof(*f->clobbers));
	f->clobbers[f->nr_clobbers++] = effect;
	return true;
}

/* A may-clobber fixed point, independent of exit/acquisition completeness.
 * Cycles are allowed: unknown effects and possible clobbers only accumulate.
 * Trusted interface contracts describe ownership changes across the call.
 */
static void derive_clobbers(struct context *c)
{
	unsigned int i, j, k, h, round, known = 0;
	bool changed = false;

	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i];

		f->clobber_unknown = !f->known_contract && (!f->defined || !f->memory_covered);
		if (f->known_contract) {
			for (j = 0; j < f->declared.n; ++j)
				if (f->declared.v[j].op == RELEASE)
					add_clobber(f, (struct clobber){ f->declared.v[j].lock, 0, true });
			continue;
		}
		for (j = 0; j < f->nr_blocks; ++j)
			for (k = 0; k < f->blocks[j].nr_sites; ++k) {
				struct site *s = &f->blocks[j].sites[k];

				if (s->write)
					add_clobber(f, (struct clobber){ expand_snapshots(c, f, s->address), s->width, false });
				else if (!s->capture && !s->callee)
					f->clobber_unknown = true;
			}
	}
	for (round = 0; round < MAX_ROUNDS; ++round) {
		changed = false;
		for (i = 0; i < c->nr_functions; ++i) {
			struct function *f = &c->functions[i];

			if (f->known_contract || f->clobber_unknown)
				continue;
			for (j = 0; j < f->nr_blocks && !f->clobber_unknown; ++j)
				for (k = 0; k < f->blocks[j].nr_sites && !f->clobber_unknown; ++k) {
					struct site *s = &f->blocks[j].sites[k];
					struct function *g = s->callee;

					if (s->write || s->capture)
						continue;
					if (!g || g->clobber_unknown) {
						f->clobber_unknown = changed = true;
						break;
					}
					for (h = 0; h < g->nr_clobbers && !f->clobber_unknown; ++h) {
						struct clobber effect = g->clobbers[h];

						effect.address = substitute(c, effect.address, s);
						effect.address = expand_snapshots(c, f, effect.address);
						changed |= add_clobber(f, effect);
					}
				}
		}
		if (!changed)
			break;
	}
	for (i = 0; i < c->nr_functions; ++i) {
		if (changed)
			c->functions[i].clobber_unknown = true;
		known += !c->functions[i].clobber_unknown;
	}
	if (c->verbose)
		fprintf(stderr, "context-analysis: ownership preservation: %u tracked summaries, %u unknown; %u rounds\n",
			known, c->nr_functions - known, round + 1);
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

static void preserve_call(struct context *c, struct function *f, struct state *s,
			  struct site *site)
{
	unsigned int i;
	struct function *g = site->callee;

	if (!g || g->clobber_unknown) {
		destroy_state(s);
		return;
	}
	for (i = 0; i < g->nr_clobbers; ++i) {
		struct clobber effect = g->clobbers[i];

		effect.address = substitute(c, effect.address, site);
		invalidate_clobber(c, f, s, effect);
	}
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

static void process_call(struct analysis *a, struct site *site, struct state *s)
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
			a->f->reason = "unrepresentable lock argument";
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
				struct context_token *left = context_token(a->ctx, f.lock);
				struct context_token *right = context_token(a->ctx, pending);
				bool alias = pending == f.lock ||
					(f.op == RELEASE && !(left && left->valid) && !(right && right->valid));

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

		if (callee && callee->local && !callee->escaped && callee->defined &&
		    (site->visited != previous[i].visited ||
		     !equal_order(&site->held, &previous[i].held)))
			callee->entry_dirty = true;
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
		if (!f->entry_dirty || !f->local || f->escaped || !f->defined)
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
	if (!address_base(lock, a, &x) || !address_base(effect.address, b, &y))
		return true;
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
			if (typed_expression(c, proto, f->may.v[j].lock, true)) {
				if ((err = emit_fact(c, id, f->may.v[j], "derived")))
					return err;
			} else representable = false;
			if (f->may.v[j].lock->has_load)
				stable = false;
			t = btf__type_by_id(c->btf, id);
			proto = btf__type_by_id(c->btf, t->type);
		}
		for (j = 0; j < f->entry.n; ++j) {
			if (typed_expression(c, proto, f->entry.v[j].lock, false)) {
				if ((err = emit_fact(c, id, f->entry.v[j], "derived")))
					return err;
				++c->entries;
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
					!stable ? "pointer-derived lock needs a stable ownership identity" :
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

		free(f->name); clear(&f->declared); clear(&f->effects); clear(&f->may); clear(&f->entry);
		for (j = 0; j < f->nr_blocks; ++j) {
			for (k = 0; k < f->blocks[j].nr_sites; ++k) {
				struct site *s = &f->blocks[j].sites[k];

				free(s->args); free(s->substitutions); clear(&s->held);
			}
			for (k = 0; k < f->blocks[j].nr_edges; ++k)
				free_value(f->blocks[j].edges[k].test);
			free(f->blocks[j].edges);
			free_value(f->blocks[j].ret);
			free(f->blocks[j].sites);
		}
		free(f->blocks); free(f->incoming); free(f->visited_sites); free(f->clobbers); free(f->snapshots);
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
	free(c->functions); free(c->names); free(c->elf_names); free(c->btf_names); free(c->capabilities);
}

static void report_entries(struct context *c)
{
	unsigned int i, j, closed = 0, escaped = 0, live = 0, with_held_call = 0, proven = 0;

	if (!c->verbose)
		return;
	for (i = 0; i < c->nr_functions; ++i) {
		struct function *f = &c->functions[i];
		unsigned int held_calls = 0;

		if (!f->defined || !f->local)
			continue;
		if (f->escaped) {
			++escaped;
			continue;
		}
		++closed;
		if (!f->live || !f->native_proto)
			continue;
		++live;
		for (j = 0; j < f->nr_incoming; ++j)
			held_calls += f->incoming[j]->visited && f->incoming[j]->held.n;
		with_held_call += held_calls != 0;
		proven += f->entry.n != 0;
		if (held_calls)
			fprintf(stderr, "context-analysis: entry candidate %s: %u/%u call sites carry ownership, %u common facts\n",
				f->name, held_calls, f->nr_incoming, f->entry.n);
	}
	fprintf(stderr, "context-analysis: entry analysis: %u escaped locals, %u closed locals, "
		"%u native closed locals, %u with an owned call site, %u with common entry ownership\n",
		escaped, closed, live, with_held_call, proven);
}

static double elapsed_seconds(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec - start->tv_sec + (now.tv_nsec - start->tv_nsec) / 1e9;
}

int context_btf_generate(const char *path, struct btf *btf, int verbose)
{
	struct context c = { .btf = btf, .verbose = verbose };
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
	if (verbose)
		fprintf(stderr, "context-analysis: resolved calls at %.3fs\n", elapsed_seconds(&start));
	c.btf_names = resize(NULL, btf__type_cnt(btf), sizeof(*c.btf_names));
	c.capabilities = resize(NULL, btf__type_cnt(btf) + 5 * c.nr_tokens, sizeof(*c.capabilities));
	memset(c.capabilities, 0, (btf__type_cnt(btf) + 5 * c.nr_tokens) * sizeof(*c.capabilities));
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
	for (i = 0; i < c.nr_functions; ++i) {
		struct function *f = &c.functions[i];
		unsigned int id = f->live && unique_symbol(&c, f->name) ?
			unique_btf(&c, f->name, BTF_KIND_FUNC) : 0;
		const struct btf_type *t = id ? btf__type_by_id(btf, id) : NULL;
		const struct btf_type *proto = t ? btf__type_by_id(btf, t->type) : NULL;

		if (proto && btf_is_func_proto(proto) && btf_vlen(proto) == f->nargs)
			f->native_proto = t->type;
	}

	derive_clobbers(&c);
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
