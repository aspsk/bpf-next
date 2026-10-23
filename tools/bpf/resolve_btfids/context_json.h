/* SPDX-License-Identifier: GPL-2.0-only */
/* Small private reader for the compiler's versioned, build-only JSON. */
#ifndef CONTEXT_JSON_H
#define CONTEXT_JSON_H

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct cj_token {
	size_t start, end;
	unsigned int next, children;
	char kind;
};

struct cj_doc {
	char *text;
	struct cj_token *tokens;
	unsigned int count, capacity;
	unsigned int *functions, nr_functions;
};

static int cj_parse_value(struct cj_doc *d, size_t *pos, unsigned int depth)
{
	struct cj_token t = {};
	unsigned int id;
	char ch;

	if (depth > 128 || d->count == d->capacity)
		return -E2BIG;
	while (isspace((unsigned char)d->text[*pos]))
		++*pos;
	ch = d->text[*pos];
	if (!ch)
		return -EINVAL;
	id = d->count++;
	t.start = *pos;
	t.kind = ch;
	if (ch == '{' || ch == '[') {
		++*pos;
		while (true) {
			while (isspace((unsigned char)d->text[*pos]))
				++*pos;
			if (d->text[*pos] == (ch == '{' ? '}' : ']')) {
				++*pos;
				break;
			}
			if (t.children) {
				char sep = ch == '{' && t.children % 2 ? ':' : ',';
				if (d->text[(*pos)++] != sep)
					return -EINVAL;
			}
			if (cj_parse_value(d, pos, depth + 1) < 0)
				return -EINVAL;
			++t.children;
		}
		if (ch == '{' && t.children % 2)
			return -EINVAL;
	} else if (ch == '"') {
		++*pos;
		while (d->text[*pos] && d->text[*pos] != '"') {
			if ((unsigned char)d->text[*pos] < 32)
				return -EINVAL;
			if (d->text[*pos] == '\\' && !d->text[++*pos])
				return -EINVAL;
			++*pos;
		}
		if (d->text[(*pos)++] != '"')
			return -EINVAL;
	} else {
		while (d->text[*pos] && !strchr(",]} \t\r\n", d->text[*pos]))
			++*pos;
		if (*pos == t.start)
			return -EINVAL;
	}
	t.end = *pos;
	t.next = d->count;
	d->tokens[id] = t;
	return id;
}

static bool cj_equal(const struct cj_doc *d, unsigned int id, const char *s)
{
	const struct cj_token *t = &d->tokens[id];

	return t->kind == '"' && t->end - t->start == strlen(s) + 2 &&
		!memcmp(d->text + t->start + 1, s, strlen(s));
}

static unsigned int cj_get(const struct cj_doc *d, unsigned int object, const char *key)
{
	unsigned int i;

	if (!object || d->tokens[object].kind != '{')
		return 0;
	for (i = object + 1; i < d->tokens[object].next;) {
		unsigned int value = d->tokens[i].next;

		if (cj_equal(d, i, key))
			return value;
		i = d->tokens[value].next;
	}
	return 0;
}

static char *cj_string(const struct cj_doc *d, unsigned int id)
{
	const struct cj_token *t;
	char *s;
	size_t i, j = 0;

	if (!id || d->tokens[id].kind != '"')
		return strdup("");
	t = &d->tokens[id];
	s = malloc(t->end - t->start);
	if (!s)
		return NULL;
	for (i = t->start + 1; i < t->end - 1; ++i) {
		char c = d->text[i];

		if (c == '\\') {
			c = d->text[++i];
			if (c == 'n') c = '\n';
			else if (c == 'r') c = '\r';
			else if (c == 't') c = '\t';
			else if (c != '\\' && c != '"' && c != '/') {
				free(s);
				return strdup("");
			}
		}
		s[j++] = c;
	}
	s[j] = 0;
	return s;
}

static long long cj_number(const struct cj_doc *d, unsigned int id, long long fallback)
{
	char *end;
	long long v;

	if (!id)
		return fallback;
	errno = 0;
	v = strtoll(d->text + d->tokens[id].start, &end, 10);
	return errno || end != d->text + d->tokens[id].end ? fallback : v;
}

static bool cj_bool(const struct cj_doc *d, unsigned int id)
{
	return id && d->tokens[id].end - d->tokens[id].start == 4 &&
		!memcmp(d->text + d->tokens[id].start, "true", 4);
}

#define cj_each(d, a, i) \
	for ((i) = (a) ? (a) + 1 : 0; (a) && (i) < (d)->tokens[a].next; \
	     (i) = (d)->tokens[i].next)

#endif
