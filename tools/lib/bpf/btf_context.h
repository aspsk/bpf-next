/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Private decoder for the versioned context-analysis declaration tags. */
#ifndef __LIBBPF_BTF_CONTEXT_H
#define __LIBBPF_BTF_CONTEXT_H

#include <stdbool.h>
#include <ctype.h>
#include <string.h>

#define BTF_CONTEXT_PREFIX "bpf_context:v1:"
#define BTF_CONTEXT_TAG_MAX 1280

enum btf_context_kind {
	BTF_CONTEXT_EFFECT,
	BTF_CONTEXT_WITNESS,
	BTF_CONTEXT_COMPLETE,
	BTF_CONTEXT_CAPABILITY,
	BTF_CONTEXT_REENTRANT,
	BTF_CONTEXT_SCOPED,
	BTF_CONTEXT_TOKEN,
};

struct btf_context_tag {
	enum btf_context_kind kind;
	const char *source, *effect, *mode, *lock, *condition, *capability, *token, *via;
	char storage[BTF_CONTEXT_TAG_MAX];
};

static inline bool btf_context_parse_tag(const char *name, struct btf_context_tag *tag)
{
	char *p, *fields[5];
	unsigned int i;

	if (!name || strncmp(name, BTF_CONTEXT_PREFIX, sizeof(BTF_CONTEXT_PREFIX) - 1) ||
	    strlen(name) >= sizeof(tag->storage))
		return false;
	memset(tag, 0, sizeof(*tag));
	strcpy(tag->storage, name + sizeof(BTF_CONTEXT_PREFIX) - 1);
	p = tag->storage;
	if (!strcmp(p, "derived:lock_summary_complete")) {
		tag->kind = BTF_CONTEXT_COMPLETE;
		tag->source = "derived";
		return true;
	}
	if (!strncmp(p, "capability:", 11) && p[11] && !strchr(p + 11, ':')) {
		tag->kind = BTF_CONTEXT_CAPABILITY;
		tag->capability = p + 11;
		return true;
	}
	if (!strncmp(p, "token:", 6) && p[6]) {
		const unsigned char *s = (const unsigned char *)p + 6;

		for (; *s; ++s)
			if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
			      (*s >= '0' && *s <= '9') || *s == '_' || *s == '.' || *s == '$'))
				return false;
		tag->kind = BTF_CONTEXT_TOKEN;
		tag->token = p + 6;
		return true;
	}
	if (!strcmp(p, "reentrant") || !strcmp(p, "scoped")) {
		tag->kind = !strcmp(p, "reentrant") ? BTF_CONTEXT_REENTRANT : BTF_CONTEXT_SCOPED;
		return true;
	}
	for (i = 0; i < 5; ++i) {
		char *sep;

		fields[i] = p;
		sep = strchr(p, ':');
		if (!*p || sep == p || (i < 4 && !sep) || (i == 4 && sep))
			return false;
		if (sep) { *sep = 0; p = sep + 1; }
	}
	if (!strcmp(fields[0], "witness")) {
		size_t len = strlen(fields[3]);

		if (strcmp(fields[1], "exclusive") && strcmp(fields[1], "shared") &&
		    strcmp(fields[1], "generic"))
			return false;
		if (strcmp(fields[3], "always") &&
		    (strncmp(fields[3], "bits_eq(", 8) || len < 12 || fields[3][len - 1] != ')'))
			return false;
		tag->kind = BTF_CONTEXT_WITNESS;
		tag->source = "witnessed";
		tag->effect = "may_acquire";
		tag->mode = fields[1]; tag->lock = fields[2];
		tag->condition = fields[3]; tag->via = fields[4];
		return true;
	}
	if (strcmp(fields[0], "declared") && strcmp(fields[0], "derived"))
		return false;
	if (strcmp(fields[1], "requires") && strcmp(fields[1], "excludes") &&
	    strcmp(fields[1], "acquires") && strcmp(fields[1], "releases") &&
	    strcmp(fields[1], "may_acquire") && strcmp(fields[1], "entry_held"))
		return false;
	if (strcmp(fields[2], "exclusive") && strcmp(fields[2], "shared") && strcmp(fields[2], "generic"))
		return false;
	if (strcmp(fields[4], "always") && strncmp(fields[4], "ret_eq(", 7) &&
	    strncmp(fields[4], "ret_ne(", 7))
		return false;
	if (strcmp(fields[4], "always")) {
		p = fields[4] + 7;
		if (*p == '-')
			++p;
		if (!isdigit((unsigned char)*p))
			return false;
		while (isdigit((unsigned char)*p))
			++p;
		if (*p++ != ')' || *p)
			return false;
	}
	tag->kind = BTF_CONTEXT_EFFECT;
	tag->source = fields[0]; tag->effect = fields[1]; tag->mode = fields[2];
	tag->lock = fields[3]; tag->condition = fields[4];
	return true;
}

#endif
