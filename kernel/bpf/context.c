// SPDX-License-Identifier: GPL-2.0-only
/* Check native entry ownership against proven kfunc acquisition paths. */
#include <linux/bpf_context.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/ctype.h>
#include <linux/log2.h>
#include <linux/overflow.h>
#include <linux/slab.h>

#define CONTEXT_PREFIX "bpf_context:v1:"
#define CONTEXT_DEPTH 3
#define CONTEXT_IDS 256
#define CONTEXT_CONDITIONS 4096
#define CONTEXT_ENTRY_LOCKS 16

struct context_path {
	u32 arg;
	u8 depth, bits;
	bool opaque;
	s32 load[CONTEXT_DEPTH], offset;
	u64 mask;
};

struct context_fact {
	struct context_path lock, guard;
	u64 mask, value;
	bool exclusive, conditional;
};

enum context_condition_kind { CONTEXT_BITS, CONTEXT_OPAQUE };
struct context_condition {
	u32 parent, left, right;
	enum context_condition_kind kind;
	u64 mask, value;
};

struct bpf_context_state {
	struct context_fact entry[CONTEXT_ENTRY_LOCKS];
	u32 nr_entry, nr_ids, nr_conditions;
	bool exhausted;
	struct context_path ids[CONTEXT_IDS];
	struct context_condition conditions[CONTEXT_CONDITIONS];
};

static bool context_path_equal(const struct context_path *a, const struct context_path *b)
{
	return a->arg == b->arg && a->depth == b->depth && a->offset == b->offset &&
	       !memcmp(a->load, b->load, a->depth * sizeof(a->load[0]));
}

static u32 intern_path(struct bpf_context_state *ctx, struct context_path p)
{
	u32 i;

	for (i = 1; i <= ctx->nr_ids; ++i)
		if (context_path_equal(&ctx->ids[i], &p) && ctx->ids[i].bits == p.bits &&
		    ctx->ids[i].mask == p.mask && ctx->ids[i].opaque == p.opaque)
			return i;
	if (ctx->nr_ids + 1 >= CONTEXT_IDS) {
		ctx->exhausted = true;
		return 0;
	}
	ctx->ids[++ctx->nr_ids] = p;
	return ctx->nr_ids;
}

static bool number(const char **s, s32 *result)
{
	const char *p = *s;
	u64 n = 0;
	bool negative = *p == '-';

	p += negative;
	if (!isdigit(*p))
		return false;
	while (isdigit(*p)) {
		n = n * 10 + *p++ - '0';
		if (n > INT_MAX)
			return false;
	}
	*result = negative ? -n : n;
	*s = p;
	return true;
}

static bool parse_path(const char **s, struct context_path *p, u32 depth)
{
	s32 n;

	if (depth > 16)
		return false;
	if (!strncmp(*s, "arg(", 4)) {
		*s += 4;
		if (!number(s, &n) || n < 0 || **s != ')')
			return false;
		p->arg = n + 1;
		++*s;
		return true;
	}
	if (!strncmp(*s, "add(", 4)) {
		*s += 4;
		if (!parse_path(s, p, depth + 1) || *(*s)++ != ',' || !number(s, &n) ||
		    **s != ')' || check_add_overflow(p->offset, n, &p->offset))
			return false;
		++*s;
		return true;
	}
	if (!strncmp(*s, "load(", 5)) {
		*s += 5;
		if (!parse_path(s, p, depth + 1) || **s != ')' || p->depth == CONTEXT_DEPTH)
			return false;
		p->load[p->depth++] = p->offset;
		p->offset = 0;
		++*s;
		return true;
	}
	return false;
}

static bool parse_fact(const char *tag, struct context_fact *fact, bool entry)
{
	char *copy, *rest, *fields[5], *end;
	const char *p;
	int i;
	bool ok = false;

	if (strncmp(tag, CONTEXT_PREFIX, sizeof(CONTEXT_PREFIX) - 1) || strlen(tag) >= 1280)
		return false;
	copy = kstrdup(tag + sizeof(CONTEXT_PREFIX) - 1, GFP_KERNEL_ACCOUNT);
	if (!copy)
		return false;
	rest = copy;
	for (i = 0; i < ARRAY_SIZE(fields); ++i) {
		fields[i] = strsep(&rest, ":");
		if (!fields[i] || !*fields[i])
			goto out;
	}
	if (rest)
		goto out;
	memset(fact, 0, sizeof(*fact));
	if (entry) {
		if ((strcmp(fields[0], "derived") || strcmp(fields[1], "entry_held")) &&
		    (strcmp(fields[0], "declared") || strcmp(fields[1], "requires")))
			goto out;
		if (strcmp(fields[4], "always"))
			goto out;
	} else {
		if (strcmp(fields[0], "witness"))
			goto out;
		/* Witness format: witness:MODE:LOCK:GUARD:VIA. */
		fields[4] = fields[3];
		fields[3] = fields[2];
		fields[2] = fields[1];
	}
	if (strcmp(fields[2], "exclusive") && strcmp(fields[2], "shared"))
		goto out;
	fact->exclusive = !strcmp(fields[2], "exclusive");
	p = fields[3];
	if (!parse_path(&p, &fact->lock, 0) || *p)
		goto out;
	if (!entry && strcmp(fields[4], "always")) {
		s32 bits;
		char *mask, *value;

		p = fields[4];
		if (strncmp(p, "bits_eq(", 8))
			goto out;
		p += 8;
		if (!parse_path(&p, &fact->guard, 0) || *p++ != ',' ||
		    !number(&p, &bits) || bits <= 0 || bits > 64 || *p++ != ',')
			goto out;
		mask = (char *)p;
		value = strchr(mask, ',');
		if (!value)
			goto out;
		*value++ = 0;
		end = strchr(value, ')');
		if (!end || end[1])
			goto out;
		*end = 0;
		if (kstrtou64(mask, 10, &fact->mask) || kstrtou64(value, 10, &fact->value) ||
		    (fact->value & ~fact->mask) || (bits < 64 && fact->mask >> bits))
			goto out;
		fact->guard.bits = bits;
		fact->conditional = true;
	}
	ok = true;
out:
	kfree(copy);
	return ok;
}

int bpf_context_init(struct bpf_verifier_env *env)
{
	struct btf *btf = env->prog->aux->attach_btf;
	const struct btf_type *func;
	struct context_fact fact;
	struct bpf_context_state *ctx;
	int id = 0;

	/* Entry facts do not describe a function's exit context. */
	if (!btf || !btf_is_kernel(btf) || env->prog->aux->dst_prog ||
	    (env->prog->type != BPF_PROG_TYPE_LSM &&
	     env->prog->expected_attach_type != BPF_TRACE_FENTRY))
		return 0;
	func = btf_type_by_id(btf, env->prog->aux->attach_btf_id);
	if (!func || !btf_type_is_func(func))
		return 0;
	while ((id = btf_find_next_decl_tag(btf, func, -1, CONTEXT_PREFIX, id)) > 0) {
		const struct btf_type *tag = btf_type_by_id(btf, id);

		if (!parse_fact(btf_name_by_offset(btf, tag->name_off), &fact, true))
			continue;
		if (!env->context_state) {
			env->context_state = kvzalloc(sizeof(*env->context_state), GFP_KERNEL_ACCOUNT);
			if (!env->context_state)
				return -ENOMEM;
		}
		ctx = env->context_state;
		if (ctx->nr_entry == CONTEXT_ENTRY_LOCKS)
			return -E2BIG;
		ctx->entry[ctx->nr_entry++] = fact;
	}
	return 0;
}

void bpf_context_free(struct bpf_verifier_env *env)
{
	kvfree(env->context_state);
}

u32 bpf_context_argument(struct bpf_verifier_env *env, u32 arg)
{
	struct context_path p = { .arg = arg + 1 };

	return env->context_state ? intern_path(env->context_state, p) : 0;
}

u32 bpf_context_load(struct bpf_verifier_env *env, u32 source, s64 offset,
		     int size, bool pointer)
{
	struct bpf_context_state *ctx = env->context_state;
	struct context_path p;

	if (!ctx || !source || source > ctx->nr_ids || offset < 0 || offset > INT_MAX)
		return 0;
	p = ctx->ids[source];
	if (p.bits || check_add_overflow(p.offset, (s32)offset, &p.offset))
		return 0;
	if (pointer) {
		if (p.depth == CONTEXT_DEPTH)
			return 0;
		p.load[p.depth++] = p.offset;
		p.offset = 0;
	} else {
		p.bits = size * 8;
		p.mask = size == 8 ? U64_MAX : (1ULL << p.bits) - 1;
	}
	return intern_path(ctx, p);
}

void bpf_context_alu(struct bpf_verifier_env *env, const struct bpf_insn *insn,
		     u32 dst_id, u32 src_id, bool src_const, u64 src_value)
{
	struct bpf_context_state *ctx = env->context_state;
	struct bpf_reg_state *dst = &env->cur_state->frame[env->cur_state->curframe]->regs[insn->dst_reg];
	struct context_path p;
	u8 op = BPF_OP(insn->code);

	if (!ctx)
		return;
	if (op == BPF_MOV) {
		if (BPF_SRC(insn->code) == BPF_K || !src_id) {
			dst->context_id = 0;
			return;
		}
		p = ctx->ids[src_id];
		if (insn->off || insn->imm)
			p.opaque = true;
		else if (BPF_CLASS(insn->code) == BPF_ALU && p.bits)
			p.mask &= U32_MAX;
		dst->context_id = intern_path(ctx, p);
		return;
	}
	if (!dst_id && !src_id)
		return;
	if (!dst_id || (src_id && !src_const && src_id != dst_id)) {
		p = (struct context_path){ .bits = 64, .opaque = true };
	} else {
		p = ctx->ids[dst_id];
		if (!p.bits && (op == BPF_ADD || op == BPF_SUB)) {
			dst->context_id = dst_id;
			return;
		}
		if (p.bits && op == BPF_AND && src_const) {
			p.mask &= src_value;
			if (BPF_CLASS(insn->code) == BPF_ALU)
				p.mask &= U32_MAX;
		} else {
			p.opaque = true;
		}
	}
	dst->context_id = intern_path(ctx, p);
}

static int add_condition(struct bpf_context_state *ctx, struct bpf_verifier_state *state,
			 struct context_condition condition)
{
	u32 id;

	for (id = state->context_condition; id; id = ctx->conditions[id].parent) {
		struct context_condition *old = &ctx->conditions[id];

		if (old->kind == condition.kind && old->left == condition.left &&
		    old->right == condition.right && old->mask == condition.mask &&
		    old->value == condition.value)
			return 0;
	}
	if (ctx->nr_conditions + 1 == CONTEXT_CONDITIONS)
		return -E2BIG;
	condition.parent = state->context_condition;
	ctx->conditions[++ctx->nr_conditions] = condition;
	state->context_condition = ctx->nr_conditions;
	return 0;
}

int bpf_context_branch(struct bpf_verifier_env *env, struct bpf_verifier_state *state,
		       const struct bpf_insn *insn, u32 left, u32 right,
		       bool constant, u64 value, bool taken)
{
	struct bpf_context_state *ctx = env->context_state;
	struct context_condition condition = { .left = left, .right = right };
	struct context_path *p;
	u8 op = BPF_OP(insn->code);
	bool eq = (op == BPF_JEQ) == taken;

	if (!ctx || (!left && !right))
		return 0;
	if (!left) {
		condition.left = right;
		condition.right = 0;
		goto opaque;
	}
	p = &ctx->ids[left];
	if (!p->bits || p->opaque || !constant ||
	    (op != BPF_JEQ && op != BPF_JNE) || value ||
	    !is_power_of_2(p->mask))
		goto opaque;
	condition.kind = CONTEXT_BITS;
	condition.mask = p->mask;
	condition.value = eq ? 0 : p->mask;
	return add_condition(ctx, state, condition);
opaque:
	condition.kind = CONTEXT_OPAQUE;
	return add_condition(ctx, state, condition);
}

static bool has_property(const struct btf *btf, const struct btf_type *t, const char *prefix)
{
	return btf_find_next_decl_tag(btf, t, -1, prefix, 0) > 0;
}

/* Resolve an exact native field, preserving capability wrapper identity. */
static u32 field_type(const struct btf *btf, u32 id, s32 offset, bool pointer, u32 depth)
{
	const struct btf_type *t;
	const struct btf_member *members;
	u32 i, matches = 0, result = 0;

	if (offset < 0 || depth > 24)
		return 0;
	t = btf_type_skip_modifiers(btf, id, &id);
	if (!t)
		return 0;
	if (!offset && (pointer ? btf_type_is_ptr(t) :
		       has_property(btf, t, CONTEXT_PREFIX "capability:")))
		return id;
	if (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT && BTF_INFO_KIND(t->info) != BTF_KIND_UNION)
		return 0;
	members = btf_type_member(t);
	for (i = 0; i < btf_type_vlen(t); ++i) {
		const struct btf_type *member = btf_type_skip_modifiers(btf, members[i].type, NULL);
		u32 size, start = btf_member_bit_offset(t, i) / 8;

		if (!member || btf_member_bit_offset(t, i) % 8 || btf_member_bitfield_size(t, i))
			continue;
		if (!btf_resolve_size(btf, member, &size) || offset < start || offset - start >= size)
			continue;
		if (++matches > 1)
			return 0;
		result = field_type(btf, members[i].type, offset - start, pointer, depth + 1);
	}
	return matches == 1 ? result : 0;
}

static u32 object_type(const struct btf *btf, const struct btf_type *proto,
		       const struct context_path *path, u32 depth)
{
	const struct btf_type *t;
	u32 id, i;

	if (!path->arg || path->arg > btf_type_vlen(proto))
		return 0;
	t = btf_type_skip_modifiers(btf, btf_params(proto)[path->arg - 1].type, NULL);
	if (!t || !btf_type_is_ptr(t))
		return 0;
	id = t->type;
	for (i = 0; i < depth; ++i) {
		id = field_type(btf, id, path->load[i], true, 0);
		if (!id)
			return 0;
		id = btf_type_by_id(btf, id)->type;
	}
	btf_type_skip_modifiers(btf, id, &id);
	return id;
}

static const struct btf_type *lock_type(const struct btf *btf, const struct btf_type *proto,
				      const struct context_path *path)
{
	u32 id = object_type(btf, proto, path, path->depth);

	id = id ? field_type(btf, id, path->offset, false, 0) : 0;
	return id ? btf_type_by_id(btf, id) : NULL;
}

static bool substitute_argument(struct bpf_verifier_env *env, const struct btf *btf,
				const struct btf_type *proto, struct context_path *path)
{
	struct bpf_reg_state *reg;
	struct context_path result;
	s64 offset;
	u32 i;

	if (!path->arg || path->arg > btf_type_vlen(proto))
		return false;
	offset = btf_ctx_arg_offset(btf, proto, path->arg - 1);
	if (offset < 0 || offset / 8 >= MAX_BPF_FUNC_REG_ARGS)
		return false;
	reg = &env->cur_state->frame[env->cur_state->curframe]->regs[BPF_REG_1 + offset / 8];
	if (!reg->context_id || !tnum_is_const(reg->var_off) ||
	    base_type(reg->type) != PTR_TO_BTF_ID)
		return false;
	result = env->context_state->ids[reg->context_id];
	offset = (s64)reg->var_off.value;
	if (result.bits || result.opaque || offset < INT_MIN || offset > INT_MAX ||
	    check_add_overflow(result.offset, (s32)offset, &result.offset) ||
	    result.depth + path->depth > CONTEXT_DEPTH)
		return false;
	for (i = 0; i < path->depth; ++i) {
		s32 load = path->load[i];

		if (!i && check_add_overflow(load, result.offset, &load))
			return false;
		result.load[result.depth++] = load;
	}
	if (path->depth)
		result.offset = path->offset;
	else if (check_add_overflow(result.offset, path->offset, &result.offset))
		return false;
	result.bits = path->bits;
	*path = result;
	return true;
}

/* Conditions are about input-field observations. Unsupported correlated tests
 * withhold a conflict proof instead of silently treating them as independent.
 */
static bool guard_possible(struct bpf_verifier_env *env, const struct context_fact *fact)
{
	struct bpf_context_state *ctx = env->context_state;
	u32 id;

	if (!fact->conditional)
		return true;
	for (id = env->cur_state->context_condition; id; id = ctx->conditions[id].parent) {
		const struct context_condition *condition = &ctx->conditions[id];
		const struct context_path *p = &ctx->ids[condition->left];

		if (!context_path_equal(p, &fact->guard)) {
			if (condition->kind == CONTEXT_OPAQUE && (!p->arg ||
			    (condition->right && context_path_equal(&ctx->ids[condition->right], &fact->guard))))
				return false;
			continue;
		}
		if (condition->kind == CONTEXT_OPAQUE)
			return false;
		if (condition->kind == CONTEXT_BITS &&
		    ((condition->value ^ fact->value) & condition->mask & fact->mask))
			return false;
	}
	return true;
}

static bool same_instance(const struct context_path *a, const struct context_path *b)
{
	return context_path_equal(a, b);
}

int bpf_context_check_kfunc(struct bpf_verifier_env *env, struct btf *btf,
			    u32 func_id, const char *name)
{
	struct bpf_context_state *ctx = env->context_state;
	const struct btf_type *func, *proto, *acquired, *held;
	struct context_fact fact;
	int id = 0;
	u32 i;

	if (!ctx || !btf_is_kernel(btf) || env->cur_state->speculative ||
	    env->cur_state->context_call_seen)
		return 0;
	for (i = 0; i <= env->cur_state->curframe; ++i)
		if (env->cur_state->frame[i]->in_async_callback_fn)
			return 0;
	if (ctx->exhausted)
		return -E2BIG;
	func = btf_type_by_id(btf, func_id);
	if (!func || !btf_type_is_func(func))
		return 0;
	proto = btf_type_by_id(btf, func->type);
	while ((id = btf_find_next_decl_tag(btf, func, -1, CONTEXT_PREFIX "witness:", id)) > 0) {
		const struct btf_type *tag = btf_type_by_id(btf, id);

		if (!parse_fact(btf_name_by_offset(btf, tag->name_off), &fact, false))
			continue;
		acquired = lock_type(btf, proto, &fact.lock);
		if (!acquired || has_property(btf, acquired, CONTEXT_PREFIX "reentrant"))
			continue;
		if (!substitute_argument(env, btf, proto, &fact.lock) ||
		    (fact.conditional && !substitute_argument(env, btf, proto, &fact.guard)) ||
		    !guard_possible(env, &fact))
			continue;
		for (i = 0; i < ctx->nr_entry; ++i) {
			if (!ctx->entry[i].exclusive && !fact.exclusive)
				continue;
			held = lock_type(env->prog->aux->attach_btf,
					 env->prog->aux->attach_func_proto, &ctx->entry[i].lock);
			if (held != acquired || !same_instance(&ctx->entry[i].lock, &fact.lock))
				continue;
			bpf_log(&env->log, "kfunc %s may deadlock: proven acquisition overlaps an entry-held lock\n", name);
			return -EACCES;
		}
	}
	return 0;
}
