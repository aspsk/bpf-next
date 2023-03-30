// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include <linux/errno.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define MAX_ENTRIES (1 << 20)

char _license[] SEC("license") = "GPL";

typedef __u8 __u128[16];

#define MAP(NAME)							\
	struct {							\
		__uint(type, BPF_MAP_TYPE_WILDCARD);			\
		__type(key, struct NAME ## _key);			\
		__type(value, __u64);					\
		__uint(max_entries, MAX_ENTRIES);			\
		__uint(map_flags, BPF_F_NO_PREALLOC);			\
	} NAME SEC(".maps")

BPF_WILDCARD_DESC_4(
	test_map,
	BPF_WILDCARD_RULE_PREFIX, __u32, x1,
	BPF_WILDCARD_RULE_RANGE, __u32, x2,
	BPF_WILDCARD_RULE_MATCH, __u32, x3,
	BPF_WILDCARD_RULE_WILDCARD_MATCH, __u32, x4
);

MAP(test_map);

BPF_WILDCARD_DESC_1(
	prefix_1,
	BPF_WILDCARD_RULE_PREFIX, __u8, x1
);

BPF_WILDCARD_DESC_1(
	prefix_2,
	BPF_WILDCARD_RULE_PREFIX, __u16, x1
);

BPF_WILDCARD_DESC_1(
	prefix_4,
	BPF_WILDCARD_RULE_PREFIX, __u32, x1
);

BPF_WILDCARD_DESC_1(
	prefix_8,
	BPF_WILDCARD_RULE_PREFIX, __u64, x1
);

BPF_WILDCARD_DESC_1(
	prefix_16,
	BPF_WILDCARD_RULE_PREFIX, __u128, x1
);

BPF_WILDCARD_DESC_1(
	range_1,
	BPF_WILDCARD_RULE_RANGE, __u8, x1
);

BPF_WILDCARD_DESC_1(
	range_2,
	BPF_WILDCARD_RULE_RANGE, __u16, x1
);

BPF_WILDCARD_DESC_1(
	range_4,
	BPF_WILDCARD_RULE_RANGE, __u32, x1
);

BPF_WILDCARD_DESC_1(
	range_8,
	BPF_WILDCARD_RULE_RANGE, __u64, x1
);

BPF_WILDCARD_DESC_1(
	match_1,
	BPF_WILDCARD_RULE_MATCH, __u8, x1
);

BPF_WILDCARD_DESC_1(
	match_2,
	BPF_WILDCARD_RULE_MATCH, __u16, x1
);

BPF_WILDCARD_DESC_1(
	match_4,
	BPF_WILDCARD_RULE_MATCH, __u32, x1
);

BPF_WILDCARD_DESC_1(
	match_8,
	BPF_WILDCARD_RULE_MATCH, __u64, x1
);

BPF_WILDCARD_DESC_1(
	match_16,
	BPF_WILDCARD_RULE_MATCH, __u64, x1
);

BPF_WILDCARD_DESC_1(
	xmatch_1,
	BPF_WILDCARD_RULE_WILDCARD_MATCH, __u8, x1
);

BPF_WILDCARD_DESC_1(
	xmatch_2,
	BPF_WILDCARD_RULE_WILDCARD_MATCH, __u16, x1
);

BPF_WILDCARD_DESC_1(
	xmatch_4,
	BPF_WILDCARD_RULE_WILDCARD_MATCH, __u32, x1
);

BPF_WILDCARD_DESC_1(
	xmatch_8,
	BPF_WILDCARD_RULE_WILDCARD_MATCH, __u64, x1
);

BPF_WILDCARD_DESC_1(
	xmatch_16,
	BPF_WILDCARD_RULE_WILDCARD_MATCH, __u128, x1
);

MAP(prefix_1);
MAP(prefix_2);
MAP(prefix_4);
MAP(prefix_8);
MAP(prefix_16);

MAP(range_1);
MAP(range_2);
MAP(range_4);
MAP(range_8);

MAP(match_1);
MAP(match_2);
MAP(match_4);
MAP(match_8);
MAP(match_16);

MAP(xmatch_1);
MAP(xmatch_2);
MAP(xmatch_4);
MAP(xmatch_8);
MAP(xmatch_16);

/*
 * The following maps can't be loaded due to incorrect key btf, except of the
 * first 'example_map' map which is left here to check the correctness of the
 * test and to illustrate how to create keys without using BPF_WILDCARD_DESC_*
 */

struct example_map_desc {
	__uint(n_rules, 4);
        __uint(x1, (BPF_WILDCARD_RULE_PREFIX) << 8 | sizeof(__u32));
        __uint(x2, (BPF_WILDCARD_RULE_RANGE) << 8 | sizeof(__u32));
        __uint(x3, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x4, (BPF_WILDCARD_RULE_WILDCARD_MATCH) << 8 | sizeof(__u32));
};

struct example_map_key {
	struct example_map_desc desc[0];
	__u32 type;
	__u32 priority;
	__u32 pad[2+2+1+1];
} __attribute__((packed));

MAP(example_map);

struct map_no_desc_key {
	int x;
};
MAP(map_no_desc);

struct map_desc_not_array_key {
	int desc;
};
MAP(map_desc_not_array);

struct no_n_rules_desc {
        /* missing: __uint(n_rules, 4); */
        __uint(x1, (BPF_WILDCARD_RULE_PREFIX) << 8 | sizeof(__u32));
        __uint(x2, (BPF_WILDCARD_RULE_RANGE) << 8 | sizeof(__u32));
        __uint(x3, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x4, (BPF_WILDCARD_RULE_WILDCARD_MATCH) << 8 | sizeof(__u32));
};
struct no_n_rules_map_key {
	struct no_n_rules_desc desc[0];
	__u32 type;
	__u32 priority;
	__u32 pad[2+2+1+1];
};
MAP(no_n_rules_map);

struct too_few_rules_desc {
        __uint(n_rules, 4);
        __uint(x1, (BPF_WILDCARD_RULE_PREFIX) << 8 | sizeof(__u32));
        __uint(x2, (BPF_WILDCARD_RULE_RANGE) << 8 | sizeof(__u32));
        __uint(x3, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        /* 4 rules expeced */
};
struct too_few_rules_map_key {
	struct too_few_rules_desc desc[0];
	__u32 type;
	__u32 priority;
	__u32 pad[2+2+1];
};
MAP(too_few_rules_map);

struct too_many_rules_desc {
        __uint(n_rules, 4);
        __uint(x1, (BPF_WILDCARD_RULE_PREFIX) << 8 | sizeof(__u32));
        __uint(x2, (BPF_WILDCARD_RULE_RANGE) << 8 | sizeof(__u32));
        __uint(x3, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x4, (BPF_WILDCARD_RULE_WILDCARD_MATCH) << 8 | sizeof(__u32));
	/* extra field */
        __uint(x5, (BPF_WILDCARD_RULE_WILDCARD_MATCH) << 8 | sizeof(__u32));
};
struct too_many_rules_map_key {
	struct too_many_rules_desc desc[0];
	__u32 type;
	__u32 priority;
	__u32 pad[2+2+1+1+1];
};
MAP(too_many_rules_map);

struct n_rules_too_big_desc {
        __uint(n_rules, 10);
        __uint(x0, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x1, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x2, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x3, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x4, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x5, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x6, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x7, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x8, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x9, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
};
struct n_rules_too_big_map_key {
	struct n_rules_too_big_desc desc[0];
	__u32 type;
	__u32 priority;
	__u32 pad[10];
};
MAP(n_rules_too_big_map);

struct reserved_bits_set_map_desc {
        __uint(n_rules, 4);
        __uint(x1, (BPF_WILDCARD_RULE_PREFIX) << 8 | sizeof(__u32) | 0xf0000); /* only 0xttss is allowed */
        __uint(x2, (BPF_WILDCARD_RULE_RANGE) << 8 | sizeof(__u32));
        __uint(x3, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x4, (BPF_WILDCARD_RULE_WILDCARD_MATCH) << 8 | sizeof(__u32));
};

struct reserved_bits_set_map_key {
	struct reserved_bits_set_map_desc desc[0];
	__u32 type;
	__u32 priority;
	__u32 pad[2+2+1+1];
};
MAP(reserved_bits_set_map);

struct wrong_rule_type_map_desc {
        __uint(n_rules, 4);
        __uint(x1, (17+BPF_WILDCARD_RULE_PREFIX) << 8 | sizeof(__u32)); /* type doesn't exist */
        __uint(x2, (BPF_WILDCARD_RULE_RANGE) << 8 | sizeof(__u32));
        __uint(x3, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x4, (BPF_WILDCARD_RULE_WILDCARD_MATCH) << 8 | sizeof(__u32));
};

struct wrong_rule_type_map_key {
	struct wrong_rule_type_map_desc desc[0];
	__u32 type;
	__u32 priority;
	__u32 pad[2+2+1+1];
};
MAP(wrong_rule_type_map);

struct rule_size_too_big_map_desc {
        __uint(n_rules, 4);
        __uint(x1, (BPF_WILDCARD_RULE_PREFIX) << 8 | 32); /* size too big */
        __uint(x2, (BPF_WILDCARD_RULE_RANGE) << 8 | sizeof(__u32));
        __uint(x3, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x4, (BPF_WILDCARD_RULE_WILDCARD_MATCH) << 8 | sizeof(__u32));
};

struct rule_size_too_big_map_key {
	struct rule_size_too_big_map_desc desc[0];
	__u32 type;
	__u32 priority;
	__u32 pad[2+2+1+1];
};
MAP(rule_size_too_big_map);

struct rule_size_not_po2_map_desc {
        __uint(n_rules, 4);
        __uint(x1, (BPF_WILDCARD_RULE_PREFIX) << 8 | 13); /* size not power of 2 */
        __uint(x2, (BPF_WILDCARD_RULE_RANGE) << 8 | sizeof(__u32));
        __uint(x3, (BPF_WILDCARD_RULE_MATCH) << 8 | sizeof(__u32));
        __uint(x4, (BPF_WILDCARD_RULE_WILDCARD_MATCH) << 8 | sizeof(__u32));
};

struct rule_size_not_po2_map_key {
	struct rule_size_not_po2_map_desc desc[0];
	__u32 type;
	__u32 priority;
	__u32 pad[2+2+1+1];
};
MAP(rule_size_not_po2_map);

/*
 * Code below is to perform a similar set of tests as in userspace from
 * the 'check_wildcard' programm attached to the fentry/sys_getpgid
 */

__u8 _key[32];

#define n_loops 7 /* can be any < 0xff, but make verifier happy with a smaller value */

static inline void _memset(void *ptr, int val, __u32 size)
{
	switch (size) {
	case 1:
		__builtin_memset(ptr, val, 1);
		break;
	case 2:
		__builtin_memset(ptr, val, 2);
		break;
	case 4:
		__builtin_memset(ptr, val, 4);
		break;
	case 8:
		__builtin_memset(ptr, val, 8);
		break;
	case 16:
		__builtin_memset(ptr, val, 16);
		break;
	}
}

static void set_key(int rule_type, void *key, __u32 size, __u8 x)
{
	switch(rule_type) {
        case BPF_WILDCARD_RULE_PREFIX:
		_memset(key + 8, x, size);
		*(__u32 *)(key + 8 + size) = (__u32)(size * 8);
		break;
        case BPF_WILDCARD_RULE_RANGE:
		_memset(key + 8, x, size);
		_memset(key + 8 + size, x, size);
		break;
        case BPF_WILDCARD_RULE_MATCH:
        case BPF_WILDCARD_RULE_WILDCARD_MATCH:
		_memset(key + 8, x, size);
		break;
	}
}

static void set_key_wildcard(int rule_type, void *key, __u32 size)
{
	switch(rule_type) {
        case BPF_WILDCARD_RULE_PREFIX:
		_memset(key + 8, 0, size);
		*(__u32 *)(key + 8 + size) = 0;
		break;
        case BPF_WILDCARD_RULE_RANGE:
		_memset(key + 8, 0, size);
		_memset(key + 8 + size, 0xff, size);
		break;
        case BPF_WILDCARD_RULE_WILDCARD_MATCH:
		_memset(key + 8, 0, size);
		break;
	}
}

static inline int test_map_update(void *map)
{
	struct wildcard_key *key = (struct wildcard_key *)_key;
	__u64 val = 0;
	int err;

	__builtin_memset(key, 0, sizeof(_key));

	/*
	 * We can't insert a key unless type is BPF_WILDCARD_KEY_RULE
	 */
	key->type = BPF_WILDCARD_KEY_MATCH;
	err = bpf_map_update_elem(map, key, &val, 0);
	if (err != -EINVAL)
		return 1;

	/*
	 * Test that we can insert and update elements in accordance with update flags
	 */
	key->type = BPF_WILDCARD_KEY_RULE;
	err = bpf_map_update_elem(map, key, &val, BPF_EXIST);
	if (err != -ENOENT)
		return 1;
	err = bpf_map_update_elem(map, key, &val, BPF_NOEXIST);
	if (err != 0)
		return 1;
	err = bpf_map_update_elem(map, key, &val, BPF_NOEXIST);
	if (err != -EEXIST)
		return 1;
	err = bpf_map_update_elem(map, key, &val, BPF_EXIST);
	if (err != 0)
		return 1;

	/*
	 * Delete the element to start from scratch
	 */
	err = bpf_map_delete_elem(map, key);
	if (err != 0)
		return 1;

	return 0;
}

static inline int test_map_priority(void *map, __u32 size,
				    int rule_type, int wildcard)
{
	struct wildcard_key *key = (struct wildcard_key *)_key;
	__u64 *valp;
	__u64 val;
	int err;
	int i;

	__builtin_memset(key, 0, sizeof(_key));

	/* Insert elements with same keys, but different priorities, the lookup
	 * should always return the highest (inverse: lowest value) priority */
	key->type = BPF_WILDCARD_KEY_RULE;
	for (i = 1; i <= n_loops; i++) {
		set_key(rule_type, key, size, 0x54);
		key->priority = i;
		val = (__u64)i; /* value can be used to check if we got the right match in regards to priority */
		err = bpf_map_update_elem(map, key, &val, 0);
		if (err != 0)
			return 1;
	}

	if (wildcard) {
		/* setup a wildcard entry */
		key->type = BPF_WILDCARD_KEY_RULE;
		set_key_wildcard(rule_type, key, size);
		key->priority = 0xffffffff; /* the lowest priority ever */
		val = 0xffffffff; /* value can be used to check if we got the right match in regards to priority */
		err = bpf_map_update_elem(map, key, &val, 0);
		if (err != 0)
			return 1;
	}

	/* The right priority should be matched for overlapping rules */
	for (i = 1; i <= n_loops; i++) {
		/* lookup should be correct with correct value */
		key->type = BPF_WILDCARD_KEY_RULE;
		key->priority = i;
		set_key(rule_type, key, size, 0x54);
		valp = bpf_map_lookup_elem(map, key);
		if (valp == NULL || *valp != i)
			return 1;

		/* match should be correct with correct priority */
		key->type = BPF_WILDCARD_KEY_MATCH;
		key->priority = 0;
		set_key(rule_type, key, size, 0x54);
		valp = bpf_map_lookup_elem(map, key);
		if (valp == NULL || *valp != i)
			return 1;

		/* delete the highest priority so that we can jump to the next one */
		key->type = BPF_WILDCARD_KEY_RULE;
		set_key(rule_type, key, size, 0x54);
		key->priority = i;
		err = bpf_map_delete_elem(map, key);
		if (err)
			return 1;

		/* if key doesn't exist, but wildcard rule is there, it should match */
		if (wildcard) {
			key->type = BPF_WILDCARD_KEY_MATCH;
			key->priority = 0;
			set_key(rule_type, key, size, 0x33);
			valp = bpf_map_lookup_elem(map, key);
			if (valp == NULL || *valp != 0xffffffff)
				return 1;
		}
	}

	if (wildcard) {
		key->type = BPF_WILDCARD_KEY_RULE;
		set_key_wildcard(rule_type, key, size);
		key->priority = 0xffffffff; /* the lowest priority ever */
		err = bpf_map_delete_elem(map, key);
		if (err)
			return 1;
	}

	/* The map should be empty now */
	key->type = BPF_WILDCARD_KEY_MATCH;
	key->priority = 0;
	set_key(rule_type, key, size, 0x54);
	valp = bpf_map_lookup_elem(map, key);
	if (valp)
		return 1;

	return 0;
}

static inline int test_map_prefix(void *map, __u32 size)
{
	int err;

	err = test_map_update(map);
	if (err)
		return err;

	err = test_map_priority(map, size, BPF_WILDCARD_RULE_PREFIX, 1);
	if (err)
		return err;

	return 0;
}

static inline int test_map_range(void *map, __u32 size)
{
	int err;

	err = test_map_update(map);
	if (err)
		return err;

	err = test_map_priority(map, size, BPF_WILDCARD_RULE_RANGE, 1);
	if (err)
		return err;

	return 0;
}

static inline int test_map_match(void *map, __u32 size, int wildcard)
{
	int rule_type = wildcard ? BPF_WILDCARD_RULE_WILDCARD_MATCH
				 : BPF_WILDCARD_RULE_MATCH;
	int err;

	err = test_map_update(map);
	if (err)
		return err;

	err = test_map_priority(map, size, rule_type, wildcard);
	if (err)
		return err;

	return 0;
}

int error = 0;
int test_no = 0;

#define TEST(...)		\
	test_no += 1;		\
	error = __VA_ARGS__;	\
	if (error)		\
		return 0

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int check_wildcard(void *ctx __attribute__((unused)))
{
	int wildcard;

	TEST(test_map_prefix(&prefix_1, 1));
	TEST(test_map_prefix(&prefix_2, 2));
	TEST(test_map_prefix(&prefix_4, 4));
	TEST(test_map_prefix(&prefix_8, 8));
	TEST(test_map_prefix(&prefix_16, 16));

	TEST(test_map_range(&range_1, 1));
	TEST(test_map_range(&range_2, 2));
	TEST(test_map_range(&range_4, 4));
	TEST(test_map_range(&range_8, 8));

	wildcard = 0;
	TEST(test_map_match(&match_1, 1, wildcard));
	TEST(test_map_match(&match_2, 2, wildcard));
	TEST(test_map_match(&match_4, 4, wildcard));
	TEST(test_map_match(&match_8, 8, wildcard));
	TEST(test_map_match(&match_16, 16, wildcard));

	wildcard = 1;
	TEST(test_map_match(&xmatch_1, 1, wildcard));
	TEST(test_map_match(&xmatch_2, 2, wildcard));
	TEST(test_map_match(&xmatch_4, 4, wildcard));
	TEST(test_map_match(&xmatch_8, 8, wildcard));
	TEST(test_map_match(&xmatch_16, 16, wildcard));

	return 0;
}
