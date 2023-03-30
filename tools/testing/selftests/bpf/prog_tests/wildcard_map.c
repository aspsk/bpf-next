// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include <sys/syscall.h>
#include <test_progs.h>
#include <stdarg.h>

#include "wildcard_map.skel.h"

static const char *S(const char *fmt, ...)
{
	static __thread char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	return buf;
}

static const char *pfx(const char *prefix, const char *str)
{
	return S("%s: %s", prefix, str);
}

static bool find_name(const char *name, const char *names[], size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (!strcmp(name, names[i]))
			return true;
	return false;
}

const char *broken_maps[] = {
	"example_map",
	"map_no_desc",
	"map_desc_not_array",
	"no_n_rules_map",
	"too_few_rules_map",
	"too_many_rules_map",
	"n_rules_too_big_map",
	"reserved_bits_set_map",
	"wrong_rule_type_map",
	"rule_size_too_big_map",
	"rule_size_not_po2_map",
};

static int skip_broken_maps(struct wildcard_map *skel)
{
	struct bpf_map_skeleton *map_skeleton;
	int n = ARRAY_SIZE(broken_maps);
	int found = 0;
	int i;

	for (i = 0; i < skel->skeleton->map_cnt; i++) {
		map_skeleton = &skel->skeleton->maps[i];
		if (find_name(map_skeleton->name, broken_maps, n)) {
			found += 1;
			bpf_map__set_autocreate(*map_skeleton->map, false);
		}
	}

	if (found != n)
		return -EFAULT;

	return wildcard_map__load(skel);
}

static int load_map(struct wildcard_map *skel, const char *name)
{
	struct bpf_map_skeleton *map_skeleton;
	bool found = false;
	int i;

	for (i = 0; i < skel->skeleton->map_cnt; i++) {
		map_skeleton = &skel->skeleton->maps[i];
		if (!strcmp(map_skeleton->name, name))
			found = true;
		else if (strcmp(map_skeleton->name, "wildcard.bss"))
			bpf_map__set_autocreate(*map_skeleton->map, false);
	}

	if (!ASSERT_EQ(found, true, name))
		return -ENOENT;

	return wildcard_map__load(skel);
}

struct test_map_key {
	__u32 type;
	__u32 priority;
	union {
		struct {
			__u32 x1;
			__u32 x1_prefix;
			__u32 x2_min;
			__u32 x2_max;
			__u32 x3;
			__u32 x4;
		} __attribute__((packed)) rule;
		struct {
			__u32 x1;
			__u32 x2;
			__u32 x3;
			__u32 x4;
		} __attribute__((packed));
	};
} __attribute__((packed));

static void test_map_set_rule(int map_fd, __u64 rule_index, const char *addr, u32 addr_prefix, u32 range_min, u32 range_max, u32 match, u32 xmatch, u32 priority)
{
	struct test_map_key key = {
		.type = BPF_WILDCARD_KEY_RULE,
		.priority = priority,
		.rule.x1 = inet_addr(addr), /* network byte order */
		.rule.x1_prefix = addr_prefix, /* host byte order */
		.rule.x2_min = htonl(range_min), /* network byte order */
		.rule.x2_max = htonl(range_max), /* network byte order */
		.rule.x3 = match, /* we don't care about byte order for matches */
		.rule.x4 = xmatch, /* we don't care about byte order for wildcard matches */
	};
	int ret;

	ret = bpf_map_update_elem(map_fd, &key, &rule_index, 0);
	ASSERT_EQ(ret, 0, S("bpf_map_update_elem, rule[%llu]", rule_index));
}

static void test_map_match_input(int map_fd, int input_no, int expected_index_or_err, const char *addr, u32 x,  u32 match, u32 xmatch)
{
	struct test_map_key key = {
		.type = BPF_WILDCARD_KEY_MATCH,
		.priority = 0,
		.x1 = inet_addr(addr), /* network byte order */
		.x2 = htonl(x), /* network byte order */
		.x3 = match, /* we don't care about byte order for matches */
		.x4 = xmatch, /* we don't care about byte order for wildcard matches */
	};
	__u64 val;
	int ret;

	ret = bpf_map_lookup_elem(map_fd, &key, &val);
	if (expected_index_or_err < 0)
		ASSERT_EQ(ret, -ENOENT, S("bpf_map_lookup_elem, input_no=%d", input_no));
	else
		ASSERT_EQ((int)val, expected_index_or_err, S("bpf_map_lookup_elem, input_no=%d", input_no));
}

/*
 * A special test which may be easily read by a human
 */
static void test_human_friendly(void)
{
	struct wildcard_map *skel;
	int map_fd;
	int ret;

	skel = wildcard_map__open();
	if (!ASSERT_OK_PTR(skel, "wildcard_map__open"))
		return;

	bpf_program__set_autoload(skel->progs.check_wildcard, false);

	/*
	 * Only load one map of interest
	 */
	ret = load_map(skel, "test_map");
	if (!ASSERT_EQ(ret, 0, "load_map"))
		goto destroy;

	/*
	 * The 'test_map' map is defined as
	 *
	 *     BPF_WILDCARD_DESC_4(
	 *             test_map,
	 *             BPF_WILDCARD_RULE_PREFIX, __u32, x1,
	 *             BPF_WILDCARD_RULE_RANGE, __u32, x2,
	 *             BPF_WILDCARD_RULE_MATCH, __u32, x3,
	 *             BPF_WILDCARD_RULE_WILDCARD_MATCH, __u32, x4
	 *     );
	 *     struct {
	 *             __uint(type, BPF_MAP_TYPE_WILDCARD);
	 *             __type(key, struct test_map_key);
	 *             __type(value, __u64);
	 *             __uint(max_entries, MAX_ENTRIES);
	 *             __uint(map_flags, BPF_F_NO_PREALLOC);
	 *     } test_map SEC(".maps")
	 *
	 * using the helper BPF_WILDCARD_DESC_4 macro from the uapi/linux/bpf.h
	 * header.  This definition means that the rules/matches for this map
	 * consist of four parts: a 32-bit prefix (e.g., IPv4 address), a
	 * 32-bit range, a 32-bit match and a 32-bit wildcard match (the
	 * difference between the two latter is described later). The
	 * BPF_WILDCARD_DESC_4 macro defines the 'struct test_map_key' structure
	 * which has the following format:
	 *
	 *     struct test_map_key {
	 *             struct test_map_desc desc[0];
	 *             __u32 type;
	 *             __u32 priority;
	 *             union {
	 *                     struct {
	 *                             __u32 x1;
	 *                             __u32 x1_prefix;
	 *                             __u32 x2_min;
	 *                             __u32 x2_max;
	 *                             __u32 x3;
	 *                             __u32 x4;
	 *                     } __attribute__((packed)) rule;
	 *                     struct {
	 *                             __u32 x1;
	 *                             __u32 x2;
	 *                             __u32 x3;
	 *                             __u32 x4;
	 *                     } __attribute__((packed));
	 *             };
	 *     } __attribute__((packed));
	 *
	 * Here the 'desc' field describes the map structure. It must be an
	 * array of size zero and contain a structure describing (in BTF terms)
	 * the structure of the map. This is impossible to create a wildcard
	 * map without passing a BTF containing a proper 'desc' field. The
	 * 'desc' should have the following format:
	 *
	 *     struct {
	 *             __uint(n_rules, N);
	 *             __uint(rule_1, TYPE_1 << 8 | SIZE_1);
	 *             __uint(rule_2, TYPE_2 << 8 | SIZE_2);
	 *             ...
	 *             __uint(rule_N, TYPE_N << 8 | SIZE_N);
	 *     };
	 *
	 * in this case the desc is as follows:
	 *
	 *     struct test_map_desc {
	 *             __uint(n_rules, 4);
	 *             __uint(x1, BPF_WILDCARD_RULE_PREFIX << 8 | sizeof(__u32));
	 *             __uint(x2, BPF_WILDCARD_RULE_RANGE << 8 | sizeof(__u32));
	 *             __uint(x3, BPF_WILDCARD_RULE_MATCH << 8 | sizeof(__u32));
	 *             __uint(x4, BPF_WILDCARD_RULE_WILDCARD_MATCH << 8 | sizeof(__u32));
	 *     };
	 */
	map_fd = bpf_map__fd(skel->maps.test_map);

	/*
	 * In order to populate the map, the 'rule' part of the 'struct
	 * test_map_key' should be used, and the key->type must be equal to
	 * BPF_WILDCARD_KEY_RULE. The key->priority may be used to specify the
	 * priority of the rule, the lower value means the higher priority.
	 *
	 * The first rule in the map specifies a prefix, e.g., 192.168.0.0/16.
	 * It can be set using key->rule.x1 (pton("192.168.0.0")) and
	 * key->rule.x1_prefix (16). The prefix value part should be in network
	 * byte order, the prefix part is in host byte order. A prefix /0 can
	 * be specified to wildcard a lookup, meaning that any value will satisfy.
	 *
	 * The second rule is a range, so in rule a minimum and a maximum value
	 * can be specified. To wildcard a lookup a [0, 0xff..ff] range should
	 * be specified.
	 *
	 * The third rule specifies an exact match, meaning that on a lookup a
	 * value should match exactly.
	 *
	 * The fourth rule specifies a wildcard match, meaning that on a lookup
	 * a value should match exactly, unless a rule was set to zero. In the
	 * latter case, every value satisfies.
	 *
	 * We now will populate the map with several rules (* means wildcard,
	 * recall that the third rule can't be wildcarded):
	 *
	 *    [1] (*,              *,     0,    *),    priority 0xffff
	 *    [2] (192.168.0.0/16, *,     0,    *),    priority 100
	 *    [3] (192.168.0.0/16, 0-100, 0,    *),    priority 10
	 *    [4] (*,              *,     0xaa, *),    priority 1000
	 *    [5] (*,              *,     0,    0xbb), priority 1000
	 *
	 * Then we will look up some inputs. The results should be as follows:
	 *
	 *    (10.0.0.2,    13,  0,    0x65) => matches the rule [1]
	 *    (10.0.0.2,    13,  1,    0x65) => doesn't match
	 *    (192.168.1.1, 13,  0,    0x65) => matches the rule [3]
	 *    (192.168.1.1, 133, 0,    0x65) => matches the rule [2]
	 *    (10.0.0.2,    13,  0xaa, 0x65) => matches the rule [4]
	 *    (10.0.0.2,    13,  0xab, 0x65) => doesn't match
	 *    (10.0.0.2,    13,  0,    0xbb) => matches the rule [5]
	 *    (192.168.1.1, 13,  0,    0xbb) => matches the rule [3]
	 *    (192.168.1.1, 133, 0,    0xbb) => matches the rule [2]
	 *
	 * In order to match values with rules, a key should be set using the
	 * second unnamed part (x1, x2, x3, x4), key->type set to
	 * BPF_WILDCARD_KEY_MATCH and a bpf_map_lookup performed.
	 *
	 * See the test_map_set_rule/test_map_match_input functions below to
	 * see how the key structure is used to update rules & match input.
	 */

	/* We set up rules and put the rule number as the map value to be validated below */
	test_map_set_rule(map_fd, 1,     "0.0.0.0",  0, 0, (__u32)-1,    0,    0, 0xffff);
	test_map_set_rule(map_fd, 2, "192.168.0.0", 16, 0, (__u32)-1,    0,    0,    100);
	test_map_set_rule(map_fd, 3, "192.168.0.0", 16, 0,       100,    0,    0,     10);
	test_map_set_rule(map_fd, 4,     "0.0.0.0",  0, 0, (__u32)-1, 0xaa,    0,   1000);
	test_map_set_rule(map_fd, 5,     "0.0.0.0",  0, 0, (__u32)-1,    0, 0xbb,   1000);

	/* Match input according, see the comment above for the return values */
	test_map_match_input(map_fd, 1,       1,    "10.0.0.2", 13,  0,    0x65);
	test_map_match_input(map_fd, 2, -ENOENT,    "10.0.0.2", 13,  1,    0x65);
	test_map_match_input(map_fd, 3,       3, "192.168.1.1", 13,  0,    0x65);
	test_map_match_input(map_fd, 4,       2, "192.168.1.1", 133, 0,    0x65);
	test_map_match_input(map_fd, 5,       4,    "10.0.0.2", 13,  0xaa, 0x65);
	test_map_match_input(map_fd, 6, -ENOENT,    "10.0.0.2", 13,  0xab, 0x66);
	test_map_match_input(map_fd, 7,       5,    "10.0.0.2", 13,  0,    0xbb);
	test_map_match_input(map_fd, 8,       3, "192.168.1.1", 13,  0,    0xbb);
	test_map_match_input(map_fd, 9,       2, "192.168.1.1", 133, 0,    0xbb);

destroy:
	wildcard_map__destroy(skel);
}

static void test_map_creation_bad_uattr()
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct bpf_map_info mi = {};
	struct wildcard_map *skel;
	__u32 map_info_len;
	int btf_fd = -1;
	int map_fd;
	int ret;

	/*
	 * Load a correct map (test_map) with correct properties, then get its
	 * info and btf descriptor (which will also contain all the broken
	 * types we need for tests) to use in the following tests with
	 * broken uattrs.
	 */
	skel = wildcard_map__open();
	if (!ASSERT_OK_PTR(skel, "wildcard_map__open"))
		return;

	bpf_program__set_autoload(skel->progs.check_wildcard, false);

	ret = load_map(skel, "test_map");
	if (!ASSERT_EQ(ret, 0, "load_map"))
		goto destroy;

	map_fd = bpf_map__fd(skel->maps.test_map);

	map_info_len = sizeof(mi);
	ret = bpf_map_get_info_by_fd(map_fd, &mi, &map_info_len);
	if (!ASSERT_EQ(ret, 0, "bpf_map_get_info_by_fd"))
		goto destroy;

	btf_fd = bpf_btf_get_fd_by_id(mi.btf_id);
	if (!ASSERT_GE(btf_fd, 0, "bpf_btf_get_fd_by_id"))
		goto destroy;

	/* Check that we can create a map if everything is set correct */
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, mi.value_size, mi.max_entries, &opts);
	ASSERT_GE(ret, 0, "bpf_map_create ok");
	close(ret);

	/* Check that map creation fails if flags are incorrect */
	opts.map_flags = 0xffffff;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, mi.value_size, mi.max_entries, &opts);
	ASSERT_LT(ret, 0, "bpf_map_create fails with wrong map_flags");

	/* Check that map creation fails if (!key_size || !value_size || !max_entries) */
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, 0, mi.value_size, mi.max_entries, &opts);
	ASSERT_LT(ret, 0, "bpf_map_create fails with key_size=0");
	/**/
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, 0, mi.max_entries, &opts);
	ASSERT_LT(ret, 0, "bpf_map_create fails with value_size=0");
	/**/
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, mi.value_size, 0, &opts);
	ASSERT_LT(ret, 0, "bpf_map_create fails with max_entries=0");

	/* Check that map creation fails if key_size != btf->key_size */
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size + 1, mi.value_size, mi.max_entries, &opts);
	ASSERT_LT(ret, 0, "bpf_map_create fails with key_size != btf->key_size");

	/* Check that map creation fails if value_size != btf->value_size */
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, mi.value_size + 1, mi.max_entries, &opts);
	ASSERT_LT(ret, 0, "bpf_map_create fails with key_size != btf->key_size");

	/* Check that map creation fails if key_size + value_size is too large */
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, 1 << 22, 1 << 22, mi.max_entries, &opts);
	ASSERT_EQ(ret, -E2BIG, "bpf_map_create fails with too big key_size+value_size");

	/* Check that map creation fails if key or value btf ids are missing */
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = 0;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, mi.value_size, mi.max_entries, &opts);
	ASSERT_EQ(ret, -EINVAL, "bpf_map_create fails with zeroed btf_key_type_id");
	/**/
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = 0;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, mi.value_size, mi.max_entries, &opts);
	ASSERT_EQ(ret, -EINVAL, "bpf_map_create fails with zeroed btf_value_type_id");

	/* Check that map creation fails if key or value btf ids are pointing to a non-existing type */
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = 0xdeadbeef;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, mi.value_size, mi.max_entries, &opts);
	ASSERT_EQ(ret, -EINVAL, "bpf_map_create fails with non-existing btf_key_type_id");
	/**/
	opts.map_flags = mi.map_flags;
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = 0xdeadbeef;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, mi.value_size, mi.max_entries, &opts);
	ASSERT_EQ(ret, -EINVAL, "bpf_map_create fails with non-existing  btf_value_type_id");

	/* Check that map creation fails btf_fd is not pointing to an open file */
	opts.map_flags = mi.map_flags;
	opts.btf_fd = 0xdeadbeef;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, mi.value_size, mi.max_entries, &opts);
	ASSERT_EQ(ret, -EBADF, "bpf_map_create fails with closed btf_fd");

	/* Check that map creation fails btf_fd is not a BTF fd (but is an fd) */
	opts.map_flags = mi.map_flags;
	opts.btf_fd = map_fd;
	opts.btf_key_type_id = mi.btf_key_type_id;
	opts.btf_value_type_id = mi.btf_value_type_id;
	ret = bpf_map_create(mi.type, mi.name, mi.key_size, mi.value_size, mi.max_entries, &opts);
	ASSERT_EQ(ret, -EINVAL, "bpf_map_create fails with btf_fd pointing to other file type");

destroy:
	if (btf_fd >= 0)
		close(btf_fd);

	wildcard_map__destroy(skel);
}

static void map_load_expected_error(const char *map_name, int expected_err)
{
	struct wildcard_map *skel;
	int err;

	skel = wildcard_map__open();
	if (!ASSERT_OK_PTR(skel, pfx(map_name, "wildcard_map__open")))
		return;

	bpf_program__set_autoload(skel->progs.check_wildcard, false);

	err = load_map(skel, map_name);
	ASSERT_EQ(err, expected_err, pfx(map_name, "load_map"));

	wildcard_map__destroy(skel);
}

static void test_map_creation_bad_btf(void)
{
	map_load_expected_error("example_map", 0);

	/* The key doesn't contain desc field */
	map_load_expected_error("map_no_desc", -EINVAL);

	/* The key does contain desc field, but this is not an array */
	map_load_expected_error("map_desc_not_array", -EINVAL);

	/* The desc is missing the n_rules field */
	map_load_expected_error("no_n_rules_map", -EINVAL);

	/* The desc has the n_rules field, but the number of rules is less than specified */
	map_load_expected_error("too_few_rules_map", -EINVAL);

	/* The desc has the n_rules field, but the number of rules is more than specified */
	map_load_expected_error("too_many_rules_map", -EINVAL);

	/* The desc has a correct n_rules field, but the number of rules is too big (max 9) */
	map_load_expected_error("n_rules_too_big_map", -EINVAL);

	/* Some reserved bits set in a rule description */
	map_load_expected_error("reserved_bits_set_map", -EINVAL);

	/* Rule description has unknown type */
	map_load_expected_error("wrong_rule_type_map", -EINVAL);

	/* Rule description has too big size */
	map_load_expected_error("rule_size_too_big_map", -EINVAL);

	/* Rule description has size which is not power of 2 */
	map_load_expected_error("rule_size_not_po2_map", -EINVAL);
}

static void test_map_creation()
{
	/* Tests to check some incorrect parameters in uattr */
	test_map_creation_bad_uattr();

	/* More specific tests to check incorrect desc btf field */
	test_map_creation_bad_btf();
}

typedef void set_key_t(void *key, size_t size, __u8 x);
typedef void set_key_wildcard_t(void *key, size_t size);

static void set_key_prefix(void *key, size_t size, __u8 x)
{
	memset(key + 8, x, size);
	*(__u32 *)(key + 8 + size) = (u32)(size * 8);
}

static void set_key_prefix_wildcard(void *key, size_t size)
{
	memset(key + 8, 0, size);
	*(__u32 *)(key + 8 + size) = 0;
}

static void set_key_range(void *key, size_t size, __u8 x)
{
	memset(key + 8, x, size);
	memset(key + 8 + size, x, size);
}

static void set_key_range_wildcard(void *key, size_t size)
{
	memset(key + 8, 0, size);
	memset(key + 8 + size, 0xff, size); /* (u_size)-1 */
}

static void set_key_match(void *key, size_t size, __u8 x)
{
	memset(key + 8, x, size);
}

static void set_key_match_wildcard(void *key, size_t size)
{
	memset(key + 8, 0, size);
}

static void test_map_update(const char *map_name, int map_fd, struct wildcard_key *key)
{
	__u64 val = 0;
	int ret;

	/*
	 * We can't insert a key unless type is BPF_WILDCARD_KEY_RULE
	 */
	key->type = BPF_WILDCARD_KEY_MATCH;
	ret = bpf_map_update_elem(map_fd, key, &val, 0);
	ASSERT_EQ(ret, -EINVAL, pfx(map_name, "bpf_map_update_elem wildcard can't insert matches"));

	/*
	 * Test that we can insert and update elements in accordance with update flags
	 */
	key->type = BPF_WILDCARD_KEY_RULE;
	ret = bpf_map_update_elem(map_fd, key, &val, BPF_EXIST);
	ASSERT_EQ(ret, -ENOENT, pfx(map_name, "bpf_map_update_elem wildcard can update rule if !exists & BPF_EXIST"));
	ret = bpf_map_update_elem(map_fd, key, &val, BPF_NOEXIST);
	ASSERT_EQ(ret, 0, pfx(map_name, "bpf_map_update_elem wildcard can insert rules"));
	ret = bpf_map_update_elem(map_fd, key, &val, BPF_NOEXIST);
	ASSERT_EQ(ret, -EEXIST, pfx(map_name, "bpf_map_update_elem wildcard can't insert rule if exists & BPF_NOEXIST"));
	ret = bpf_map_update_elem(map_fd, key, &val, BPF_EXIST);
	ASSERT_EQ(ret, 0, pfx(map_name, "bpf_map_update_elem wildcard can update rule if exists & BPF_EXIST"));

	/*
	 * Delete the element to start from scratch
	 */
	ret = bpf_map_delete_elem(map_fd, key);
	ASSERT_EQ(ret, 0, pfx(map_name, "bpf_map_delete_elem wildcard can delete"));
}

/* Just a random non-zero value, but less than 0xff */
const int n_loops = 17;

static void test_map_get_next_key(const char *map_name,
				  int map_fd,
				  size_t size,
				  struct wildcard_key *key,
				  struct wildcard_key *next_key,
				  set_key_t set_key)
{
	__u64 val;
	int ret;
	int i;

	key->type = BPF_WILDCARD_KEY_RULE;
	for (i = 1; i <= n_loops; i++) {
		set_key(key, size, i);
		val = i;
		ret = bpf_map_update_elem(map_fd, key, &val, 0);
		ASSERT_EQ(ret, 0, S("%s: bpf_map_update_elem wildcard can update rule, loop=%d", map_name, i));
	}

	/* Should fail due to bad key type */
	next_key->type = BPF_WILDCARD_KEY_MATCH;
	ret = bpf_map_get_next_key(map_fd, next_key, next_key);
	ASSERT_EQ(ret, -EINVAL, pfx(map_name, "bpf_map_get_next_key wildcard can't lookup a match"));

	/* Should work, key 0xff doesn't exist */
	i = 0;
	next_key->type = BPF_WILDCARD_KEY_RULE;
	set_key(key, size, 0xff);
	for ( ;; ) {
		ret = bpf_map_get_next_key(map_fd, next_key, next_key);
		if (ret == -ENOENT)
			break;
		if (!ASSERT_EQ(ret, 0, S("%s: bpf_map_get_next_key wildcard: i=%d", map_name, i)))
			break;

		ret = bpf_map_lookup_elem(map_fd, next_key, &val);
		ASSERT_EQ(ret, 0, S("%s: bpf_map_lookup_elem wildcard: i=%d", map_name, i));
		i += val;
	}
	ASSERT_EQ(i, n_loops * (n_loops + 1) / 2, pfx(map_name, "bpf_map_lookup_elem wildcard all elems"));

	/* All elements should match */
	key->type = BPF_WILDCARD_KEY_MATCH;
	for (i = 1; i <= n_loops; i++) {
		set_key(key, size, i);
		ret = bpf_map_lookup_elem(map_fd, key, &val);
		ASSERT_EQ(ret, 0, S("%s: bpf_map_lookup_elem wildcard correct return code, i=%d", map_name, i));
		ASSERT_EQ(val, i, S("%s: bpf_map_lookup_elem wildcard correct value, i=%d", map_name, i));
	}

	/* Delete should fail if not a rule */
	key->type = BPF_WILDCARD_KEY_MATCH;
	set_key(key, size, 1);
	ret = bpf_map_delete_elem(map_fd, key);
	ASSERT_EQ(ret, -EINVAL, pfx(map_name, "bpf_map_delete_elem wildcard can't delete match"));

	/* Delete all elements; check that next_key approves the deletion */
	key->type = BPF_WILDCARD_KEY_RULE;
	for (i = 1; i <= n_loops; i++) {
		set_key(key, size, i);
		ret = bpf_map_delete_elem(map_fd, key);
		ASSERT_EQ(ret, 0, S("%s: bpf_map_delete_elem wildcard can delete rule, i=%d", map_name, i));
	}
	ret = bpf_map_get_next_key(map_fd, NULL, next_key);
	ASSERT_EQ(ret, -ENOENT, pfx(map_name, "bpf_map_get_next_key wildcard map is empty"));
}

static void test_map_priority(const char *map_name, int map_fd,
			      size_t size,
			      struct wildcard_key *key,
			      struct wildcard_key *next_key,
			      set_key_t set_key,
			      set_key_wildcard_t set_key_wildcard)
{
	__u64 val;
	int ret;
	int i;

	/* Insert elements with same keys, but different priorities, the lookup
	 * should always return the highest (inverse: lowest value) priority */
	key->type = BPF_WILDCARD_KEY_RULE;
	for (i = 1; i <= n_loops; i++) {
		set_key(key, size, 0x54);
		key->priority = i;
		val = i; /* value can be used to check if we got the right match in regards to priority */
		ret = bpf_map_update_elem(map_fd, key, &val, 0);
		ASSERT_EQ(ret, 0, S("%s: bpf_map_update_elem wildcard can update rule with priority, i=%d", map_name, i));
	}

	if (set_key_wildcard) {
		/* setup a wildcard entry */
		key->type = BPF_WILDCARD_KEY_RULE;
		set_key_wildcard(key, size);
		key->priority = 0xffffffff; /* the lowest priority ever */
		val = 0xffffffff; /* value can be used to check if we got the right match in regards to priority */
		ret = bpf_map_update_elem(map_fd, key, &val, 0);
		ASSERT_EQ(ret, 0, pfx(map_name, "bpf_map_update_elem wildcard can insert a wildcard match"));
	}

	/* The right priority should be matched for overlapping rules */
	for (i = 1; i <= n_loops; i++) {
		/* lookup should be correct with correct value */
		key->type = BPF_WILDCARD_KEY_RULE;
		key->priority = i;
		set_key(key, size, 0x54);
		ret = bpf_map_lookup_elem(map_fd, key, &val);
		ASSERT_EQ(ret, 0, S("%s: bpf_map_lookup_elem wildcard correct return value, i=%d", map_name, i));
		ASSERT_EQ(val, i, S("%s: bpf_map_lookup_elem wildcard correct priority, i=%d", map_name, i));

		/* match should be correct with correct priority */
		key->type = BPF_WILDCARD_KEY_MATCH;
		key->priority = 0;
		set_key(key, size, 0x54);
		ret = bpf_map_lookup_elem(map_fd, key, &val);
		ASSERT_EQ(ret, 0, S("%s: bpf_map_lookup_elem [match] correct return value, i=%d", map_name, i));
		ASSERT_EQ(val, i, S("%s: bpf_map_lookup_elem [match] correct priority, i=%d", map_name, i));

		/* delete the highest priority so that we can jump to the next one */
		key->type = BPF_WILDCARD_KEY_RULE;
		set_key(key, size, 0x54);
		key->priority = i;
		ret = bpf_map_delete_elem(map_fd, key);
		ASSERT_EQ(ret, 0, S("%s: bpf_map_delete_elem wildcard can delete rule with priority, i=%d", map_name, i));

		/* if key doesn't exist, but wildcard rule is there, it should match */
		if (set_key_wildcard) {
			key->type = BPF_WILDCARD_KEY_MATCH;
			key->priority = 0;
			set_key(key, size, 0x33);
			ret = bpf_map_lookup_elem(map_fd, key, &val);
			ASSERT_EQ(ret, 0, S("%s: bpf_map_lookup_elem wildcard precise value, correct priority, i=%d", map_name, i));
			ASSERT_EQ(val, 0xffffffff, S("%s: bpf_map_lookup_elem wildcard precise value, correct wildcard priority, i=%d", map_name, i));
		}
	}

	if (set_key_wildcard) {
		key->type = BPF_WILDCARD_KEY_RULE;
		set_key_wildcard(key, size);
		key->priority = 0xffffffff; /* the lowest priority ever */
		ret = bpf_map_delete_elem(map_fd, key);
		ASSERT_EQ(ret, 0, pfx(map_name, "bpf_map_delete_elem wildcard can delete a wildcard match"));
	}

	/* The map should be empty now */
	key->type = BPF_WILDCARD_KEY_MATCH;
	key->priority = 0;
	set_key(key, size, 0x54);
	ret = bpf_map_lookup_elem(map_fd, key, &val);
	ASSERT_EQ(ret, -ENOENT, pfx(map_name, "bpf_map_lookup_elem wildcard precise value, map is empty"));
	ret = bpf_map_get_next_key(map_fd, NULL, next_key);
	ASSERT_EQ(ret, -ENOENT, pfx(map_name, "bpf_map_get_next_key wildcard map is empty"));
}

static void test_map_basic(const char *map_name, int map_fd,
			   size_t field_size, size_t key_size,
			   set_key_t set_key, set_key_wildcard_t set_key_wildcard)
{
	void *next_key = calloc(1, key_size);
	void *key = calloc(1, key_size);

	test_map_update(map_name, map_fd, key);
	test_map_get_next_key(map_name, map_fd, field_size, key, next_key, set_key);
	test_map_priority(map_name, map_fd, field_size, key, next_key, set_key, set_key_wildcard);

	free(next_key);
	free(key);
}

static void test_map_prefix(const char *map_name, int map_fd, size_t size)
{
	/*
	 * struct prefix_key {
	 *     __u32 type;
	 *     __u32 priority;
	 *     __u8 x[size];
	 *     __u32 prefix;
	 * } __attribute__((packed, aligned(4)));
	 */
	size_t key_size = 2 * sizeof(__u32) + size + sizeof(__u32);

	test_map_basic(map_name, map_fd, size, key_size,
		       set_key_prefix, set_key_prefix_wildcard);
}

static void test_map_range(const char *map_name, int map_fd, size_t size)
{
	/* struct range_key {
	 *     __u32 type;
	 *     __u32 priority;
	 *     __u8 min[size];
	 *     __u8 max[size];
	 * } __attribute__((packed, aligned(4)));
	 */
	size_t key_size = 2 * sizeof(__u32) + 2 * size;

	test_map_basic(map_name, map_fd, size, key_size,
		       set_key_range, set_key_range_wildcard);
}

static void test_map_match(const char *map_name, int map_fd, size_t size, bool wildcard)
{
	/*
	 * struct match_key {
	 *     __u32 type;
	 *     __u32 priority;
	 *     __u8 x[size];
	 * } __attribute__((packed, aligned(4)));
	 */
	size_t key_size = 2 * sizeof(__u32) + size;

	test_map_basic(map_name, map_fd, size, key_size, set_key_match,
		       wildcard ? set_key_match_wildcard : NULL);
}

#define NAME_AND_FD(MAP) #MAP, bpf_map__fd(skel->maps. MAP)

static void test_map_basic_functionality_userspace(void)
{
	struct wildcard_map *skel;
	bool wildcard;
	int ret;

	skel = wildcard_map__open();
	if (!ASSERT_OK_PTR(skel, "wildcard_map__open"))
		return;

	bpf_program__set_autoload(skel->progs.check_wildcard, false);

	ret = skip_broken_maps(skel);
	if (!ASSERT_EQ(ret, 0, "skip_broken_maps"))
		goto destroy;

	test_map_prefix(NAME_AND_FD(prefix_1), 1);
	test_map_prefix(NAME_AND_FD(prefix_2), 2);
	test_map_prefix(NAME_AND_FD(prefix_4), 4);
	test_map_prefix(NAME_AND_FD(prefix_8), 8);
	test_map_prefix(NAME_AND_FD(prefix_16), 16);

	test_map_range(NAME_AND_FD(range_1), 1);
	test_map_range(NAME_AND_FD(range_2), 2);
	test_map_range(NAME_AND_FD(range_4), 4);
	test_map_range(NAME_AND_FD(range_8), 8);

	wildcard = false;
	test_map_match(NAME_AND_FD(match_1), 1, wildcard);
	test_map_match(NAME_AND_FD(match_2), 2, wildcard);
	test_map_match(NAME_AND_FD(match_4), 4, wildcard);
	test_map_match(NAME_AND_FD(match_8), 8, wildcard);
	test_map_match(NAME_AND_FD(match_16), 16, wildcard);

	wildcard = true;
	test_map_match(NAME_AND_FD(xmatch_1), 1, wildcard);
	test_map_match(NAME_AND_FD(xmatch_2), 2, wildcard);
	test_map_match(NAME_AND_FD(xmatch_4), 4, wildcard);
	test_map_match(NAME_AND_FD(xmatch_8), 8, wildcard);
	test_map_match(NAME_AND_FD(xmatch_16), 16, wildcard);

destroy:
	wildcard_map__destroy(skel);
}

static void test_map_basic_functionality_bpf(void)
{
	struct wildcard_map *skel;
	struct bpf_link *link;
	int ret;

	skel = wildcard_map__open();
	if (!ASSERT_OK_PTR(skel, "wildcard_map__open_and_load"))
		return;

	ret = skip_broken_maps(skel);
	if (!ASSERT_EQ(ret, 0, "skip_broken_maps"))
		goto destroy;

	link = bpf_program__attach(skel->progs.check_wildcard);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto destroy;

	syscall(SYS_getpgid);

	ASSERT_EQ(skel->bss->error, 0ULL, S("error: test #%d", skel->bss->test_no));

	bpf_link__destroy(link);

destroy:
	wildcard_map__destroy(skel);
}

void test_wildcard_map(void)
{
	/* rfc */
	test_human_friendly();

	test_map_creation();
	test_map_basic_functionality_userspace();
	test_map_basic_functionality_bpf();
}
