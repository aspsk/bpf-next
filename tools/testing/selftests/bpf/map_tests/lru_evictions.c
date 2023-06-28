// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <bpf_util.h>
#include <test_maps.h>

#define MAX_ENTRIES 16384
#define N_THREADS 1

#define MAX_MAP_KEY_SIZE 4

static void map_info(int map_fd, struct bpf_map_info *info)
{
	__u32 len = sizeof(*info);
	int ret;

	memset(info, 0, sizeof(*info));

	ret = bpf_obj_get_info_by_fd(map_fd, info, &len);
	CHECK(ret < 0, "bpf_obj_get_info_by_fd", "error: %s\n", strerror(errno));
}

static void *map_key(__u32 type, __u32 i)
{
	static __thread __u8 key[MAX_MAP_KEY_SIZE];

	*(__u32 *)key = i;
	return key;
}

static __u32 map_count_elements(__u32 type, int map_fd)
{
	void *key = map_key(type, -1);
	int n = 0;

	while (!bpf_map_get_next_key(map_fd, key, key))
		n++;
	return n;
}

static void delete_all_elements(__u32 type, int map_fd)
{
	void *key = map_key(type, -1);
	void *keys;
	int n = 0;
	int ret;

	keys = calloc(MAX_MAP_KEY_SIZE, MAX_ENTRIES);
	CHECK(!keys, "calloc", "error: %s\n", strerror(errno));

	for (; !bpf_map_get_next_key(map_fd, key, key); n++)
		memcpy(keys + n*MAX_MAP_KEY_SIZE, key, MAX_MAP_KEY_SIZE);

	while (--n >= 0) {
		ret = bpf_map_delete_elem(map_fd, keys + n*MAX_MAP_KEY_SIZE);
		CHECK(ret < 0, "bpf_map_delete_elem", "error: %s\n", strerror(errno));
	}
}

static bool is_lru(__u32 map_type)
{
	return map_type == BPF_MAP_TYPE_LRU_HASH ||
	       map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

struct upsert_opts {
	__u32 map_type;
	int map_fd;
	__u32 n;
};

static int x = 0;

static void *patch_map_thread(void *arg)
{
	struct upsert_opts *opts = arg;
	void *key;
	int val;
	int ret;
	int i;

	for (i = 0; i < opts->n; i++) {
		key = map_key(opts->map_type, i);
		val = rand();
		ret = bpf_map_update_elem(opts->map_fd, key, &val, 0);
		CHECK(ret < 0, "bpf_map_update_elem", "error: %s\n", strerror(errno));

		x += 1;
	}
	return NULL;
}

static void upsert_elements(struct upsert_opts *opts)
{
	pthread_t threads[N_THREADS];
	int ret;
	int i;

	for (i = 0; i < ARRAY_SIZE(threads); i++) {
		ret = pthread_create(&i[threads], NULL, patch_map_thread, opts);
		CHECK(ret != 0, "pthread_create", "error: %s\n", strerror(ret));
	}

	for (i = 0; i < ARRAY_SIZE(threads); i++) {
		ret = pthread_join(i[threads], NULL);
		CHECK(ret != 0, "pthread_join", "error: %s\n", strerror(ret));
	}
}

#include <err.h>

static void __test(int map_fd)
{
	__u32 n = MAX_ENTRIES + 1;
	__u32 real_current_elements;
	struct upsert_opts opts = {
		.map_fd = map_fd,
		.n = n,
	};
	struct bpf_map_info info;

	map_info(map_fd, &info);
	opts.map_type = info.type;

	/*
	 * Upsert keys [0, n) under some competition: with random values from
	 * N_THREADS threads
	 */
	upsert_elements(&opts);

	/*
	 * The sum of percpu elements counters for all hashtable-based maps
	 * should be equal to the number of elements present in the map. For
	 * non-lru maps this number should be the number n of upserted
	 * elements. For lru maps some elements might have been evicted. Check
	 * that all numbers make sense
	 */
	map_info(map_fd, &info);
	real_current_elements = map_count_elements(info.type, map_fd);
	if (!is_lru(info.type))
		CHECK(n != real_current_elements, "map_count_elements",
		      "real_current_elements(%u) != expected(%u)\n", real_current_elements, n);

	warnx("real_current_elements=%u n=%u", real_current_elements, n);

	/*
	 * Cleanup the map and check that all elements are actually gone and
	 * that the sum of percpu elements counters is back to 0 as well
	 */
	delete_all_elements(info.type, map_fd);
	map_info(map_fd, &info);
	real_current_elements = map_count_elements(info.type, map_fd);
	CHECK(real_current_elements, "map_count_elements",
	      "expected real_current_elements=0, got %u", real_current_elements);

	close(map_fd);
}

static int map_create_opts(__u32 type, const char *name,
			   struct bpf_map_create_opts *map_opts,
			   __u32 key_size, __u32 val_size)
{
	int map_fd;

	map_fd = bpf_map_create(type, name, key_size, val_size, MAX_ENTRIES, map_opts);
	CHECK(map_fd < 0, "bpf_map_create()", "error:%s (name=%s)\n",
			strerror(errno), name);

	return map_fd;
}

static int map_create(__u32 type, const char *name, struct bpf_map_create_opts *map_opts)
{
	return map_create_opts(type, name, map_opts, sizeof(int), sizeof(int));
}

static int create_lru_hash(void)
{
	return map_create(BPF_MAP_TYPE_LRU_HASH, "lru_hash", NULL);
}

static int create_percpu_lru_hash(void)
{
	return map_create(BPF_MAP_TYPE_LRU_PERCPU_HASH, "lru_hash_percpu", NULL);
}

void test_lru_evictions(void)
{
	__test(create_lru_hash());
	printf("test_%s:PASS\n", __func__);

	if (0) {
	__test(create_percpu_lru_hash());
	printf("test_%s:PASS\n", __func__);
	}
}
