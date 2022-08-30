// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Isovalent, Inc.
 */
/*
 * The wildcard map algorithm is a derivative of the algorithm presented in the
 * following paper: Daly, J., Bruschi, V., Linguaglossa, L., Pontarelli, S.,
 * Rossi, D., Tollet, J., Torng, E., and Yourtchenko, A., 2019.  "TupleMerge:
 * Fast Software Packet Processing for Online Packet Classification." IEEE/ACM
 * Transactions on Networking, https://dx.doi.org/10.1109/TNET.2019.2920718
 */

#include <linux/container_of.h>
#include <linux/btf_ids.h>
#include <linux/random.h>
#include <linux/xxhash.h>
#include <linux/sort.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/btf.h>
#include <linux/err.h>

#include <asm/unaligned.h>

#define WILDCARD_CREATE_FLAG_MASK \
	(BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | \
	 BPF_F_ACCESS_MASK | BPF_F_ZERO_SEED)

/* Max number of rules */
#define BPF_WILDCARD_MAX_RULES 9

/* We only support rules of size 1,2,4,...,BPF_WILDCARD_MAX_RULE_SIZE */
#define BPF_WILDCARD_MAX_RULE_SIZE 16

/* Max hash size in bytes: 144. An IPv6 5-tuple size is (16+2)*2+1=37 */
#define BPF_WILDCARD_MAX_TOTAL_HASH_SIZE  \
	(BPF_WILDCARD_MAX_RULES * BPF_WILDCARD_MAX_RULE_SIZE)

union wildcard_lock {
	spinlock_t     lock;
	raw_spinlock_t raw_lock;
};

struct tm_bucket {
	struct hlist_head head;
	atomic_t n_elements;
};

struct tm_mask {
	u32 n_prefixes;
        u8 prefix[];
};

struct tm_table {
	struct list_head list;
	struct tm_mask *mask;
	atomic_t n_elements;
	struct rcu_head rcu;
	u32 id;
};

struct bpf_wildcard {
	struct bpf_map map;
	u32 elem_size;
	struct wildcard_desc *desc;
	bool prealloc;
	struct lock_class_key lockdep_key;

	/* currently, all map updates are protected by a single lock,
	 * so count is not atomic/percpu */
	int count;

	struct tm_bucket *buckets;
	u32 n_buckets;

	union wildcard_lock lock; /* one global lock to rule them all */
	struct list_head tables_list_head;
};

struct wcard_elem {
	struct bpf_wildcard *wcard;

	struct hlist_node node;
	struct rcu_head rcu;

	u32 table_id;
	u32 hash;

	char key[] __aligned(8);
};

static bool parse_rule(u32 x, u32 *type_res, u32 *size_res)
{
	u32 type = x >> 8;
	u32 size = x & 0xff;

	if (type & 0xffff0000)
		return false;

	switch (type) {
	case BPF_WILDCARD_RULE_PREFIX:
	case BPF_WILDCARD_RULE_MATCH:
	case BPF_WILDCARD_RULE_WILDCARD_MATCH:
		switch (size) {
		case 1: case 2: case 4: case 8: case 16:
			break;
		default:
			return false;
		}
		break;
	case BPF_WILDCARD_RULE_RANGE:
		switch (size) {
		case 1: case 2: case 4: case 8:
			break;
		default:
			return false;
		}
		break;
	default:
		return false;
	}
	*type_res = type;
	*size_res = size;
	return true;
}

/*
 * The key should have the following structure:
 *
 *     struct some_key {
 *         struct desc desc[0];
 *         __u32 type;
 *         __u32 priority;
 *         ... custom fields ...
 *     };
 *
 * The purpose of the wildcard_desc_from_btf() function is to parse the 'desc'
 * field and create a corresponding 'struct wildcard_desc' structure. The desc
 * inside the key should have the following format:
 *
 *     struct {
 *             __uint(n_rules, N);
 *             __uint(rule_1, TYPE_1 << 8 | SIZE_1);
 *             __uint(rule_2, TYPE_2 << 8 | SIZE_2);
 *             ...
 *             __uint(rule_N, TYPE_N << 8 | SIZE_N);
 *     };
 *
 * for example,
 *
 *     struct {
 *             __uint(n_rules, 4);
 *             __uint(saddr, BPF_WILDCARD_RULE_PREFIX << 8 | sizeof(__u32));
 *             __uint(daddr, BPF_WILDCARD_RULE_PREFIX << 8 | sizeof(__u32));
 *             __uint(sport, BPF_WILDCARD_RULE_RANGE << 8 | sizeof(__u16));
 *             __uint(dport, BPF_WILDCARD_RULE_RANGE << 8 | sizeof(__u16));
 *     };
 *
 * To simplify definition of these structures, a helper macro is available, for
 * example, the following definition
 *
 *     BPF_WILDCARD_DESC_4(
 *             four_tuple,
 *             BPF_WILDCARD_RULE_PREFIX, __u32, saddr,
 *             BPF_WILDCARD_RULE_PREFIX, __u32, saddr,
 *             BPF_WILDCARD_RULE_RANGE, __u16, sport,
 *             BPF_WILDCARD_RULE_RANGE, __u16, dport
 *     );
 *
 * will define a corresponding 'struct four_tuple_key' suitable to be used in a
 * map definition.
 */
static void *wildcard_desc_from_btf(u32 btf_fd, u32 key_type_id)
{
	const struct btf_array *desc_array;
	const struct btf_member *m;
	struct wildcard_desc *desc;
	const struct btf_type *t;
	u32 hash_size = 0;
	const char *name;
	struct btf *btf;
	u32 type, size;
	u32 n_rules, x;
	u64 desc_size;
	void *ret;
	u16 vlen;
	int i;

	btf = btf_get_by_fd(btf_fd);
	if (IS_ERR(btf))
		return btf;

	if (btf_is_kernel(btf)) {
		ret = ERR_PTR(-EACCES);
		goto put_btf;
	}

	t = btf_type_by_id(btf, key_type_id);
	if (!t) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	if (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	m = btf_members(t);
	if (!m) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	name = btf_name_by_offset(btf, m->name_off);
	if (!name || strcmp(name, "desc")) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	t = btf_type_by_id(btf, m->type);
	if (!t) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	if (BTF_INFO_KIND(t->info) != BTF_KIND_ARRAY) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	desc_array = btf_array(t);
	if (!desc_array) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	t = btf_type_by_id(btf, desc_array->type);
	if (!t) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	if (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	m = btf_members(t);

	name = btf_name_by_offset(btf, m->name_off);
	if (!name || strcmp(name, "n_rules") || btf_get_int(btf, m, &n_rules)) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	vlen = btf_vlen(t);
	if (vlen != n_rules + 1) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	if (n_rules == 0 || n_rules > BPF_WILDCARD_MAX_RULES) {
		ret = ERR_PTR(-EINVAL);
		goto put_btf;
	}

	desc_size = sizeof(*desc) + n_rules * sizeof(desc->rule_desc[0]);
	desc = bpf_map_area_alloc(desc_size, NUMA_NO_NODE);
	if (!desc) {
		ret = ERR_PTR(-ENOMEM);
		goto put_btf;
	}
	desc->n_rules = n_rules;

	for (i = 0; i < vlen - 1; i += 1) {
		if (btf_get_int(btf, ++m, &x) ||
		    !parse_rule(x, &type, &size) ||
		    ((hash_size += size) > BPF_WILDCARD_MAX_TOTAL_HASH_SIZE)) {
			bpf_map_area_free(desc);
			ret = ERR_PTR(-EINVAL);
			goto put_btf;
		}
		desc->rule_desc[i].type = type;
		desc->rule_desc[i].size = size;
	}

	ret = desc;

put_btf:
	btf_put(btf);
	return ret;
}

typedef struct {
	u64 hi;
	u64 lo;
} u128;

/* TYPE is one of u8, u16, u32 or u64 */
#define __mask(TYPE, PFX) \
	(PFX? (TYPE)-1 << ((sizeof(TYPE) * 8) - PFX) : 0)

#define __mask_prefix(TYPE, X, PFX) \
	(*(TYPE*)(X) & __mask(TYPE, (PFX)))

#define ____match_prefix(TYPE, RULE, PFX, ELEM) \
	(__mask_prefix(TYPE, (ELEM), PFX) == *(TYPE*)(RULE))

#define ____match_range(TYPE, X_MIN, X_MAX, X) \
	(*(TYPE*)(X_MIN) <= *(TYPE*)(X) && *(TYPE*)(X_MAX) >= *(TYPE*)(X))

static inline int
__match_prefix(u32 size, const void *prule, const void *pprefix, const void *pelem)
{
	u32 prefix = get_unaligned((u32 *)pprefix);

	if (size == 16) {
		u128 rule;
		u128 elem;

		rule.lo = get_unaligned((u64 *)prule);
		rule.hi = get_unaligned((u64 *)(prule+8));
		elem.hi = get_unaligned_be64((u64 *)pelem);
		elem.lo = get_unaligned_be64((u64 *)(pelem+8));

		if (prefix <= 64) {
			return ____match_prefix(u64, &rule.hi, prefix, &elem.hi);
		} else {
			return (rule.hi == elem.hi &&
				____match_prefix(u64, &rule.lo, prefix-64, &elem.lo));
		}
	} else if (size == 4) {
		u32 rule = get_unaligned((u32 *) prule);
		u32 elem = get_unaligned_be32(pelem);
		return ____match_prefix(u32, &rule, prefix, &elem);
	} else if (size == 8) {
		u64 rule = get_unaligned((u64 *) prule);
		u64 elem = get_unaligned_be64(pelem);
		return ____match_prefix(u64, &rule, prefix, &elem);
	} else if (size == 2) {
		u16 rule = get_unaligned((u16 *) prule);
		u16 elem = get_unaligned_be16(pelem);
		return ____match_prefix(u16, &rule, prefix, &elem);
	} else if (size == 1) {
		return ____match_prefix(u8, prule, prefix, pelem);
	}

	BUG();
	return 0;
}

static inline int
__match_range(u32 size, const void *pmin, const void *pmax, const void *pelem)
{
	if (size == 2) {
		u16 min = get_unaligned((u16 *) pmin);
		u16 max = get_unaligned((u16 *) pmax);
		u16 elem = get_unaligned_be16(pelem);
		return ____match_range(u16, &min, &max, &elem);
	} else if (size == 1) {
		return ____match_range(u8, pmin, pmax, pelem);
	} else if (size == 4) {
		u32 min = get_unaligned((u32 *) pmin);
		u32 max = get_unaligned((u32 *) pmax);
		u32 elem = get_unaligned_be32(pelem);
		return ____match_range(u32, &min, &max, &elem);
	} else if (size == 8) {
		u64 min = get_unaligned((u64 *) pmin);
		u64 max = get_unaligned((u64 *) pmax);
		u64 elem = get_unaligned_be64(pelem);
		return ____match_range(u64, &min, &max, &elem);
	}

	BUG();
	return 0;
}

static inline bool __match_wildcard(u32 size, const void *rule, const void *elem)
{
	static const u8 zero[BPF_WILDCARD_MAX_RULE_SIZE] = {};

	if (!memcmp(zero, rule, size))
		return true;

	return !memcmp(rule, elem, size);
}

static inline int __match_rule(const struct wildcard_rule_desc *desc,
			       const void *rule, const void *elem)
{
	u32 size = desc->size;

	switch (desc->type) {
	case BPF_WILDCARD_RULE_PREFIX:
		switch (size) {
		case 1: case 2: case 4: case 8: case 16:
			return __match_prefix(size, rule, rule+size, elem);
		}
		break;
	case BPF_WILDCARD_RULE_RANGE:
		switch (desc->size) {
		case 1: case 2: case 4: case 8:
			return __match_range(size, rule, rule+size, elem);
		}
		break;
	case BPF_WILDCARD_RULE_WILDCARD_MATCH:
		return __match_wildcard(size, rule, elem);
	case BPF_WILDCARD_RULE_MATCH:
		return !memcmp(rule, elem, size);
	}

	BUG();
	return 0;
}

static inline int __match(const struct wildcard_desc *desc,
			  const struct wildcard_key *rule,
			  const struct wildcard_key *elem)
{
	u32 off_rule = 0, off_elem = 0;
	u32 i, size;

	for (i = 0; i < desc->n_rules; i++) {
		if (!__match_rule(&desc->rule_desc[i],
				  &rule->data[off_rule],
				  &elem->data[off_elem]))
			return 0;

		size = desc->rule_desc[i].size;
		switch (desc->rule_desc[i].type) {
		case BPF_WILDCARD_RULE_PREFIX:
			off_rule += size + sizeof(u32);
			break;
		case BPF_WILDCARD_RULE_RANGE:
			off_rule += 2 * size;
			break;
		case BPF_WILDCARD_RULE_MATCH:
		case BPF_WILDCARD_RULE_WILDCARD_MATCH:
			off_rule += size;
			break;
		}
		off_elem += size;
	}
	return 1;
}

static void patch_endianness(u8 *x, size_t size)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	size_t i;
	u8 t;

	for (i = 0; i < size/2; i++) {
		t = x[i];
		x[i] = x[size - 1 - i];
		x[size - 1 - i] = t;
	}
#endif
}

/*
 * We're assuming that every field of type PREFIX or RANGE comes in network
 * byte order (we do not care about MATCH and WILDCARD_MATCH, because we don't
 * do any computations with them, only hashing). We convert such fields to
 * host byte order to store, and back, when returning keys.
 */
static void patch_key(struct wildcard_desc *desc, void *key)
{
	u32 off = 0;
	u32 i, size;

	for (i = 0; i < desc->n_rules; i++) {
		size = desc->rule_desc[i].size;
		switch (desc->rule_desc[i].type) {
		case BPF_WILDCARD_RULE_PREFIX:
			patch_endianness(key + 8 + off, size);
			off += size + sizeof(u32);
			break;
		case BPF_WILDCARD_RULE_RANGE:
			patch_endianness(key + 8 + off, size);
			patch_endianness(key + 8 + off + size, size);
			off += 2 * size;
			break;
		case BPF_WILDCARD_RULE_MATCH:
		case BPF_WILDCARD_RULE_WILDCARD_MATCH:
			off += size;
			break;
		}
	}
}

static int check_map_update_flags(void *l_old, u64 map_flags)
{
	if (l_old && (map_flags & ~BPF_F_LOCK) == BPF_NOEXIST)
		/* elem already exists */
		return -EEXIST;

	if (!l_old && (map_flags & ~BPF_F_LOCK) == BPF_EXIST)
		/* elem doesn't exist, cannot update it */
		return -ENOENT;

	return 0;
}

static inline bool wcard_use_raw_lock(const struct bpf_wildcard *wcard)
{
	return (!IS_ENABLED(CONFIG_PREEMPT_RT) || wcard->prealloc);
}

static struct wcard_elem *wcard_elem_alloc(struct bpf_wildcard *wcard,
					   const void *key,
					   void *value,
					   void *l_old)
{
	struct bpf_map *map = &wcard->map;
	u32 key_size = map->key_size;
	struct wcard_elem *l;

	if (wcard->count >= wcard->map.max_entries && !l_old)
		return ERR_PTR(-E2BIG);

	wcard->count++;
	l = bpf_map_kmalloc_node(map, wcard->elem_size,
				 GFP_ATOMIC | __GFP_NOWARN, map->numa_node);
	if (unlikely(!l)) {
		wcard->count--;
		return ERR_PTR(-ENOMEM);
	}
	l->wcard = wcard;
	memcpy(l->key, key, key_size);
	copy_map_value(map, l->key + round_up(key_size, 8), value);
	return l;
}

static void __wcard_elem_free(struct wcard_elem *l)
{
	l->wcard->count--;
	kfree(l);
}

static void wcard_elem_free_rcu(struct rcu_head *head)
{
	struct wcard_elem *l = container_of(head, struct wcard_elem, rcu);

	__wcard_elem_free(l);
}

static void wcard_elem_free(struct wcard_elem *l)
{
	call_rcu(&l->rcu, wcard_elem_free_rcu);
}

static inline void wcard_init_lock(struct bpf_wildcard *wcard,
				   union wildcard_lock *lock)
{
	if (wcard_use_raw_lock(wcard)) {
		raw_spin_lock_init(&lock->raw_lock);
		lockdep_set_class(&lock->raw_lock, &wcard->lockdep_key);
	} else {
		spin_lock_init(&lock->lock);
		lockdep_set_class(&lock->lock, &wcard->lockdep_key);
	}
}

static inline int wcard_lock(struct bpf_wildcard *wcard,
			     union wildcard_lock *lock,
			     unsigned long *pflags)
{
	unsigned long flags;

	if (wcard_use_raw_lock(wcard))
		raw_spin_lock_irqsave(&lock->raw_lock, flags);
	else
		spin_lock_irqsave(&lock->lock, flags);
	*pflags = flags;

	return 0;
}

static inline void wcard_unlock(struct bpf_wildcard *wcard,
				union wildcard_lock *lock,
				unsigned long flags)
{
	if (wcard_use_raw_lock(wcard))
		raw_spin_unlock_irqrestore(&lock->raw_lock, flags);
	else
		spin_unlock_irqrestore(&lock->lock, flags);
}

static void __tm_copy_masked_rule(void *dst, const void *data, u32 size, u32 prefix)
{
	if (size == 1) {
		u8 x = *(u8 *)data;
		x = __mask_prefix(u8, &x, prefix);
		memcpy(dst, &x, 1);
	} else if (size == 2) {
		u16 x = get_unaligned((u16 *) data);
		x = __mask_prefix(u16, &x, prefix);
		memcpy(dst, &x, 2);
	} else if (size == 4) {
		u32 x = get_unaligned((u32 *) data);
		x = __mask_prefix(u32, &x, prefix);
		memcpy(dst, &x, 4);
	} else if (size == 8) {
		u64 x = get_unaligned((u64 *) data);
		x = __mask_prefix(u64, &x, prefix);
		memcpy(dst, &x, 8);
	} else if (size == 16) {
		u128 x;

		x.lo = get_unaligned((u64 *)data);
		x.hi = get_unaligned((u64 *)(data+8));

		/* if prefix is less than 64, then we will zero out the lower
		 * part in any case, otherwise we won't mask out any bits from
		 * the higher part; in any case, first we copy the lower part */
		if (prefix <= 64) {
			x.lo = 0;
			x.hi = __mask_prefix(u64, &x.hi, prefix);
		} else {
			x.lo = __mask_prefix(u64, &x.lo, prefix-64);
		}
		memcpy(dst, &x, 16);
	}
}

static void __tm_copy_masked_elem(void *dst, const void *data, u32 size, u32 prefix)
{
	if (size == 1) {
		u8 x = *(u8 *)data;
		x = __mask_prefix(u8, &x, prefix);
		memcpy(dst, &x, 1);
	} else if (size == 2) {
		u16 x = get_unaligned_be16(data);
		x = __mask_prefix(u16, &x, prefix);
		memcpy(dst, &x, 2);
	} else if (size == 4) {
		u32 x = get_unaligned_be32(data);
		x = __mask_prefix(u32, &x, prefix);
		memcpy(dst, &x, 4);
	} else if (size == 8) {
		u64 x = get_unaligned_be64(data);
		x = __mask_prefix(u64, &x, prefix);
		memcpy(dst, &x, 8);
	} else if (size == 16) {
		u128 x;

		x.hi = get_unaligned_be64(data);
		x.lo = get_unaligned_be64(data+8);

		/* if prefix is less than 64, then we will zero out the lower
		 * part in any case, otherwise we won't mask out any bits from
		 * the higher part; in any case, first we copy the lower part */
		if (prefix <= 64) {
			x.hi = __mask_prefix(u64, &x.hi, prefix);
			x.lo = 0;
		} else {
			x.lo = __mask_prefix(u64, &x.lo, prefix-64);
		}
		memcpy(dst, &x, 16);
	}
}

static inline u32 bpf_hash32(const void *key, u32 length, u32 initval)
{
       return xxh64(key, length, initval) >> 32;
}

static u32 tm_hash_rule(const struct wildcard_desc *desc,
			const struct tm_table *table,
			const struct wildcard_key *key)
{
	u8 buf[BPF_WILDCARD_MAX_TOTAL_HASH_SIZE];
	const void *data = key->data;
	u32 type, size, i;
	u32 n = 0;

	for (i = 0; i < desc->n_rules; i++) {

		type = desc->rule_desc[i].type;
		size = desc->rule_desc[i].size;

		if (type == BPF_WILDCARD_RULE_RANGE ||
		    ((type == BPF_WILDCARD_RULE_PREFIX ||
		      type == BPF_WILDCARD_RULE_WILDCARD_MATCH) &&
		      !table->mask->prefix[i]))
			goto ignore;

		if (likely(type == BPF_WILDCARD_RULE_PREFIX))
			__tm_copy_masked_rule(buf+n, data, size,
					      table->mask->prefix[i]);
		else if (type == BPF_WILDCARD_RULE_MATCH ||
			 type == BPF_WILDCARD_RULE_WILDCARD_MATCH)
			memcpy(buf+n, data, size);

		n += size;
ignore:
		switch (type) {
		case BPF_WILDCARD_RULE_PREFIX:
			data += size + sizeof(u32);
			break;
		case BPF_WILDCARD_RULE_RANGE:
			data += 2 * size;
			break;
		case BPF_WILDCARD_RULE_MATCH:
		case BPF_WILDCARD_RULE_WILDCARD_MATCH:
			data += size;
			break;
		}
	}

	return bpf_hash32(buf, n, table->id);
}

static u32 tm_hash(const struct wildcard_desc *desc,
		   const struct tm_table *table,
		   const struct wildcard_key *key)
{
	u8 buf[BPF_WILDCARD_MAX_TOTAL_HASH_SIZE];
	const void *data = key->data;
	u32 type, size, i;
	u32 n = 0;

	for (i = 0; i < desc->n_rules; i++) {

		type = desc->rule_desc[i].type;
		size = desc->rule_desc[i].size;

		if (type == BPF_WILDCARD_RULE_RANGE ||
		    ((type == BPF_WILDCARD_RULE_PREFIX ||
		      type == BPF_WILDCARD_RULE_WILDCARD_MATCH) &&
		      !table->mask->prefix[i]))
			goto ignore;

		if (likely(type == BPF_WILDCARD_RULE_PREFIX))
			__tm_copy_masked_elem(buf+n, data, size,
					      table->mask->prefix[i]);
		else if (type == BPF_WILDCARD_RULE_MATCH ||
			 type == BPF_WILDCARD_RULE_WILDCARD_MATCH)
			memcpy(buf+n, data, size);

		n += size;
ignore:
		data += size;
	}

	return bpf_hash32(buf, n, table->id);
}

static struct wcard_elem *__tm_lookup(const struct bpf_wildcard *wcard,
				      const struct wildcard_key *key,
				      struct tm_table **table_ptr,
				      struct tm_bucket **bucket_ptr)
{
	struct tm_bucket *bucket;
	struct tm_table *table;
	struct wcard_elem *l;
	u32 hash;

	list_for_each_entry_rcu(table, &wcard->tables_list_head, list) {
		hash = tm_hash_rule(wcard->desc, table, key);
		bucket = &wcard->buckets[hash & (wcard->n_buckets - 1)];
		hlist_for_each_entry_rcu(l, &bucket->head, node) {
			if (l->hash != hash)
				continue;
			if (l->table_id != table->id)
				continue;
			if (!memcmp(l->key, key, wcard->map.key_size)) {
				if (table_ptr)
					*table_ptr = table;
				if (bucket_ptr)
					*bucket_ptr = bucket;
				return l;
			}
		}
	}
	return NULL;
}

static void *tm_match(const struct bpf_wildcard *wcard,
		      const struct wildcard_key *key)
{
	struct wcard_elem *l, *ret = NULL;
	struct wildcard_key *curr_key;
	struct tm_bucket *bucket;
	struct tm_table *table;
	u32 min_priority;
	u32 hash;

	list_for_each_entry_rcu(table, &wcard->tables_list_head, list) {
		hash = tm_hash(wcard->desc, table, key);
		bucket = &wcard->buckets[hash & (wcard->n_buckets - 1)];
		hlist_for_each_entry_rcu(l, &bucket->head, node) {
			if (l->hash != hash)
				continue;
			if (l->table_id != table->id)
				continue;
			curr_key = (void *)l->key;
			if (__match(wcard->desc, curr_key, key)) {
				if (!ret || min_priority > curr_key->priority) {
					ret = l;
					min_priority = curr_key->priority;
				}
			}
		}
	}
	return ret;
}

static void *tm_lookup(const struct bpf_wildcard *wcard,
		       struct wildcard_key *key)
{
	/* Store prefixes and ranges in host byte order */
	patch_key(wcard->desc, key);
	return __tm_lookup(wcard, key, NULL, NULL);
}

static void __tm_table_free(struct tm_table *table)
{
	bpf_map_area_free(table);
}

static void tm_table_free_rcu(struct rcu_head *head)
{
	struct tm_table *table = container_of(head, struct tm_table, rcu);

	__tm_table_free(table);
}

static void tm_table_free(struct tm_table *table)
{
	call_rcu(&table->rcu, tm_table_free_rcu);
}

static bool __tm_table_id_exists(struct list_head *head, u32 id)
{
	struct tm_table *table;

	list_for_each_entry(table, head, list)
		if (table->id == id)
			return true;

	return false;
}

static u32 tm_new_table_id(struct bpf_wildcard *wcard, bool dynamic)
{
	struct list_head *head = &wcard->tables_list_head;
	u32 id;

	do id = get_random_u32();
	while (__tm_table_id_exists(head, id));

	return id;
}

static struct tm_table *tm_new_table(struct bpf_wildcard *wcard,
				     const struct wildcard_key *key,
				     bool circumcision, bool dynamic)
{
	static const u8 zero[BPF_WILDCARD_MAX_RULE_SIZE] = {};
	struct tm_table *table;
	u32 type, size;
	u32 off = 0;
	u32 prefix;
	u32 i;

	/*
	 * struct tm_table | struct tm_mask | u8 prefixes[n_rules]
	 *        \             ^       \           ^
	 *         -------------|        -----------|
	 */
	size = sizeof(*table) + sizeof(struct tm_mask) + wcard->desc->n_rules;

	table = bpf_map_kmalloc_node(&wcard->map, size,
				     GFP_ATOMIC | __GFP_NOWARN,
				     wcard->map.numa_node);
	if (!table)
		return NULL;

	table->id = tm_new_table_id(wcard, dynamic);
	table->mask = (struct tm_mask *)(table + 1);
	atomic_set(&table->n_elements, 0);

	table->mask->n_prefixes = wcard->desc->n_rules;
	for (i = 0; i < wcard->desc->n_rules; i++) {
		type = wcard->desc->rule_desc[i].type;
		size = wcard->desc->rule_desc[i].size;

		switch (type) {
		case BPF_WILDCARD_RULE_PREFIX:
			prefix = *(u32 *)(key->data + off + size);
			table->mask->prefix[i] = prefix;
			if (circumcision)
				table->mask->prefix[i] -= prefix/8;
			off += size + sizeof(u32);
			break;
		case BPF_WILDCARD_RULE_RANGE:
			table->mask->prefix[i] = 0;
			off += 2 * size;
			break;
		case BPF_WILDCARD_RULE_MATCH:
			table->mask->prefix[i] = 0;
			off += size;
			break;
		case BPF_WILDCARD_RULE_WILDCARD_MATCH:
			if (!memcmp(zero, key->data + off, size))
				table->mask->prefix[i] = 0;
			else
				/*
				 * The actual prefix value is not used,
				 * however, set it to proper value
				 */
				table->mask->prefix[i] = size * 8;
			off += size;
			break;
		default:
			BUG();
		}
	}

	return table;
}

static bool tm_table_compatible(const struct bpf_wildcard *wcard,
				const struct tm_table *table,
				const struct wildcard_key *key)
{
	static const u8 zero[BPF_WILDCARD_MAX_RULE_SIZE] = {};
	u32 table_prefix;
	u32 type, size;
	u32 off = 0;
	u32 prefix;
	u32 i;

	for (i = 0; i < wcard->desc->n_rules; i++) {
		type = wcard->desc->rule_desc[i].type;
		size = wcard->desc->rule_desc[i].size;

		switch (type) {
		case BPF_WILDCARD_RULE_PREFIX:
			/*
			 * A table is compatible if its prefix is less than or
			 * equal to the rule prefix. However, in order to
			 * prevent situations when an existing /0 table
			 * attracts all the rules, we require that /0 table
			 * attracts only /0 rules
			 */
			prefix = *(u32 *)(key->data + off + size);
			table_prefix = table->mask->prefix[i];
			if (table_prefix > prefix || (!table_prefix && prefix))
				return false;

			off += size + sizeof(u32);
			break;
		case BPF_WILDCARD_RULE_RANGE:
			/* ignore this case, table is always compatible */
			off += 2 * size;
			break;
		case BPF_WILDCARD_RULE_MATCH:
			/* ignore this case, table is always compatible */
			off += size;
			break;
		case BPF_WILDCARD_RULE_WILDCARD_MATCH:
			/* wildcard rules only match wildcard tables */
			if (!memcmp(zero, key->data + off, size) != !table->mask->prefix[i])
				return false;
			off += size;
			break;
		}
	}
	return true;
}

static struct tm_table *tm_find_table(struct bpf_wildcard *wcard,
					     const struct wildcard_key *key)
{
	struct tm_table *table;

	list_for_each_entry(table, &wcard->tables_list_head, list)
		if (tm_table_compatible(wcard, table, key))
			return table;

	table = tm_new_table(wcard, key, true, true);
	if (!table)
		return ERR_PTR(-ENOMEM);

	list_add_tail_rcu(&table->list, &wcard->tables_list_head);

	return table;
}

static int __tm_update_elem(struct bpf_wildcard *wcard,
			    const struct wildcard_key *key,
			    void *value, u64 map_flags)
{
	struct bpf_map *map = &wcard->map;
	struct tm_bucket *bucket;
	struct tm_table *table;
	struct wcard_elem *l;
	u32 hash;
	int ret;

	l = __tm_lookup(wcard, key, NULL, NULL);
	ret = check_map_update_flags(l, map_flags);
	if (ret)
		return ret;
	if (l) {
		copy_map_value(map, l->key + round_up(map->key_size, 8), value);
		return 0;
	}

	l = wcard_elem_alloc(wcard, key, value, NULL);
	if (IS_ERR(l))
		return PTR_ERR(l);

	table = tm_find_table(wcard, key);
	if (IS_ERR(table)) {
		__wcard_elem_free(l);
		return PTR_ERR(table);
	}

	hash = tm_hash_rule(wcard->desc, table, (void*)l->key);
	bucket = &wcard->buckets[hash & (wcard->n_buckets - 1)];
	l->hash = hash;
	l->table_id = table->id;
	atomic_inc(&table->n_elements);
	atomic_inc(&bucket->n_elements);

	hlist_add_head_rcu(&l->node, &bucket->head);
	return 0;
}

static int __tm_delete_elem(struct bpf_wildcard *wcard,
			    const struct wildcard_key *key)
{
	struct tm_bucket *bucket;
	struct wcard_elem *elem;
	struct tm_table *table;
	int n;

	elem = __tm_lookup(wcard, key, &table, &bucket);
	if (!elem)
		return -ENOENT;

	hlist_del_rcu(&elem->node);
	wcard_elem_free(elem);

	atomic_dec(&bucket->n_elements);
	n = atomic_dec_return(&table->n_elements);
	if (n == 0) {
		list_del_rcu(&table->list);
		tm_table_free(table);
	}

	return 0;
}

static int tm_update_elem(struct bpf_wildcard *wcard,
			  struct wildcard_key *key,
			  void *value, u64 flags)
{
	unsigned long irq_flags;
	int ret;

	if (key->type != BPF_WILDCARD_KEY_RULE)
		return -EINVAL;

	ret = wcard_lock(wcard, &wcard->lock, &irq_flags);
	if (ret)
		return ret;
	patch_key(wcard->desc, key);
	ret = __tm_update_elem(wcard, key, value, flags);
	wcard_unlock(wcard, &wcard->lock, irq_flags);
	return ret;
}

static int tm_delete_elem(struct bpf_wildcard *wcard,
			  struct wildcard_key *key)
{
	unsigned long irq_flags;
	int ret;

	if (!key || key->type != BPF_WILDCARD_KEY_RULE)
		return -EINVAL;

	ret = wcard_lock(wcard, &wcard->lock, &irq_flags);
	if (ret)
		return ret;
	patch_key(wcard->desc, key);
	ret = __tm_delete_elem(wcard, key);
	wcard_unlock(wcard, &wcard->lock, irq_flags);
	return ret;
}

static int tm_get_next_key(struct bpf_wildcard *wcard,
			   struct wildcard_key *key,
			   struct wildcard_key *next_key)
{
	struct tm_bucket *bucket;
	struct hlist_node *node;
	struct wcard_elem *l;
	unsigned int i = 0;

	if (!key)
		goto find_first_elem;

	if (key->type != BPF_WILDCARD_KEY_RULE)
		return -EINVAL;

	patch_key(wcard->desc, key);

	l = __tm_lookup(wcard, key, NULL, &bucket);
	if (!l)
		goto find_first_elem;

	node = rcu_dereference_raw(hlist_next_rcu(&l->node));
	l = hlist_entry_safe(node, struct wcard_elem, node);
	if (l)
		goto copy;

	i = (bucket - wcard->buckets) + 1;

find_first_elem:
	for (; i < wcard->n_buckets; i++) {
		bucket = &wcard->buckets[i];
		node = rcu_dereference_raw(hlist_first_rcu(&bucket->head));
		l = hlist_entry_safe(node, struct wcard_elem, node);
		if (l)
			goto copy;
	}
	return -ENOENT;

copy:
	memcpy(next_key, l->key, wcard->map.key_size);
	patch_key(wcard->desc, next_key);
	return 0;
}

static void tm_free_bucket(struct tm_bucket *bucket)
{
	struct hlist_node *n;
	struct wcard_elem *l;

	hlist_for_each_entry_safe(l, n, &bucket->head, node) {
		hlist_del(&l->node);
		__wcard_elem_free(l);
	}
}

static void *wildcard_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);
	struct wcard_elem *l;

	switch (((struct wildcard_key *)key)->type) {
	case BPF_WILDCARD_KEY_MATCH:
		l = tm_match(wcard, key);
		break;
	case BPF_WILDCARD_KEY_RULE:
		l = tm_lookup(wcard, key);
		break;
	default:
		return NULL;
	}
	if (l)
		return l->key + round_up(wcard->map.key_size, 8);
	return NULL;
}

static int wildcard_map_update_elem(struct bpf_map *map, void *key,
				    void *value, u64 map_flags)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);

	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST))
		/* unknown flags */
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());

	return tm_update_elem(wcard, key, value, map_flags);
}

static int wildcard_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);

	return tm_delete_elem(wcard, key);
}

static int wildcard_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);

	return tm_get_next_key(wcard, key, next_key);
}

static void wildcard_map_free(struct bpf_map *map)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);
	struct tm_table *table, *n;
	unsigned int i;

	for (i = 0; i < wcard->n_buckets; i++)
		tm_free_bucket(&wcard->buckets[i]);
	bpf_map_area_free(wcard->buckets);

	list_for_each_entry_safe(table, n, &wcard->tables_list_head, list)
		__tm_table_free(table);

	lockdep_unregister_key(&wcard->lockdep_key);
	bpf_map_area_free(wcard->desc);
	bpf_map_area_free(wcard);
}

static int wildcard_map_alloc_check(union bpf_attr *attr)
{
	bool prealloc;

	if (!bpf_capable())
		return -EPERM;

	if (attr->map_flags & ~WILDCARD_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return -EINVAL;

	/* not implemented, yet, sorry */
	prealloc = !(attr->map_flags & BPF_F_NO_PREALLOC);
	if (prealloc)
		return -ENOTSUPP;

	if (attr->max_entries == 0 || attr->key_size == 0 ||
	    attr->value_size == 0)
		return -EINVAL;

	if ((u64)attr->key_size + attr->value_size >= KMALLOC_MAX_SIZE -
	   sizeof(struct wcard_elem))
		/* if key_size + value_size is bigger, the user space won't be
		 * able to access the elements via bpf syscall. This check
		 * also makes sure that the elem_size doesn't overflow and it's
		 * kmalloc-able later in wildcard_map_update_elem()
		 */
		return -E2BIG;

	if (!attr->btf_key_type_id || !attr->btf_value_type_id)
		return -EINVAL;

	return 0;
}

static struct bpf_map *wildcard_map_alloc(union bpf_attr *attr)
{
	struct bpf_wildcard *wcard;
	struct wildcard_desc *desc;
	unsigned int i;
	int err;

	wcard = bpf_map_area_alloc(sizeof(*wcard), NUMA_NO_NODE);
	if (!wcard)
		return ERR_PTR(-ENOMEM);

	lockdep_register_key(&wcard->lockdep_key);

	bpf_map_init_from_attr(&wcard->map, attr);

	desc = wildcard_desc_from_btf(attr->btf_fd, attr->btf_key_type_id);
	if (IS_ERR(desc)) {
		err = PTR_ERR(desc);
		goto free_wcard;
	}
	wcard->desc = desc;

	wcard->prealloc = !(wcard->map.map_flags & BPF_F_NO_PREALLOC);

	wcard->elem_size = sizeof(struct wcard_elem) +
			  round_up(wcard->map.key_size, 8) +
			  round_up(wcard->map.value_size, 8);
	wcard->n_buckets = roundup_pow_of_two(wcard->map.max_entries);
	wcard->buckets = bpf_map_area_alloc(wcard->n_buckets *
					   sizeof(struct tm_bucket),
					   wcard->map.numa_node);
	if (!wcard->buckets) {
		err = -ENOMEM;
		goto free_desc;
	}

	for (i = 0; i < wcard->n_buckets; i++) {
		INIT_HLIST_HEAD(&wcard->buckets[i].head);
		atomic_set(&wcard->buckets[i].n_elements, 0);
	}

	INIT_LIST_HEAD(&wcard->tables_list_head);
	wcard_init_lock(wcard, &wcard->lock);

	return &wcard->map;

free_desc:
	bpf_map_area_free(wcard->desc);
free_wcard:
	lockdep_unregister_key(&wcard->lockdep_key);
	bpf_map_area_free(wcard);
	return ERR_PTR(err);
}

static u64 wildcard_map_mem_usage(const struct bpf_map *map)
{
	struct bpf_wildcard *wcard =
		container_of(map, struct bpf_wildcard, map);
	struct wildcard_desc *desc = wcard->desc;
	u64 usage = sizeof(struct bpf_wildcard);
	struct tm_table *table;
	u64 tables = 0;

	usage += sizeof(*desc) + desc->n_rules * sizeof(desc->rule_desc[0]);
	usage += wcard->n_buckets * sizeof(struct tm_bucket);
	list_for_each_entry_rcu(table, &wcard->tables_list_head, list)
		tables += 1;
	usage += tables * (sizeof(struct tm_table) +
			   sizeof(struct tm_mask) +
			   desc->n_rules);
	usage += wcard->elem_size * wcard->count;
	return usage;
}

BTF_ID_LIST_SINGLE(bpf_wildcard_map_btf_ids, struct, bpf_wildcard)
const struct bpf_map_ops wildcard_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = wildcard_map_alloc_check,
	.map_alloc = wildcard_map_alloc,
	.map_free = wildcard_map_free,
	.map_lookup_elem = wildcard_map_lookup_elem,
	.map_update_elem = wildcard_map_update_elem,
	.map_delete_elem = wildcard_map_delete_elem,
	.map_get_next_key = wildcard_map_get_next_key,
	.map_mem_usage = wildcard_map_mem_usage,
	.map_btf_id = &bpf_wildcard_map_btf_ids[0],
};
