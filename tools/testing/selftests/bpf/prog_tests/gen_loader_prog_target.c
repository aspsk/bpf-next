// SPDX-License-Identifier: GPL-2.0

#include <bpf/btf.h>
#include <test_progs.h>
#include "bpf/skel_internal.h"

#include "gen_loader_prog_target.skel.h"
#include "test_pkt_access.skel.h"

#define PIN_PATH "/sys/fs/bpf/gen_loader_prog_target"

static char log_buf[64 * 1024];

/*
 * Open the skeleton with only one program to be loaded, which is attached
 * to tgt_name inside the program pinned at tgt_path, which has the tgt_btf.
 */
static struct gen_loader_prog_target *open_skel(const char *prog_name, const char *tgt_path,
						const struct btf *tgt_btf,
						const char *tgt_name)
{
	struct gen_loader_prog_target *skel;
	struct bpf_program *prog;
	int err;

	skel = gen_loader_prog_target__open();
	if (!ASSERT_OK_PTR(skel, "gen_loader_prog_target__open"))
		return NULL;

	bpf_object__for_each_program(prog, skel->obj) {
		bool load = !strcmp(bpf_program__name(prog), prog_name);

		bpf_program__set_autoload(prog, load);
		if (!load)
			continue;

		err = bpf_program__set_attach_target_path(prog, tgt_path, tgt_btf, tgt_name);
		if (!ASSERT_OK(err, "bpf_program__set_attach_target_path")) {
			gen_loader_prog_target__destroy(skel);
			return NULL;
		}
	}

	return skel;
}

static int prog_info(int prog_fd, struct bpf_prog_info *info)
{
	__u32 len = sizeof(*info);

	memset(info, 0, len);
	return bpf_prog_get_info_by_fd(prog_fd, info, &len);
}

/* Run the loader. It loads only one program, which has the first descriptor. */
static int run_loader(struct gen_loader_opts *gen_opts, int nr_maps, int nr_progs, int *prog_fd)
{
	struct bpf_load_and_run_opts opts = {};
	struct bpf_prog_desc *prog_desc;
	struct bpf_loader_ctx *ctx;
	__u32 ctx_sz;
	int err;

	*prog_fd = -1;
	ctx_sz = sizeof(*ctx) + nr_maps * sizeof(struct bpf_map_desc) +
		 nr_progs * sizeof(struct bpf_prog_desc);
	ctx = calloc(1, ctx_sz);
	if (!ASSERT_OK_PTR(ctx, "calloc"))
		return -ENOMEM;

	ctx->sz = ctx_sz;
	ctx->log_level = 1;
	ctx->log_size = sizeof(log_buf);
	ctx->log_buf = ptr_to_u64(log_buf);
	log_buf[0] = '\0';

	prog_desc = (void *)ctx + sizeof(*ctx) + nr_maps * sizeof(struct bpf_map_desc);

	opts.ctx = ctx;
	opts.data = gen_opts->data;
	opts.data_sz = gen_opts->data_sz;
	opts.insns = gen_opts->insns;
	opts.insns_sz = gen_opts->insns_sz;

	err = bpf_load_and_run(&opts);
	*prog_fd = prog_desc[0].prog_fd;

	free(ctx);
	return err;
}

/*
 * Load a program which attaches to another BPF program, set by its pin path
 * and its BTF, first directly by libbpf, then by a loader generated from the
 * same object. The loader opens the target by itself, and must load the
 * program attached to the same target, or fail if nothing is pinned at the
 * path.
 */
static void __check_prog_target(const char *prog_name, const char *tgt_name)
{
	LIBBPF_OPTS(gen_loader_opts, gen_opts);
	struct bpf_prog_info tgt_info, info;
	struct gen_loader_prog_target *skel;
	int nr_maps = 0, nr_progs = 0;
	struct test_pkt_access *tgt_skel;
	int tgt_fd, prog_fd, err;
	const struct btf *tgt_btf;
	struct bpf_program *prog;
	struct bpf_map *map;
	int attach_btf_id;

	tgt_skel = test_pkt_access__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "test_pkt_access__open_and_load"))
		return;

	tgt_fd = bpf_program__fd(tgt_skel->progs.test_pkt_access);
	if (!ASSERT_OK(prog_info(tgt_fd, &tgt_info), "prog_info(tgt_fd)"))
		goto cleanup;

	tgt_btf = bpf_object__btf(tgt_skel->obj);
	attach_btf_id = btf__find_by_name_kind(tgt_btf, tgt_name, BTF_KIND_FUNC);
	if (!ASSERT_GT(attach_btf_id, 0, "btf__find_by_name_kind"))
		goto cleanup;

	unlink(PIN_PATH);
	if (!ASSERT_OK(bpf_obj_pin(tgt_fd, PIN_PATH), "bpf_obj_pin"))
		goto cleanup;

	skel = open_skel(prog_name, PIN_PATH, tgt_btf, tgt_name);
	if (!skel)
		goto cleanup_pin;

	err = gen_loader_prog_target__load(skel);
	if (ASSERT_OK(err, "gen_loader_prog_target__load")) {
		prog = bpf_object__find_program_by_name(skel->obj, prog_name);
		err = prog_info(bpf_program__fd(prog), &info);
		if (ASSERT_OK(err, "prog_info(direct)")) {
			ASSERT_EQ(info.attach_btf_obj_id, tgt_info.btf_id, "attach_btf_obj_id");
			ASSERT_EQ(info.attach_btf_id, attach_btf_id, "attach_btf_id");
		}
	}
	gen_loader_prog_target__destroy(skel);
	if (err)
		goto cleanup_pin;

	skel = open_skel(prog_name, PIN_PATH, tgt_btf, tgt_name);
	if (!skel)
		goto cleanup_pin;

	if (!ASSERT_OK(bpf_object__gen_loader(skel->obj, &gen_opts), "bpf_object__gen_loader"))
		goto cleanup_skel;

	if (!ASSERT_OK(bpf_object__load(skel->obj), "bpf_object__load"))
		goto cleanup_skel;

	bpf_object__for_each_program(prog, skel->obj)
		nr_progs++;
	bpf_object__for_each_map(map, skel->obj)
		nr_maps++;

	err = run_loader(&gen_opts, nr_maps, nr_progs, &prog_fd);
	if (!ASSERT_OK(err, "run_loader(pinned)")) {
		printf("%s: loader log:\n%s\n", __func__, log_buf);
		goto cleanup_skel;
	}
	if (ASSERT_GT(prog_fd, 0, "prog_fd(pinned)")) {
		if (ASSERT_OK(prog_info(prog_fd, &info), "prog_info(loader)")) {
			ASSERT_EQ(info.attach_btf_obj_id, tgt_info.btf_id, "attach_btf_obj_id");
			ASSERT_EQ(info.attach_btf_id, attach_btf_id, "attach_btf_id");
		}
		close(prog_fd);
	}

	unlink(PIN_PATH);
	err = run_loader(&gen_opts, nr_maps, nr_progs, &prog_fd);
	ASSERT_EQ(err, -ENOENT, "run_loader(not pinned)");
	ASSERT_LE(prog_fd, 0, "prog_fd(not pinned)");
	if (prog_fd > 0)
		close(prog_fd);

cleanup_skel:
	gen_loader_prog_target__destroy(skel);
cleanup_pin:
	unlink(PIN_PATH);
cleanup:
	test_pkt_access__destroy(tgt_skel);
}

static void check_freplace(void)
{
	__check_prog_target("gen_loader_freplace", "get_constant");
}

static void check_fentry(void)
{
	__check_prog_target("gen_loader_fentry", "test_pkt_access");
}

static void check_fexit(void)
{
	__check_prog_target("gen_loader_fexit", "test_pkt_access");
}

/*
 * Load the fentry program attached to the target, either cloned from a
 * prepared object with the target set by path, or with the path replaced
 * by the fd of the target, in which case nothing is pinned at the path.
 */
static void __check_target_set(bool clone)
{
	struct bpf_prog_info tgt_info, info;
	struct gen_loader_prog_target *skel;
	struct test_pkt_access *tgt_skel;
	int tgt_fd, prog_fd = -1, err;
	const struct btf *tgt_btf;
	int attach_btf_id;

	tgt_skel = test_pkt_access__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "test_pkt_access__open_and_load"))
		return;

	tgt_fd = bpf_program__fd(tgt_skel->progs.test_pkt_access);
	if (!ASSERT_OK(prog_info(tgt_fd, &tgt_info), "prog_info(tgt_fd)"))
		goto cleanup;

	tgt_btf = bpf_object__btf(tgt_skel->obj);
	attach_btf_id = btf__find_by_name_kind(tgt_btf, "test_pkt_access", BTF_KIND_FUNC);
	if (!ASSERT_GT(attach_btf_id, 0, "btf__find_by_name_kind"))
		goto cleanup;

	unlink(PIN_PATH);
	if (clone && !ASSERT_OK(bpf_obj_pin(tgt_fd, PIN_PATH), "bpf_obj_pin"))
		goto cleanup;

	skel = open_skel("gen_loader_fentry", PIN_PATH, tgt_btf, "test_pkt_access");
	if (!skel)
		goto cleanup_pin;

	if (clone) {
		err = bpf_object__prepare(skel->obj);
		if (!ASSERT_OK(err, "bpf_object__prepare"))
			goto cleanup_skel;
		prog_fd = bpf_program__clone(skel->progs.gen_loader_fentry, NULL);
	} else {
		err = bpf_program__set_attach_target(skel->progs.gen_loader_fentry, tgt_fd, NULL);
		if (!ASSERT_OK(err, "bpf_program__set_attach_target"))
			goto cleanup_skel;
		if (ASSERT_OK(gen_loader_prog_target__load(skel), "gen_loader_prog_target__load"))
			prog_fd = dup(bpf_program__fd(skel->progs.gen_loader_fentry));
	}

	if (ASSERT_GE(prog_fd, 0, "prog_fd")) {
		if (ASSERT_OK(prog_info(prog_fd, &info), "prog_info")) {
			ASSERT_EQ(info.attach_btf_obj_id, tgt_info.btf_id, "attach_btf_obj_id");
			ASSERT_EQ(info.attach_btf_id, attach_btf_id, "attach_btf_id");
		}
		close(prog_fd);
	}

cleanup_skel:
	gen_loader_prog_target__destroy(skel);
cleanup_pin:
	unlink(PIN_PATH);
cleanup:
	test_pkt_access__destroy(tgt_skel);
}

static void check_clone(void)
{
	__check_target_set(true);
}

static void check_override(void)
{
	__check_target_set(false);
}

void test_gen_loader_prog_target(void)
{
	if (test__start_subtest("freplace"))
		check_freplace();
	if (test__start_subtest("fentry"))
		check_fentry();
	if (test__start_subtest("fexit"))
		check_fexit();
	if (test__start_subtest("clone"))
		check_clone();
	if (test__start_subtest("override"))
		check_override();
}
