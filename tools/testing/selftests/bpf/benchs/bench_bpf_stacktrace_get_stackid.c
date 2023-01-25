// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Isovalent */

#include <sys/random.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <argp.h>
#include "bench.h"
#include "bpf_stacktrace_get_stackid.skel.h"
#include "bpf_util.h"

/* BPF triggering benchmarks */
static struct ctx {
	struct bpf_stacktrace_get_stackid *skel;
} ctx;

/* only available to kernel, so define it here */
#define BPF_MAX_LOOPS (1<<23)

#define MAX_KEY_SIZE 512 /* the size of the key map */

static struct {
	__u32 map_flags;
	__u32 nr_loops;	
} args = {
	.map_flags = 0,
	.nr_loops = 100000,
};

static const struct argp_option opts[] = {
	{ "map_flags", ARG_MAP_FLAGS, "MAP_FLAGS", 0,
	  "The stackmap flags passed to BPF_MAP_CREATE"},
	{ "nr_loops", ARG_NR_LOOPS, "NR_LOOPS", 0,
	  "The number of loops for the benchmark"},
	{},
};

static int map_fd = -1;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long ret;

	switch (key) {
	case ARG_MAP_FLAGS:
		if (!strncasecmp(arg, "0x", 2)) {
			ret = strtol(arg, NULL, 0x10);
		} else {
			ret = strtol(arg, NULL, 10);
		}
		if (ret < 0 || ret > UINT_MAX) {
			fprintf(stderr, "invalid map_flags");
			argp_usage(state);
		}
		args.map_flags = ret;
		break;
	case ARG_NR_LOOPS:
		ret = strtol(arg, NULL, 10);
		if (ret < 1 || ret > BPF_MAX_LOOPS) {
			fprintf(stderr, "invalid nr_loops: %ld (min=1 max=%u)\n",
				ret, BPF_MAX_LOOPS);
			argp_usage(state);
		}
		args.nr_loops = ret;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_stackmap_get_stackid_argp = {
	.options = opts,
	.parser = parse_arg,
};

static void validate(void)
{
	if (env.consumer_cnt != 1) {
		fprintf(stderr, "benchmark doesn't support multi-consumer!\n");
		exit(1);
	}
}

static void *producer(void *input)
{
	int fd;

	while (true) {
		fd = open("/dev/null", O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "open: /dev/null: %s", strerror(errno));
			exit(1);
		}
		if (close(fd) < 0) {
			fprintf(stderr, "close: %s", strerror(errno));
			exit(1);
		}
	}
	return NULL;
}

static void *consumer(void *input)
{
	return NULL;
}

static void measure(struct bench_res *res)
{
}

static void setup(void)
{
	struct bpf_link *link;
	int ret;

	setup_libbpf();

	ctx.skel = bpf_stacktrace_get_stackid__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	//bpf_map__set_map_flags(ctx.skel->maps.stack_trace_map_bench, args.map_flags);

	ret = bpf_stacktrace_get_stackid__load(ctx.skel);
	if (ret) {
		bpf_stacktrace_get_stackid__destroy(ctx.skel);
		fprintf(stderr, "failed to load map: %s", strerror(-ret));
		exit(1);
	}

	ctx.skel->bss->nr_loops = args.nr_loops;

	map_fd = bpf_map__fd(ctx.skel->maps.stack_trace_map_bench);					\

	link = bpf_program__attach(ctx.skel->progs.benchmark);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

static inline double events_from_time(u64 time)
{
	if (time)
		return args.nr_loops * 1000000000llu / time / 1000000.0L;

	return 0;
}

static int compute_events(u64 *times, double *events_mean, double *events_stddev, u64 *mean_time)
{
	int i, n = 0;

	*events_mean = 0;
	*events_stddev = 0;
	*mean_time = 0;

	for (i = 0; i < 128; i++) {
		if (!times[i])
			break;
		*mean_time += times[i];
		*events_mean += events_from_time(times[i]);
		n += 1;
	}
	if (!n)
		return 0;

	*mean_time /= n;
	*events_mean /= n;

	if (n > 1) {
		for (i = 0; i < n; i++) {
			double events_i = *events_mean - events_from_time(times[i]);
			*events_stddev += events_i * events_i / (n - 1);
		}
		*events_stddev = sqrt(*events_stddev);
	}

	return n;
}

static int print_stats()
{
	struct bpf_map_info info = {};
        __u32 len = sizeof(info);
	int ret = 0;

	ret = bpf_obj_get_info_by_fd(map_fd, &info, &len);
	if (ret < 0) {
		fprintf(stderr, "bpf_obj_get_info_by_fd\n");
		exit(1);
	}

	if (info.stats_lookup_ok) {
		ret = info.stats_lookup_ok_time/info.stats_lookup_ok;
		fprintf(stderr, "__get_stackid: %d\n", ret);
	} else {
		fprintf(stderr, "__get_stackid: dunno\n");
	}

	if (info.stats_lookup_fail) {
		ret = info.stats_lookup_fail_time/info.stats_lookup_fail;
		fprintf(stderr, "total: %d [time=%llu failed lookups=%llu]\n", ret, info.stats_lookup_fail_time, info.stats_lookup_fail);
	}

	if (info.stats_update) {
		ret = info.stats_update_time/info.stats_update;
		fprintf(stderr, "get_perf_callchain: %d [time=%llu failed lookups=%llu]\n", ret, info.stats_update_time, info.stats_update);
	}

	return ret;
}

static void report_final(struct bench_res res[], int res_cnt)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	double events_mean, events_stddev;
	u64 mean_time;
	int i, n;

	for (i = 0; i < nr_cpus; i++) {
		n = compute_events(ctx.skel->bss->percpu_times[i], &events_mean, &events_stddev, &mean_time);
		if (n == 0)
			continue;

		printf("cpu%02d: get_stackid %.3lfM ± %.3lfM events per sec (approximated from %d samples of ~%lums)\n",
		       i, events_mean, 2*events_stddev, n, mean_time / 1000000);
	}

	print_stats();
}

const struct bench bench_bpf_stacktrace_get_stackid = {
	.name = "bpf-stacktrace-get-stackid",
	.validate = validate,
	.setup = setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = NULL,
	.report_final = report_final,
};
