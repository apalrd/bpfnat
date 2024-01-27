// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 Andrew Palardy */
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "nat64.skel.h"
#include <bpf/bpf.h>

#define CLAT_IFINDEX 3

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = CLAT_IFINDEX,
			    .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	bool hook_created = false;
	struct nat64_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	/* NAT64 Prefix + local address in one */
	uint32_t ipv6_prefix[4] = {
		htonl(0x0064ff9b),
		htonl(0x0),
		htonl(0x0),
		htonl(0xC0000004),
	};
	/* Local address */
	uint32_t ipv6_addr[4] = {
		htonl(0x2601040e),
		htonl(0x8102ccc0),
		htonl(0x0),
		htonl(0x6464),
	};

	skel = nat64_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_nat);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	/* Write memory */
	int i = 0;
	if(bpf_map_update_elem(bpf_map__fd(skel->maps.addrs),&i,&ipv6_addr,BPF_ANY))
	{
		fprintf(stderr,"Can't write local address to bpf: %s\n",strerror(errno));
		goto cleanup;
	}
	i = 1;
	if(bpf_map_update_elem(bpf_map__fd(skel->maps.addrs),&i,&ipv6_prefix,BPF_ANY))
	{
		fprintf(stderr,"Can't write local address to bpf: %s\n",strerror(errno));
		goto cleanup;
	}


	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	nat64_bpf__destroy(skel);
	return -err;
}
