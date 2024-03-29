//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct config {
	u32 netns;
	u8 block;
	u8 _pads[3];
};

static volatile const struct config CONFIG = {};

struct exec_event {
	u32 pid;
	unsigned char args[16][16];
};

#define MAX_QUEUE_ENTRIES 10000
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct exec_event);
	__uint(max_entries, MAX_QUEUE_ENTRIES);
} exec_events SEC(".maps");

struct nf_log_event {
	unsigned char buf[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct nf_log_event);
	__uint(max_entries, MAX_QUEUE_ENTRIES);
} nf_log_events SEC(".maps");

inline int _memcmp(char *a, char *b, int len)
{
	for (int i=0; i<len; i++) {
		if (a[i] != b[i])
			return 1;
	}
	return 0;
}

SEC("kprobe/sys_execve")
int sys_execve(struct pt_regs *ctx)
{
	struct pt_regs *__ctx = (struct pt_regs *)ctx->di;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct ns_common ns = {};
	BPF_CORE_READ_INTO(&ns, task, nsproxy, net_ns, ns);
	if (ns.inum != CONFIG.netns)
		return 0;

	struct exec_event e = {};
	e.pid = bpf_get_current_pid_tgid() >> 32;

	char **argv = (char **)BPF_CORE_READ(__ctx, si);
	char *argi;
	for (int i=0; i<10; i++) {
		bpf_probe_read_user(&argi, sizeof(argi), &argv[i]);
		bpf_probe_read_user_str(e.args[i], sizeof(e.args[i]), argi);
	}

	if (_memcmp((char *)e.args[0], "iptables", 8)
	    && _memcmp((char *)e.args[0], "ip6tables", 9))
		return 0;

	if (CONFIG.block)
		bpf_override_return(ctx, -1);

	bpf_map_push_elem(&exec_events, &e, BPF_EXIST);
	return 0;
}

SEC("kprobe/nf_log_buf_close")
int nf_log_buf_close(struct pt_regs *ctx)
{
	struct nf_log_buf *m = (struct nf_log_buf *)ctx->di;
	struct nf_log_event e = {};
	BPF_CORE_READ_STR_INTO(&e.buf, m, buf);
	bpf_map_push_elem(&nf_log_events, &e, BPF_EXIST);
	return 0;
}
