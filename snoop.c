//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "builtins.h"

struct config_t {
	u32 netns;
};

static volatile const struct config_t CONFIG = {};

struct exec_ctx {
	u8 pad[16];

	unsigned char *filename;
	unsigned char **argv;
	unsigned char **envp;
};

struct event_t {
	u32 pid;
	unsigned char filename[32];
};

#define MAX_QUEUE_ENTRIES 10000
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct event_t);
	__uint(max_entries, MAX_QUEUE_ENTRIES);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct exec_ctx *ctx) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct ns_common ns = {};
	BPF_CORE_READ_INTO(&ns, task, nsproxy, net_ns, ns);
	if (ns.inum != CONFIG.netns)
		return 0;

	struct event_t event = {};
	event.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)ctx->filename);

	bpf_map_push_elem(&events, &event, BPF_EXIST);
	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
