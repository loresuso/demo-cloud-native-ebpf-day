#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
#include "printk.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

/* int commit_creds(struct cred *); */
SEC("kprobe/commit_creds")
int BPF_KPROBE(handle_commit_creds, struct creds *new)
{
    struct commit_creds_event *event;
    struct creds *old;
    
    event = bpf_ringbuf_reserve(&rb, sizeof(struct commit_creds_event), 0);
    if(!event)
    {
        bpf_printk("cannot reserve space in the ring buffer");
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    = bpf_core_read(task->cred, )

    return 0;
}