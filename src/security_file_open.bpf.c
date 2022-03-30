#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
#include "printk.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

static inline void fill_event_header(struct header *hdr, enum event_type type)
{
    hdr->type = type;
    hdr->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&hdr->comm, MAX_COMM);
}


SEC("lsm/file_open")
int BPF_PROG(handle_security_file_open, struct file *file)
{
    struct security_file_open_event *event;
    struct path path;

    event = bpf_ringbuf_reserve(&rb, sizeof(struct security_file_open_event), 0);
    if(!event)
    {
        bpf_printk("cannot reserve space in the ring buffer");
        return 0;
    }

    fill_event_header(&event->hdr, SECURITY_FILE_OPEN);

    bpf_d_path(&file->f_path, event->path, MAX_FILENAME);
    bpf_core_read(&event->flags, sizeof(file->f_flags), (void *)&file->f_flags);
    bpf_core_read(&event->flags, sizeof(file->f_mode), (void *)&file->f_mode);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(handle_security_file_mprotect, struct vm_area_struct *vma, 
                unsigned long reqprot,
			    unsigned long prot)
{
    struct security_file_mprotect_event *event;

    event = bpf_ringbuf_reserve(&rb, sizeof(struct security_file_mprotect_event), 0);
    if(!event)
    {
        bpf_printk("cannot reserve space in the ring buffer");
        return 0;
    }

    fill_event_header(&event->hdr, SECURITY_FILE_MPROTECT);

    event->addr = vma->vm_start;
    event->len = vma->vm_end - vma->vm_start;
    event->prot = reqprot;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

/*
SEC("lsm/bprm_check")

SEC("lsm/inode_unlink")

SEC("lsm/mmap_addr")
*/