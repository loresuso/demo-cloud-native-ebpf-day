#include "utils.c"
#include "common.h"
#include "kprobe_commit_creds.skel.h"

int main(int argc, char **argv)
{
    struct kprobe_commit_creds_bpf *skel;
    struct commit_creds_event *event;
    int err;

    libbpf_set_print(libbpf_print_fn);

    bump_memlock_rlimit();

    if (signal(SIGINT, sig_int) == SIG_ERR || signal(SIGTERM, sig_int) == SIG_ERR)
    {
        fprintf(stderr, "Can't handle Ctrl-C: %s\n", strerror(errno));
        goto cleanup;
    }

    skel = kprobe_commit_creds_bpf__open_and_load();
    if(!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    fprintf(stdout, "BPF skeleton ok\n");

    err = kprobe_commit_creds_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    err = bpf_trace_pipe(STDERR_FILENO);

cleanup:
    kprobe_commit_creds_bpf__destroy(skel);
    return -err;
}