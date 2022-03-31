#include "utils.c"
#include "common.h"
#include "security_file_open.skel.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>

void handle_file_open(struct security_file_open_event *event);
void handle_file_mprotect(struct security_file_mprotect_event *event);

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct header *hdr = data;
    if(!strcmp("id", hdr->comm))
    {
        
        switch(hdr->type)
        {
        case SECURITY_FILE_OPEN:
            handle_file_open((struct security_file_open_event *)data);
            break;
        case SECURITY_FILE_MPROTECT:
            handle_file_mprotect((struct security_file_mprotect_event *)data);
            break;
        default:
            break;
        }
    }
	return 0;
}

void handle_file_open(struct security_file_open_event *e){
    printf("filename: %s, mode: %x, flags: %x\n, is_overlay: %s\n", 
        e->path, e->mode, e->flags, e->is_overlay ? "true" : "false");
}

void handle_file_mprotect(struct security_file_mprotect_event *e)
{
    printf("addr: %lx, len: %x, prot: %x\n", e->addr, e->len, e->prot);
}


int main(int argc, char **argv)
{
    struct security_file_open_bpf *skel;
    struct ring_buffer *rb;
    int err;

    libbpf_set_print(libbpf_print_fn);

    bump_memlock_rlimit();

    if (signal(SIGINT, sig_int) == SIG_ERR || signal(SIGTERM, sig_int) == SIG_ERR)
    {
        fprintf(stderr, "Can't handle Ctrl-C: %s\n", strerror(errno));
        goto cleanup;
    }

    skel = security_file_open_bpf__open_and_load();
    if(!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    fprintf(stdout, "BPF skeleton ok\n");

    err = security_file_open_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

    while (!stop) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
    ring_buffer__free(rb);
    security_file_open_bpf__destroy(skel);
    return -err;
}