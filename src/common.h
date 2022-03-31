#define MAX_FILENAME 128
#define MAX_COMM 32

#define OVERLAYFS_SUPER_MAGIC 0x794c7630

enum event_type 
{
    SECURITY_FILE_OPEN,
    SECURITY_FILE_MPROTECT,
};

struct header 
{
    enum event_type type;
    int pid;
    char comm[MAX_COMM];
};

struct security_file_open_event 
{
    struct header hdr;
    char path[MAX_FILENAME];
    uint32_t flags;
    uint32_t mode;
    bool is_overlay;
};

struct security_file_mprotect_event
{
    struct header hdr;
    uint64_t addr;
    uint32_t len;
    uint32_t prot;
};
