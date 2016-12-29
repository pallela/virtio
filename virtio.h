
#ifndef VIRTIO_H
#define VIRTIO_H

#include<stdint.h>

enum vhost_user_request {
        VHOST_USER_NONE = 0,
        VHOST_USER_GET_FEATURES = 1,
        VHOST_USER_SET_FEATURES = 2,
        VHOST_USER_SET_OWNER = 3,
        VHOST_USER_RESET_OWNER = 4,
        VHOST_USER_SET_MEM_TABLE = 5,
        VHOST_USER_SET_LOG_BASE = 6,
        VHOST_USER_SET_LOG_FD = 7,
        VHOST_USER_SET_VRING_NUM = 8,
        VHOST_USER_SET_VRING_ADDR = 9,
        VHOST_USER_SET_VRING_BASE = 10,
        VHOST_USER_GET_VRING_BASE = 11,
        VHOST_USER_SET_VRING_KICK = 12,
        VHOST_USER_SET_VRING_CALL = 13,
        VHOST_USER_SET_VRING_ERR = 14,
        VHOST_USER_GET_PROTOCOL_FEATURES = 15,
        VHOST_USER_SET_PROTOCOL_FEATURES = 16,
        VHOST_USER_GET_QUEUE_NUM = 17,
        VHOST_USER_SET_VRING_ENABLE = 18,
        VHOST_USER_MAX
};

char req_names[][50] = {
        "VHOST_USER_NONE",
        "VHOST_USER_GET_FEATURES",
        "VHOST_USER_SET_FEATURES",
        "VHOST_USER_SET_OWNER",
        "VHOST_USER_RESET_OWNER",
        "VHOST_USER_SET_MEM_TABLE",
        "VHOST_USER_SET_LOG_BASE",
        "VHOST_USER_SET_LOG_FD",
        "VHOST_USER_SET_VRING_NUM",
        "VHOST_USER_SET_VRING_ADDR",
        "VHOST_USER_SET_VRING_BASE",
        "VHOST_USER_GET_VRING_BASE",
        "VHOST_USER_SET_VRING_KICK",
        "VHOST_USER_SET_VRING_CALL",
        "VHOST_USER_SET_VRING_ERR",
        "VHOST_USER_GET_PROTOCOL_FEATURES",
        "VHOST_USER_SET_PROTOCOL_FEATURES",
        "VHOST_USER_GET_QUEUE_NUM",
        "VHOST_USER_SET_VRING_ENABLE",
        "VHOST_USER_MAX"
};



#define VHOST_MEMORY_MAX_NREGIONS 8

struct vhost_vring_state {
        unsigned int index;
        unsigned int num;
};

struct vhost_vring_file {
        unsigned int index;
        int fd;
};

struct vhost_vring_addr {
        unsigned int index;
        /* Option flags. */
        unsigned int flags;
        /* Flag values: */
        /* Whether log address is valid. If set enables logging. */
#define VHOST_VRING_F_LOG 0

        /* Start of array of descriptors (virtually contiguous) */
        uint64_t desc_user_addr;
        /* Used structure address. Must be 32 bit aligned */
        uint64_t used_user_addr;
        /* Available structure address. Must be 16 bit aligned */
        uint64_t avail_user_addr;
        /* Logging support. */
        /* Log writes to used structure, at offset calculated from specified
         * address. Address must be 32 bit aligned.
         */
        uint64_t log_guest_addr;
};


struct vhost_memory_region {
        uint64_t guest_phys_addr;
        uint64_t memory_size; /* bytes */
        uint64_t userspace_addr;
        uint64_t mmap_offset;
};

struct vhost_memory {
        uint32_t nregions;
        uint32_t padding;
        struct vhost_memory_region regions[VHOST_MEMORY_MAX_NREGIONS];
};


struct vhost_user_msg {
        enum vhost_user_request request;

#define VHOST_USER_VERSION_MASK     0x3
#define VHOST_USER_REPLY_MASK       (0x1 << 2)
        uint32_t flags;
        uint32_t size; /* the following payload size */
        union {
#define VHOST_USER_VRING_IDX_MASK   0xff
#define VHOST_USER_VRING_NOFD_MASK  (0x1 << 8)
                uint64_t u64;
                struct vhost_vring_state state;
                struct vhost_vring_addr addr;
                struct vhost_memory memory;
        } payload;
        int fds[VHOST_MEMORY_MAX_NREGIONS];
} __attribute((packed));


#endif

