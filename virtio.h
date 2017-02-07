
#ifndef VIRTIO_H
#define VIRTIO_H

#include<stdint.h>
#include<errno.h>

#define VHOST_USER_VERSION    0x1

/* The feature bitmap for virtio net */
#define VIRTIO_NET_F_CSUM       0       /* Host handles pkts w/ partial csum */
#define VIRTIO_NET_F_GUEST_CSUM 1       /* Guest handles pkts w/ partial csum */
#define VIRTIO_NET_F_MAC        5       /* Host has given MAC address. */
#define VIRTIO_NET_F_GUEST_TSO4 7       /* Guest can handle TSOv4 in. */
#define VIRTIO_NET_F_GUEST_TSO6 8       /* Guest can handle TSOv6 in. */
#define VIRTIO_NET_F_GUEST_ECN  9       /* Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_GUEST_UFO  10      /* Guest can handle UFO in. */
#define VIRTIO_NET_F_HOST_TSO4  11      /* Host can handle TSOv4 in. */
#define VIRTIO_NET_F_HOST_TSO6  12      /* Host can handle TSOv6 in. */
#define VIRTIO_NET_F_HOST_ECN   13      /* Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_HOST_UFO   14      /* Host can handle UFO in. */
#define VIRTIO_NET_F_MRG_RXBUF  15      /* Host can merge receive buffers. */
#define VIRTIO_NET_F_STATUS     16      /* virtio_net_config.status available */
#define VIRTIO_NET_F_CTRL_VQ    17      /* Control channel available */
#define VIRTIO_NET_F_CTRL_RX    18      /* Control channel RX mode support */
#define VIRTIO_NET_F_CTRL_VLAN  19      /* Control channel VLAN filtering */
#define VIRTIO_NET_F_CTRL_RX_EXTRA 20   /* Extra RX mode control support */
#define VIRTIO_NET_F_GUEST_ANNOUNCE 21  /* Guest can announce device on the
                                         * network */
#define VIRTIO_NET_F_MQ         22      /* Device supports Receive Flow
                                         * Steering */
#define VIRTIO_NET_F_CTRL_MAC_ADDR 23   /* Set MAC address */

/* Do we get callbacks when the ring is completely used, even if we've
 * suppressed them? */
#define VIRTIO_F_NOTIFY_ON_EMPTY        24

/* Can the device handle any descriptor layout? */
#define VIRTIO_F_ANY_LAYOUT             27

/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC     28

#define VIRTIO_F_VERSION_1              32



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

static char req_names[][50] = {
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

#define offsetof(type, field)  ((size_t) &( ((type *)0)->field) )

typedef struct vhost_user_msg {
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
} __attribute((packed)) VhostUserMsg;
#define VHOST_USER_HDR_SIZE offsetof(VhostUserMsg, payload.u64)


int read_fd_message(int sockfd, char *buf, int buflen, int *fds, int fd_num);
int read_vhost_message(int sockfd, struct vhost_user_msg *msg);
int send_vhost_message(int sockfd, struct vhost_user_msg *msg);
int send_fd_message(int sockfd, char *buf, int buflen, int *fds, int fd_num);
uint64_t get_blk_size(int fd);

/* Macro to align a value to a given power-of-two. The resultant value
 * will be of the same type as the first parameter, and will be no
 * bigger than the first parameter. Second parameter must be a
 * power-of-two value.
 */
#define RTE_ALIGN_FLOOR(val, align) \
        (typeof(val))((val) & (~((typeof(val))((align) - 1))))

/**
 * Macro to align a pointer to a given power-of-two. The resultant
 * pointer will be a pointer of the same type as the first parameter, and
 * point to an address no lower than the first parameter. Second parameter
 * must be a power-of-two value.
 */
#define RTE_PTR_ALIGN_CEIL(ptr, align) \
        RTE_PTR_ALIGN_FLOOR((typeof(ptr))RTE_PTR_ADD(ptr, (align) - 1), align)

/**
 * Macro to align a value to a given power-of-two. The resultant value
 * will be of the same type as the first parameter, and will be no lower
 * than the first parameter. Second parameter must be a power-of-two
 * value.
 */
#define RTE_ALIGN_CEIL(val, align) \
        RTE_ALIGN_FLOOR(((val) + ((typeof(val)) (align) - 1)), align)

struct address_translation
{
	volatile uint64_t guestphyaddr;
	volatile uint64_t qemuvirtaddr;
	volatile uint64_t vhostuservirtaddr;
	volatile uint64_t len;
	volatile uint64_t offset;
	int mapfd;
};

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT       1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE      2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT   4

/* The Host uses this in used->flags to advise the Guest: don't kick me
 * when you add a buffer.  It's unreliable, so it's simply an
 * optimization.  Guest will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY  1
/* The Guest uses this in avail->flags to advise the Host: don't
 * interrupt me when you consume a buffer.  It's unreliable, so it's
 * simply an optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT  1



/* VirtIO ring descriptors: 16 bytes.
 * These can chain together via "next". */
struct vring_desc {
        volatile uint64_t addr;  /*  Address (guest-physical). */
        volatile uint32_t len;   /* Length. */
        volatile uint16_t flags; /* The flags as indicated above. */
        volatile uint16_t next;  /* We chain unused descriptors via this. */
};

struct vring_avail {
        volatile uint16_t flags;
        volatile uint16_t idx;
        volatile uint16_t ring[0];
};

/* id is a 16bit index. uint32_t is used here for ids for padding reasons. */
struct vring_used_elem {
        /* Index of start of used descriptor chain. */
        volatile uint32_t id;
        /* Total length of the descriptor chain which was written to. */
        volatile uint32_t len;
};


struct vring_used {
        volatile uint16_t flags;
        volatile uint16_t idx;
        volatile struct vring_used_elem ring[0];
};


/**
 * This is the first element of the scatter-gather list.  If you don't
 * specify GSO or CSUM features, you can simply ignore the header.
 */
struct virtio_net_hdr {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM 1    /**< Use csum_start,csum_offset*/
        uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE     0    /**< Not a GSO frame */
#define VIRTIO_NET_HDR_GSO_TCPV4    1    /**< GSO frame, IPv4 TCP (TSO) */
#define VIRTIO_NET_HDR_GSO_UDP      3    /**< GSO frame, IPv4 UDP (UFO) */
#define VIRTIO_NET_HDR_GSO_TCPV6    4    /**< GSO frame, IPv6 TCP */
#define VIRTIO_NET_HDR_GSO_ECN      0x80 /**< TCP has ECN set */
        uint8_t gso_type;
        uint16_t hdr_len;     /**< Ethernet + IP + tcp/udp hdrs */
        uint16_t gso_size;    /**< Bytes to append to hdr_len per frame */
        uint16_t csum_start;  /**< Position to start checksumming from */
        uint16_t csum_offset; /**< Offset after that to place checksum */
};      
                
/**
 * This is the version of the header to use when the MRG_RXBUF
 * feature has been negotiated.
 */             
struct virtio_net_hdr_mrg_rxbuf {
        struct   virtio_net_hdr hdr;
        uint16_t num_buffers; /**< Number of merged rx buffers */
};      

struct mem_chunks
{
	uint64_t addr;
	uint64_t len;
};

struct sg_list
{
	int num_elements;
	struct mem_chunks *chunks;
};

#define wmb()   asm volatile("sfence" ::: "memory")
#define rmb()   asm volatile("lfence" ::: "memory")
#define barrier() asm volatile("" ::: "memory")


#define VHOST_USER_F_PROTOCOL_FEATURES  30

#define VHOST_SUPPORTS_MQ      (1ULL << VIRTIO_NET_F_MQ)
#define VHOST_F_LOG_ALL 26
/* Features supported by this lib. */


#define VHOST_USER_PROTOCOL_F_MQ        0
#define VHOST_USER_PROTOCOL_F_LOG_SHMFD 1
#define VHOST_USER_PROTOCOL_F_RARP      2

/*
#define VHOST_USER_PROTOCOL_FEATURES    ((1ULL << VHOST_USER_PROTOCOL_F_MQ) | \
                                         (1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD) |\
                                         (1ULL << VHOST_USER_PROTOCOL_F_RARP))
*/


#define VHOST_USER_PROTOCOL_FEATURES    (1ULL << VHOST_USER_PROTOCOL_F_MQ) 



#if 0
#define VHOST_SUPPORTED_FEATURES ((1ULL << VIRTIO_NET_F_MRG_RXBUF) | \
                                (1ULL << VIRTIO_NET_F_CTRL_VQ) | \
                                (1ULL << VIRTIO_NET_F_CTRL_RX) | \
                                (1ULL << VIRTIO_NET_F_GUEST_ANNOUNCE) | \
                                (VHOST_SUPPORTS_MQ)            | \
                                (1ULL << VIRTIO_F_VERSION_1)   | \
                                (1ULL << VHOST_F_LOG_ALL)      | \
                                (1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
                                (1ULL << VIRTIO_NET_F_HOST_TSO4) | \
                                (1ULL << VIRTIO_NET_F_HOST_TSO6) | \
                                (1ULL << VIRTIO_NET_F_CSUM)    | \
                                (1ULL << VIRTIO_NET_F_GUEST_CSUM) | \
                                (1ULL << VIRTIO_NET_F_GUEST_TSO4) | \
                                (1ULL << VIRTIO_NET_F_GUEST_TSO6))
#endif


/* Features supported by this lib. */
//#define VHOST_SUPPORTED_FEATURES ((1ULL << VIRTIO_NET_F_MRG_RXBUF) | \


#define VHOST_SUPPORTED_FEATURES ((1ULL << VIRTIO_NET_F_CTRL_VQ) | \
                                (1ULL << VIRTIO_NET_F_CTRL_RX) | \
				(1ULL << VIRTIO_F_VERSION_1)   | \
                                (1ULL << VHOST_F_LOG_ALL)      | \
                                (1ULL << VHOST_USER_F_PROTOCOL_FEATURES))






#endif

