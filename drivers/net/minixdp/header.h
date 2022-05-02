#ifndef MINI_XDP_HEADER_H
#define MINI_XDP_HEADER_H

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include "mini_xdp_deps.h"
#include <bpf/bpf.h>
#include <bpf/xsk.h>

#include <rte_ethdev.h>
#include <ethdev_driver.h>
#include <ethdev_vdev.h>
#include <rte_kvargs.h>
#include <rte_bus_vdev.h>
#include <rte_string_fns.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_spinlock.h>
#include <rte_power_intrinsics.h>

#include "compat.h"
#include "vdev.h"

#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif


#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

RTE_LOG_REGISTER_DEFAULT(mini_xdp_logtype, NOTICE);

#define MINI_XDP_LOG(level, fmt, args...)         \
    rte_log(RTE_LOG_ ## level, mini_xdp_logtype,    \
        "%s(): " fmt, __func__, ##args)

// XDP每帧空间
#define ETH_AF_XDP_FRAME_SIZE        2048
// Ringbuff分配数量，对齐desc的两倍即可
#define ETH_AF_XDP_NUM_BUFFERS        ETH_AF_XDP_DFLT_NUM_DESCS * 2

// 默认的XDP desc数量，默认为2048
//  此大小目前用于Rxq Txq，以及Fill和Complete Ring
#define ETH_AF_XDP_DFLT_NUM_DESCS    XSK_RING_CONS__DEFAULT_NUM_DESCS

#define ETH_AF_XDP_DFLT_QUEUE_COUNT    1
#define ETH_AF_XDP_DFLT_BUSY_BUDGET    64
#define ETH_AF_XDP_DFLT_BUSY_TIMEOUT    20

#define ETH_MINI_XDP_DFLT_BURST_SIZE 64

#define ETH_AF_XDP_RX_BATCH_SIZE    XSK_RING_CONS__DEFAULT_NUM_DESCS
#define ETH_AF_XDP_TX_BATCH_SIZE    XSK_RING_CONS__DEFAULT_NUM_DESCS

#define ETH_AF_XDP_ETH_OVERHEAD        (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN)

#endif //MINI_XDP_HEADER_H
