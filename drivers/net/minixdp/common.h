#ifndef MINI_XDP_COMMON_H
#define MINI_XDP_COMMON_H

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
#include "af_xdp_deps.h"
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

#define ETH_AF_XDP_FRAME_SIZE        2048
#define ETH_AF_XDP_NUM_BUFFERS        4096
#define ETH_AF_XDP_DFLT_NUM_DESCS    XSK_RING_CONS__DEFAULT_NUM_DESCS
#define ETH_AF_XDP_DFLT_QUEUE_COUNT    1
#define ETH_AF_XDP_DFLT_BUSY_BUDGET    64
#define ETH_AF_XDP_DFLT_BUSY_TIMEOUT    20

#define ETH_AF_XDP_RX_BATCH_SIZE    XSK_RING_CONS__DEFAULT_NUM_DESCS
#define ETH_AF_XDP_TX_BATCH_SIZE    XSK_RING_CONS__DEFAULT_NUM_DESCS

#define ETH_AF_XDP_ETH_OVERHEAD        (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN)



struct pmd_internals {
    int if_index;
    char if_name[IFNAMSIZ];
//    int start_queue_idx;
//    int queue_cnt;
//    int max_queue_cnt;
//    int combined_queue_cnt;
//    bool shared_umem;
    char prog_path[PATH_MAX];
    bool custom_prog_configured;
    struct bpf_map *map;

    struct rte_ether_addr eth_addr;

    struct pkt_rx_queue *rx_queues;
    struct pkt_tx_queue *tx_queues;
};

#endif //MINI_XDP_COMMON_H



// 原有文件中挪出来的
#ifndef _RTE_ETHDEV_VDEV_H_
#define _RTE_ETHDEV_VDEV_H_

#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_bus_vdev.h>
#include <ethdev_driver.h>

/**
 * @internal
 * Allocates a new ethdev slot for an Ethernet device and returns the pointer
 * to that slot for the driver to use.
 *
 * @param dev
 *	Pointer to virtual device
 *
 * @param private_data_size
 *	Size of private data structure
 *
 * @return
 *	A pointer to a rte_eth_dev or NULL if allocation failed.
 */
static inline struct rte_eth_dev *
rte_eth_vdev_allocate(struct rte_vdev_device *dev, size_t private_data_size)
{
    struct rte_eth_dev *eth_dev;
    const char *name = rte_vdev_device_name(dev);

    eth_dev = rte_eth_dev_allocate(name);
    if (!eth_dev)
        return NULL;

    if (private_data_size) {
        eth_dev->data->dev_private = rte_zmalloc_socket(name,
                                                        private_data_size, RTE_CACHE_LINE_SIZE,
                                                        dev->device.numa_node);
        if (!eth_dev->data->dev_private) {
            rte_eth_dev_release_port(eth_dev);
            return NULL;
        }
    }

    eth_dev->device = &dev->device;
    eth_dev->intr_handle = NULL;

    eth_dev->data->numa_node = dev->device.numa_node;
    return eth_dev;
}

#endif /* _RTE_ETHDEV_VDEV_H_ */