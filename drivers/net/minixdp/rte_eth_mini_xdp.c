#include "header.h"

struct pmd_internals {
    // 父接口的ID
    int if_index;
    // 父接口名
    char if_name[IFNAMSIZ];

    // eBPF程序部分
    // 程序二进制文件路径
    char prog_path[PATH_MAX];
    // 标记
    bool custom_prog_configured;
    // ebpf程序文件描述符
    int bpf_fd;
    // ARP缓存表
    struct bpf_map *arp_cache_map;
    // 重定向的IPv4路由表
    struct bpf_map *redirect_v4_map;
    // 重定向的队列
    struct bpf_map *xsk_map;

    struct rte_ether_addr eth_addr;

    struct pkt_rx_queue *rx_queues;
    struct pkt_tx_queue *tx_queues;
};

struct xsk_umem_info {
    struct xsk_umem *umem;
    struct rte_ring *buf_ring;
    const struct rte_memzone *mz;
    struct rte_mempool *mb_pool;
    void *buffer;
    uint8_t refcnt;
};

// Rx队列计数器
struct rx_stats {
    uint64_t rx_pkts;
    uint64_t rx_bytes;
    uint64_t rx_dropped;
};

// Rx队列配置
struct pkt_rx_queue {
    struct xsk_ring_cons rx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    struct rte_mempool *mb_pool;

    struct rx_stats stats;

    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;

    struct pkt_tx_queue *pair;
    struct pollfd fds[1];
    int xsk_queue_idx;
};

// Tx队列计数器
struct tx_stats {
    uint64_t tx_pkts;
    uint64_t tx_bytes;
    uint64_t tx_dropped;
};

// Tx队列配置
struct pkt_tx_queue {
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;

    struct tx_stats stats;

    struct pkt_rx_queue *pair;
    int xsk_queue_idx;
};

static const struct rte_eth_link pmd_link = {
        .link_speed = RTE_ETH_SPEED_NUM_10G,
        .link_duplex = RTE_ETH_LINK_FULL_DUPLEX,
        .link_status = RTE_ETH_LINK_DOWN,
        .link_autoneg = RTE_ETH_LINK_AUTONEG,
};

static inline int
reserve_fill_queue(struct xsk_umem_info *umem, uint16_t reserve_size,
                   struct rte_mbuf **bufs __rte_unused, struct xsk_ring_prod *fq) {
    void *addrs[reserve_size];
    uint32_t idx;
    uint16_t i;

    if (rte_ring_dequeue_bulk(umem->buf_ring, addrs, reserve_size, NULL) != reserve_size) {
        MINI_XDP_LOG(DEBUG, "Failed to get enough buffers for fq.\n");
        return -1;
    }

    if (unlikely(!xsk_ring_prod__reserve(fq, reserve_size, &idx))) {
        MINI_XDP_LOG(DEBUG, "Failed to reserve enough fq descs.\n");
        rte_ring_enqueue_bulk(umem->buf_ring, addrs,
                              reserve_size, NULL);
        return -1;
    }

    for (i = 0; i < reserve_size; i++) {
        __u64 *fq_addr;

        fq_addr = xsk_ring_prod__fill_addr(fq, idx++);
        *fq_addr = (uint64_t) addrs[i];
    }

    xsk_ring_prod__submit(fq, reserve_size);

    return 0;
}

static uint16_t
af_xdp_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts) {
    struct pkt_rx_queue *rxq = queue;
    struct xsk_ring_cons *rx = &rxq->rx;
    struct xsk_umem_info *umem = rxq->umem;
    struct xsk_ring_prod *fq = &rxq->fq;
    uint32_t idx_rx = 0;
    unsigned long rx_bytes = 0;
    int i;
    uint32_t free_thresh = fq->size >> 1;
    struct rte_mbuf *mbufs[ETH_AF_XDP_RX_BATCH_SIZE];

    // prod队列不能空，不然会出现死锁，所以在消费前必须判断一下是否为空的，空了就要放desc
    if (xsk_prod_nb_free(fq, free_thresh) >= free_thresh)
        (void) reserve_fill_queue(umem, nb_pkts, NULL, fq);

    nb_pkts = xsk_ring_cons__peek(rx, nb_pkts, &idx_rx);
    if (nb_pkts == 0) {
#if defined(XDP_USE_NEED_WAKEUP)
        if (xsk_ring_prod__needs_wakeup(fq))
            (void)poll(rxq->fds, 1, 1000);
#endif
        return 0;
    }

    // 为传入的mbuf准备
    if (unlikely(rte_pktmbuf_alloc_bulk(rxq->mb_pool, mbufs, nb_pkts))) {
        /* rollback cached_cons which is added by
         * xsk_ring_cons__peek
         */
        rx->cached_cons -= nb_pkts;
        return 0;
    }

    for (i = 0; i < nb_pkts; i++) {
        const struct xdp_desc *desc;
        uint64_t addr;
        uint32_t len;
        void *pkt;

        desc = xsk_ring_cons__rx_desc(rx, idx_rx++);
        addr = desc->addr;
        len = desc->len;
        pkt = xsk_umem__get_data(rxq->umem->mz->addr, addr);

        rte_memcpy(rte_pktmbuf_mtod(mbufs[i], void *), pkt, len);
        rte_ring_enqueue(umem->buf_ring, (void *) addr);
        rte_pktmbuf_pkt_len(mbufs[i]) = len;
        rte_pktmbuf_data_len(mbufs[i]) = len;
        rx_bytes += len;
        bufs[i] = mbufs[i];
    }

    xsk_ring_cons__release(rx, nb_pkts);

    /* statistics */
    rxq->stats.rx_pkts += nb_pkts;
    rxq->stats.rx_bytes += rx_bytes;

    return nb_pkts;
}

static uint16_t
eth_af_xdp_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts) {
    uint16_t nb_rx;

    if (likely(nb_pkts <= ETH_AF_XDP_RX_BATCH_SIZE))
        return af_xdp_rx(queue, bufs, nb_pkts);

    /* Split larger batch into smaller batches of size
     * ETH_AF_XDP_RX_BATCH_SIZE or less.
     */
    nb_rx = 0;
    while (nb_pkts) {
        uint16_t ret, n;

        n = (uint16_t) RTE_MIN(nb_pkts, ETH_AF_XDP_RX_BATCH_SIZE);
        ret = af_xdp_rx(queue, &bufs[nb_rx], n);
        nb_rx = (uint16_t)(nb_rx + ret);
        nb_pkts = (uint16_t)(nb_pkts - ret);
        if (ret < n)
            break;
    }

    return nb_rx;
}

static void
pull_umem(struct xsk_umem_info *umem, int size, struct xsk_ring_cons *cq) {
    size_t i, n;
    uint32_t idx_cq = 0;

    n = xsk_ring_cons__peek(cq, size, &idx_cq);

    for (i = 0; i < n; i++) {
        uint64_t addr;
        addr = *xsk_ring_cons__comp_addr(cq, idx_cq++);
        rte_ring_enqueue(umem->buf_ring, (void *) addr);
    }

    xsk_ring_cons__release(cq, n);
}

static void
kick_tx(struct pkt_tx_queue *txq, struct xsk_ring_cons *cq) {
    struct xsk_umem_info *umem = txq->umem;

    pull_umem(umem, XSK_RING_CONS__DEFAULT_NUM_DESCS, cq);

    if (tx_syscall_needed(&txq->tx))
        while (send(xsk_socket__fd(txq->pair->xsk), NULL,
                    0, MSG_DONTWAIT) < 0) {
            /* some thing unexpected */
            if (errno != EBUSY && errno != EAGAIN && errno != EINTR)
                break;

            /* pull from completion queue to leave more space */
            if (errno == EAGAIN)
                pull_umem(umem,
                          XSK_RING_CONS__DEFAULT_NUM_DESCS,
                          cq);
        }
}

static uint16_t
af_xdp_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts) {
    struct pkt_tx_queue *txq = queue;
    struct xsk_umem_info *umem = txq->umem;
    struct rte_mbuf *mbuf;
    void *addrs[ETH_AF_XDP_TX_BATCH_SIZE];
    unsigned long tx_bytes = 0;
    int i;
    uint32_t idx_tx;
    struct xsk_ring_cons *cq = &txq->pair->cq;

    pull_umem(umem, nb_pkts, cq);

    nb_pkts = rte_ring_dequeue_bulk(umem->buf_ring, addrs,
                                    nb_pkts, NULL);
    if (nb_pkts == 0)
        return 0;

    if (xsk_ring_prod__reserve(&txq->tx, nb_pkts, &idx_tx) != nb_pkts) {
        kick_tx(txq, cq);
        rte_ring_enqueue_bulk(umem->buf_ring, addrs, nb_pkts, NULL);
        return 0;
    }

    for (i = 0; i < nb_pkts; i++) {
        struct xdp_desc *desc;
        void *pkt;

        desc = xsk_ring_prod__tx_desc(&txq->tx, idx_tx + i);
        mbuf = bufs[i];
        desc->len = mbuf->pkt_len;

        desc->addr = (uint64_t) addrs[i];
        pkt = xsk_umem__get_data(umem->mz->addr, desc->addr);
        rte_memcpy(pkt, rte_pktmbuf_mtod(mbuf, void *), desc->len);
        tx_bytes += mbuf->pkt_len;
        rte_pktmbuf_free(mbuf);
    }

    xsk_ring_prod__submit(&txq->tx, nb_pkts);

    kick_tx(txq, cq);

    txq->stats.tx_pkts += nb_pkts;
    txq->stats.tx_bytes += tx_bytes;

    return nb_pkts;
}

static uint16_t
eth_af_xdp_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts) {
    uint16_t nb_tx;

    if (likely(nb_pkts <= ETH_AF_XDP_TX_BATCH_SIZE))
        return af_xdp_tx(queue, bufs, nb_pkts);

    nb_tx = 0;
    while (nb_pkts) {
        uint16_t ret, n;

        /* Split larger batch into smaller batches of size
         * ETH_AF_XDP_TX_BATCH_SIZE or less.
         */
        n = (uint16_t) RTE_MIN(nb_pkts, ETH_AF_XDP_TX_BATCH_SIZE);
        ret = af_xdp_tx(queue, &bufs[nb_tx], n);
        nb_tx = (uint16_t)(nb_tx + ret);
        nb_pkts = (uint16_t)(nb_pkts - ret);
        if (ret < n)
            break;
    }

    return nb_tx;
}

static int
eth_dev_start(struct rte_eth_dev *dev) {
    dev->data->dev_link.link_status = RTE_ETH_LINK_UP;

    return 0;
}

static int
eth_dev_stop(struct rte_eth_dev *dev) {
    dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;

    return 0;
}

static int
eth_dev_configure(struct rte_eth_dev *dev) {
    /* rx/tx must be paired */
    if (dev->data->nb_rx_queues != dev->data->nb_tx_queues)
        return -EINVAL;

    return 0;
}

#define CLB_VAL_IDX 0

static int
eth_monitor_callback(const uint64_t value,
                     const uint64_t opaque[RTE_POWER_MONITOR_OPAQUE_SZ]) {
    const uint64_t v = opaque[CLB_VAL_IDX];
    const uint64_t m = (uint32_t)
    ~0;

    /* if the value has changed, abort entering power optimized state */
    return (value & m) == v ? 0 : -1;
}

static int
eth_get_monitor_addr(void *rx_queue, struct rte_power_monitor_cond *pmc) {
    struct pkt_rx_queue *rxq = rx_queue;
    unsigned int *prod = rxq->rx.producer;
    const uint32_t cur_val = rxq->rx.cached_prod; /* use cached value */

    /* watch for changes in producer ring */
    pmc->addr = (void *) prod;

    /* store current value */
    pmc->opaque[CLB_VAL_IDX] = cur_val;
    pmc->fn = eth_monitor_callback;

    /* AF_XDP producer ring index is 32-bit */
    pmc->size = sizeof(uint32_t);

    return 0;
}

// 获取接口信息
static int
eth_dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info) {
    struct pmd_internals *internals = dev->data->dev_private;

    dev_info->if_index = internals->if_index;
    dev_info->max_mac_addrs = 1;

    // 队列只支持一个，因此全部设置为1即可
    dev_info->max_rx_queues = 1;
    dev_info->max_tx_queues = 1;

    dev_info->min_mtu = RTE_ETHER_MIN_MTU;
    dev_info->max_rx_pktlen = ETH_AF_XDP_FRAME_SIZE - XDP_PACKET_HEADROOM;
    // dev_info获取的最大MTU限制为1500，以免公网传输过程中产生太多分片
    dev_info->max_mtu = ((dev_info->max_rx_pktlen - ETH_AF_XDP_ETH_OVERHEAD) > 1500) ?
                        1500 : (dev_info->max_rx_pktlen - ETH_AF_XDP_ETH_OVERHEAD);

    // 突发模式把队列缩小
    dev_info->default_rxportconf.burst_size = ETH_MINI_XDP_DFLT_BURST_SIZE;
    dev_info->default_txportconf.burst_size = ETH_MINI_XDP_DFLT_BURST_SIZE;

    dev_info->default_rxportconf.nb_queues = 1;
    dev_info->default_txportconf.nb_queues = 1;
    dev_info->default_rxportconf.ring_size = ETH_AF_XDP_DFLT_NUM_DESCS;
    dev_info->default_txportconf.ring_size = ETH_AF_XDP_DFLT_NUM_DESCS;

    return 0;
}

static int
eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats) {
    struct pmd_internals *internals = dev->data->dev_private;
    struct xdp_statistics xdp_stats;
    struct pkt_rx_queue *rxq;
    struct pkt_tx_queue *txq;
    socklen_t optlen;
    int i, ret;

    for (i = 0; i < dev->data->nb_rx_queues; i++) {
        optlen = sizeof(struct xdp_statistics);
        rxq = &internals->rx_queues[i];
        txq = rxq->pair;
        stats->q_ipackets[i] = rxq->stats.rx_pkts;
        stats->q_ibytes[i] = rxq->stats.rx_bytes;

        stats->q_opackets[i] = txq->stats.tx_pkts;
        stats->q_obytes[i] = txq->stats.tx_bytes;

        stats->ipackets += stats->q_ipackets[i];
        stats->ibytes += stats->q_ibytes[i];
        stats->imissed += rxq->stats.rx_dropped;
        stats->oerrors += txq->stats.tx_dropped;
        ret = getsockopt(xsk_socket__fd(rxq->xsk), SOL_XDP,
                         XDP_STATISTICS, &xdp_stats, &optlen);
        if (ret != 0) {
            MINI_XDP_LOG(ERR, "getsockopt() failed for XDP_STATISTICS.\n");
            return -1;
        }
        stats->imissed += xdp_stats.rx_dropped;

        stats->opackets += stats->q_opackets[i];
        stats->obytes += stats->q_obytes[i];
    }

    return 0;
}

// 重置接口收发包计数器
static int
eth_stats_reset(struct rte_eth_dev *dev) {
    struct pmd_internals *internals = dev->data->dev_private;

    // 只有一个队列
    memset(&internals->rx_queues[0].stats, 0, sizeof(struct rx_stats));
    memset(&internals->tx_queues[0].stats, 0, sizeof(struct tx_stats));

    return 0;
}

// 卸载xdp程序
static void
remove_xdp_program(struct pmd_internals *internals) {
    uint32_t curr_prog_id = 0;

    if (bpf_get_link_xdp_id(internals->if_index, &curr_prog_id,
                            XDP_FLAGS_UPDATE_IF_NOEXIST)) {
        MINI_XDP_LOG(ERR, "bpf_get_link_xdp_id failed\n");
        return;
    }
    bpf_set_link_xdp_fd(internals->if_index, -1,
                        XDP_FLAGS_UPDATE_IF_NOEXIST);
}

static void
xdp_umem_destroy(struct xsk_umem_info *umem) {
    rte_memzone_free(umem->mz);
    umem->mz = NULL;

    rte_ring_free(umem->buf_ring);
    umem->buf_ring = NULL;

    rte_free(umem);
}

// 关闭vdev接口
static int
eth_dev_close(struct rte_eth_dev *dev) {
    struct pmd_internals *internals = dev->data->dev_private;
    struct pkt_rx_queue *rxq;

    // 只处理主线程，因为不会有第二个，因此其他线程的就不再处理
    if (rte_eal_process_type() != RTE_PROC_PRIMARY)
        return 0;

    MINI_XDP_LOG(INFO,
                 "Closing AF_XDP ethdev on numa socket %u\n",
                 rte_socket_id());

    // 只有一个队列，因此下边只需要关第一个队列即可
    rxq = &internals->rx_queues[0];
    if (rxq->umem == NULL)
        goto clean_mac;
    xsk_socket__delete(rxq->xsk);
    if (__atomic_sub_fetch(&rxq->umem->refcnt, 1, __ATOMIC_ACQUIRE) == 0) {
        (void) xsk_umem__delete(rxq->umem->umem);
        xdp_umem_destroy(rxq->umem);
    }

    /* free pkt_tx_queue */
    rte_free(rxq->pair);
    rte_free(rxq);

    clean_mac:
    /*
     * MAC is not allocated dynamically, setting it to NULL would prevent
     * from releasing it in rte_eth_dev_release_port.
     */
    dev->data->mac_addrs = NULL;

    // 移除接口绑定的XDP程序
    remove_xdp_program(internals);

    // 没有开启共享的UMEM，所以不再进行原本代码中的shared UMEM操作

    return 0;
}

static int
eth_link_update(struct rte_eth_dev *dev __rte_unused,
                int wait_to_complete __rte_unused) {
    return 0;
}

static struct xsk_umem_info *
xdp_umem_configure(struct pmd_internals *internals, struct pkt_rx_queue *rxq) {
    struct xsk_umem_info *umem;
    const struct rte_memzone *mz;
    struct xsk_umem_config usr_config = {
            .fill_size = ETH_AF_XDP_DFLT_NUM_DESCS,
            .comp_size = ETH_AF_XDP_DFLT_NUM_DESCS,
            .frame_size = ETH_AF_XDP_FRAME_SIZE,
            .frame_headroom = 0};
    char ring_name[RTE_RING_NAMESIZE];
    char mz_name[RTE_MEMZONE_NAMESIZE];
    int ret;
    uint64_t i;

    umem = rte_zmalloc_socket("umem", sizeof(struct xsk_umem_info), 0, rte_socket_id());
    if (umem == NULL) {
        MINI_XDP_LOG(ERR, "Failed to allocate umem info");
        return NULL;
    }

    snprintf(ring_name, sizeof(ring_name), "mini_xdp_ring_%s_%u",
             internals->if_name, rxq->xsk_queue_idx);
    umem->buf_ring = rte_ring_create(ring_name,
                                     ETH_AF_XDP_NUM_BUFFERS,
                                     rte_socket_id(),
                                     0x0);
    if (umem->buf_ring == NULL) {
        MINI_XDP_LOG(ERR, "Failed to create rte_ring\n");
        goto err;
    }

    for (i = 0; i < ETH_AF_XDP_NUM_BUFFERS; i++)
        rte_ring_enqueue(umem->buf_ring,
                         (void *) (i * ETH_AF_XDP_FRAME_SIZE));

    snprintf(mz_name, sizeof(mz_name), "mini_xdp_umem_%s_%u",
             internals->if_name, rxq->xsk_queue_idx);
    mz = rte_memzone_reserve_aligned(mz_name,
                                     ETH_AF_XDP_NUM_BUFFERS * ETH_AF_XDP_FRAME_SIZE,
                                     rte_socket_id(), RTE_MEMZONE_IOVA_CONTIG,
                                     getpagesize());
    if (mz == NULL) {
        MINI_XDP_LOG(ERR, "Failed to reserve memzone for umem.\n");
        goto err;
    }

    ret = xsk_umem__create(&umem->umem, mz->addr,
                           ETH_AF_XDP_NUM_BUFFERS * ETH_AF_XDP_FRAME_SIZE,
                           &rxq->fq, &rxq->cq,
                           &usr_config);

    if (ret) {
        MINI_XDP_LOG(ERR, "Failed to create umem");
        goto err;
    }
    umem->mz = mz;

    return umem;

    err:
    xdp_umem_destroy(umem);
    return NULL;
};

static int
load_xdp_prog(struct pmd_internals *internals) {
    struct bpf_object *obj;

    int ret = bpf_prog_load(internals->prog_path, BPF_PROG_TYPE_XDP, &obj, &internals->bpf_fd);
    if (ret) {
        MINI_XDP_LOG(ERR,
                     "Failed to load xdp program: %s\n", internals->prog_path);
        return ret;
    }

    // 加载 arp_cache_map
    //  此map主要用于同步ARP记录
    internals->arp_cache_map = bpf_object__find_map_by_name(obj, "arp_cache_map");
    if (!internals->arp_cache_map) {
        MINI_XDP_LOG(ERR,
                     "Failed to find arp_cache_map in %s\n", internals->prog_path);
        return -1;
    }

    // 加载 redirect_v4_map
    //  此map主要用于IPv4重定向到xsk map
    internals->redirect_v4_map = bpf_object__find_map_by_name(obj, "redirect_v4_map");
    if (!internals->redirect_v4_map) {
        MINI_XDP_LOG(ERR,
                     "Failed to find redirect_v4_map in %s\n", internals->prog_path);
        return -1;
    }

    // 加载 xsk_map
    internals->xsk_map = bpf_object__find_map_by_name(obj, "xsk_map");
    if (!internals->xsk_map) {
        MINI_XDP_LOG(ERR,
                     "Failed to find xsk_map in %s\n", internals->prog_path);
        return -1;
    }

    // 把XDP程序加载到接口
    ret = bpf_set_link_xdp_fd(internals->if_index, internals->bpf_fd,
                              XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (ret) {
        MINI_XDP_LOG(ERR,
                     "Failed to set prog fd %d on interface\n", internals->bpf_fd);
        return -1;
    }

    MINI_XDP_LOG(INFO,
                 "Successfully loaded XDP program %s with fd %d\n",
                 internals->prog_path, internals->bpf_fd);

    return 0;
};

static int
xsk_configure(struct pmd_internals *internals, struct pkt_rx_queue *rxq, int ring_size) {
    struct xsk_socket_config cfg;
    struct pkt_tx_queue *txq = rxq->pair;
    int ret = 0;
    int reserve_size = ETH_AF_XDP_DFLT_NUM_DESCS;
    struct rte_mbuf *fq_bufs[reserve_size];

    rxq->umem = xdp_umem_configure(internals, rxq);
    if (rxq->umem == NULL)
        return -ENOMEM;
    txq->umem = rxq->umem;

    cfg.rx_size = ring_size;
    cfg.tx_size = ring_size;
    cfg.libbpf_flags = 0;
    cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    cfg.bind_flags = 0;

#if defined(XDP_USE_NEED_WAKEUP)
    // 可以设置唤醒模式，省掉busy poll的CPU消耗
    cfg.bind_flags |= XDP_USE_NEED_WAKEUP;
#endif

    if (strnlen(internals->prog_path, PATH_MAX) && !internals->custom_prog_configured) {
        // 加载XDP程序和其内部的map
        ret = load_xdp_prog(internals);
        if (ret) {
            MINI_XDP_LOG(ERR, "Failed to load XDP program %s\n",
                         internals->prog_path);
            goto err;
        }

        internals->custom_prog_configured = 1;
        cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    }

    ret = xsk_socket__create(&rxq->xsk, internals->if_name,
                             rxq->xsk_queue_idx, rxq->umem->umem, &rxq->rx,
                             &txq->tx, &cfg);
    if (ret) {
        MINI_XDP_LOG(ERR, "Failed to create xsk socket.\n");
        goto err;
    }

    /* insert the xsk into the xsk_map */
    if (internals->custom_prog_configured) {
        int err, fd;

        fd = xsk_socket__fd(rxq->xsk);
        err = bpf_map_update_elem(bpf_map__fd(internals->xsk_map),
                                  &rxq->xsk_queue_idx, &fd, 0);
        if (err) {
            MINI_XDP_LOG(ERR, "Failed to insert xsk in map.\n");
            goto err;
        }
    }

    ret = reserve_fill_queue(rxq->umem, reserve_size, fq_bufs, &rxq->fq);
    if (ret) {
        xsk_socket__delete(rxq->xsk);
        MINI_XDP_LOG(ERR, "Failed to reserve fill queue.\n");
        goto err;
    }

    return 0;

    err:
    if (__atomic_sub_fetch(&rxq->umem->refcnt, 1, __ATOMIC_ACQUIRE) == 0)
        xdp_umem_destroy(rxq->umem);

    return ret;
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev,
                   uint16_t rx_queue_id,
                   uint16_t nb_rx_desc,
                   unsigned int socket_id __rte_unused,
                   const struct rte_eth_rxconf *rx_conf __rte_unused,
                   struct rte_mempool *mb_pool) {
    struct pmd_internals *internals = dev->data->dev_private;
    struct pkt_rx_queue *rxq;
    int ret;

    // 只支持单队列，队列ID仅会为0
    if (rx_queue_id != 0) {
        MINI_XDP_LOG(ERR,
                     "Set up rx queue failed: id %d is not 0\n", rx_queue_id);
        ret = -EINVAL;
        goto err;
    }

    // 获取父接口的rx队列
    //  这里保证队列一定只有0号
    rxq = &internals->rx_queues[rx_queue_id];

    MINI_XDP_LOG(INFO, "Set up rx queue, rx queue id: %d, xsk queue id: %d\n",
                 rx_queue_id, rxq->xsk_queue_idx);

    rxq->mb_pool = mb_pool;

    if (xsk_configure(internals, rxq, nb_rx_desc)) {
        MINI_XDP_LOG(ERR, "Failed to configure xdp socket\n");
        ret = -EINVAL;
        goto err;
    }

    rxq->fds[0].fd = xsk_socket__fd(rxq->xsk);
    rxq->fds[0].events = POLLIN;

    dev->data->rx_queues[rx_queue_id] = rxq;
    return 0;

    err:
    return ret;
}

// 设置发送流程
static int
eth_tx_queue_setup(struct rte_eth_dev *dev,
                   uint16_t tx_queue_id,
                   uint16_t nb_tx_desc __rte_unused,
                   unsigned int socket_id __rte_unused,
                   const struct rte_eth_txconf *tx_conf __rte_unused) {
    struct pmd_internals *internals = dev->data->dev_private;
    struct pkt_tx_queue *txq;

    // 只支持单队列，队列ID仅会为0
    if (tx_queue_id != 0) {
        MINI_XDP_LOG(ERR,
                     "Set up tx queue failed: id %d is not 0\n", tx_queue_id);
        return -EINVAL;
    }

    // tx_queue_id 一定只有0
    txq = &internals->tx_queues[tx_queue_id];

    dev->data->tx_queues[tx_queue_id] = txq;
    return 0;
}

// 设置接口的MTU
//  虽然是面向XDP的vdev设置的，但是实际上是对父接口生效
static int
eth_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu) {
    struct pmd_internals *internals = dev->data->dev_private;
    struct ifreq ifr = {.ifr_mtu = mtu};
    int ret;

    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -EINVAL;

    strlcpy(ifr.ifr_name, internals->if_name, IFNAMSIZ);
    ret = ioctl(fd, SIOCSIFMTU, &ifr);
    close(fd);

    return (ret < 0) ? -errno : 0;
}

static int
eth_dev_change_flags(char *if_name, uint32_t flags, uint32_t mask) {
    struct ifreq ifr;
    int ret = 0;
    int s;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -errno;

    strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        ret = -errno;
        goto out;
    }
    ifr.ifr_flags &= mask;
    ifr.ifr_flags |= flags;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        ret = -errno;
        goto out;
    }
    out:
    close(s);
    return ret;
}

// 启用混杂模式
static int
eth_dev_promiscuous_enable(struct rte_eth_dev *dev) {
    struct pmd_internals *internals = dev->data->dev_private;

    return eth_dev_change_flags(internals->if_name, IFF_PROMISC, ~0);
}

// 关闭混杂模式
static int
eth_dev_promiscuous_disable(struct rte_eth_dev *dev) {
    struct pmd_internals *internals = dev->data->dev_private;

    return eth_dev_change_flags(internals->if_name, 0, ~IFF_PROMISC);
}

// 注册到init_internals函数，vdev创建时会带上这些ops
static const struct eth_dev_ops ops = {
        .dev_start = eth_dev_start,
        .dev_stop = eth_dev_stop,
        .dev_close = eth_dev_close,
        .dev_configure = eth_dev_configure,
        .dev_infos_get = eth_dev_info,
        .mtu_set = eth_dev_mtu_set,
        .promiscuous_enable = eth_dev_promiscuous_enable,
        .promiscuous_disable = eth_dev_promiscuous_disable,
        .rx_queue_setup = eth_rx_queue_setup,
        .tx_queue_setup = eth_tx_queue_setup,
        .link_update = eth_link_update,
        .stats_get = eth_stats_get,
        .stats_reset = eth_stats_reset,
        .get_monitor_addr = eth_get_monitor_addr,
};

/* 获取接口上的通道数量
 * @max_queues: Read only. Maximum number of combined channel the driver
 *	support. Set of queues RX, TX or other.
 * @combined_queues: Valid values are in the range 1 to the max_combined.
 * @tx_queues: Valid values are in the range 1 to the max_tx.
 * @rx_queues: Valid values are in the range 1 to the max_rx.
 */
static int
xdp_get_channels_info(const char *if_name,
                      int *max_queues,
                      int *combined_queues,
                      int *tx_queues,
                      int *rx_queues) {
    struct ethtool_channels channels;
    struct ifreq ifr;
    int fd, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    channels.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data = (void *) &channels;
    strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ret) {
        // 如果不支持的话继续，认为是单队列
        if (errno == EOPNOTSUPP) {
            ret = 0;
        } else {
            ret = -errno;
            goto out;
        }
    }

    if (channels.max_combined == 0 || errno == EOPNOTSUPP) {
        /* If the device says it has no channels, then all traffic
         * is sent to a single stream, so max queues = 1.
         */
        *max_queues = 1;
        *combined_queues = 1;
        *tx_queues = 1;
        *rx_queues = 1;
    } else {
        *max_queues = channels.max_combined;
        *combined_queues = channels.combined_count;
        *tx_queues = channels.tx_count;
        *rx_queues = channels.rx_count;
    }

    out:
    close(fd);
    return ret;
}

// 设置接口上的通道数量
//  目前仅支持Rxq和Txq的设置，如果驱动不支持的话，则会返回-EOPNOTSUPP错误
static int
xdp_set_channels_info(const char *if_name,
                      int tx_queues,
                      int rx_queues) {
    struct ethtool_channels channels;
    struct ifreq ifr;
    int fd, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    // 先获取现有的通道信息
    channels.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data = (void *) &channels;
    strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ret) {
        ret = -errno;
        goto out;
    }

    // 设置提供的通道信息
    channels.tx_count = tx_queues;
    channels.rx_count = rx_queues;

    // 设置通道
    channels.cmd = ETHTOOL_SCHANNELS;
    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ret) {
        ret = -errno;
        goto out;
    }

    out:
    close(fd);
    return ret;
}

// 获取接口信息
static int
get_iface_info(const char *if_name,
               struct rte_ether_addr *eth_addr,
               int *if_index) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0)
        return -1;

    // 获取接口index id
    strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &ifr))
        goto error;
    *if_index = ifr.ifr_ifindex;

    // 获取接口mac地址
    if (ioctl(fd, SIOCGIFHWADDR, &ifr))
        goto error;
    rte_memcpy(eth_addr, ifr.ifr_hwaddr.sa_data, RTE_ETHER_ADDR_LEN);

    close(fd);
    return 0;

    error:
    close(fd);
    return -1;
}

#define ETH_MINI_XDP_IFACE_ARG "iface"
#define ETH_MINI_XDP_PROG_ARG  "xdp_prog"

static const char *const valid_arguments[] = {
        ETH_MINI_XDP_IFACE_ARG,
        ETH_MINI_XDP_PROG_ARG,
        NULL
};

// 解析int
static int
parse_integer_arg(const char *key __rte_unused,
                   const char *value, void *extra_args) {
    int *i = (int *) extra_args;
    char *end;

    *i = strtol(value, &end, 10);
    if (*i < 0) {
        MINI_XDP_LOG(ERR, "Argument has to be positive.\n");
        return -EINVAL;
    }

    return 0;
}

// 解析接口名称
static int
parse_name_arg(const char *key __rte_unused,
                const char *value, void *extra_args) {
    char *name = extra_args;

    if (strnlen(value, IFNAMSIZ) > IFNAMSIZ - 1) {
        MINI_XDP_LOG(ERR, "Invalid name %s, should be less than %u bytes.\n",
                     value, IFNAMSIZ);
        return -EINVAL;
    }

    strlcpy(name, value, IFNAMSIZ);

    return 0;
}

// 解析XDP内核程序位置
static int
parse_prog_arg(const char *key __rte_unused,
                const char *value, void *extra_args) {
    char *path = extra_args;

    if (strnlen(value, PATH_MAX) == PATH_MAX) {
        MINI_XDP_LOG(ERR, "Invalid path %s, should be less than %u bytes.\n",
                     value, PATH_MAX);
        return -EINVAL;
    }

    if (access(value, F_OK) != 0) {
        MINI_XDP_LOG(ERR, "Error accessing %s: %s\n",
                     value, strerror(errno));
        return -EINVAL;
    }

    strlcpy(path, value, PATH_MAX);

    return 0;
}

// 解析EAL参数
static int
parse_parameters(struct rte_kvargs *kvlist, char *if_name, char *prog_path) {
    int ret;

    ret = rte_kvargs_process(kvlist, ETH_MINI_XDP_IFACE_ARG, &parse_name_arg, if_name);
    if (ret < 0)
        goto free_kvlist;

    ret = rte_kvargs_process(kvlist, ETH_MINI_XDP_PROG_ARG, &parse_prog_arg, prog_path);
    if (ret < 0)
        goto free_kvlist;

    free_kvlist:
    rte_kvargs_free(kvlist);
    return ret;
}

static struct rte_eth_dev *
init_internals(struct rte_vdev_device *dev, const char *if_name, const char *prog_path) {
    const char *name = rte_vdev_device_name(dev);
    const unsigned int numa_node = dev->device.numa_node;
    struct pmd_internals *internals;
    struct rte_eth_dev *eth_dev;
    int ret;

    // 在指定NUMA node上分配内存
    internals = rte_zmalloc_socket(name, sizeof(struct pmd_internals), 0, numa_node);
    if (internals == NULL)
        return NULL;

    strlcpy(internals->if_name, if_name, IFNAMSIZ);
    strlcpy(internals->prog_path, prog_path, PATH_MAX);
    internals->custom_prog_configured = 0;

    int max_queue_count = 0;
    int combined_queue_count = 0;
    int tx_queues = 0;
    int rx_queues = 0;

    // 获取通道信息
    ret = xdp_get_channels_info(if_name, &max_queue_count, &combined_queue_count, &tx_queues, &rx_queues);
    // 如果不支持的话，则认为是单通道，可以正常运行
    if (ret == -EOPNOTSUPP) {
        MINI_XDP_LOG(INFO, "Device not support channels: %s\n", if_name);
        tx_queues = 1;
        rx_queues = 1;
    } else if (ret) {
        MINI_XDP_LOG(ERR, "Failed to get channel info of interface: %s\n", if_name);
        goto err_free_internals;
    }

    // 如果不是单通道（仅限Txq和Rxq）的话就设置一下
    if (tx_queues != 1 || rx_queues != 1) {
        ret = xdp_set_channels_info(if_name, 1, 1);
        if (ret) {
            MINI_XDP_LOG(ERR, "Device can not set to valid queue count: %s\n", if_name);
            goto err_free_internals;
        }
    }

    // 分配rx队列空间
    internals->rx_queues = rte_zmalloc_socket(NULL,
                                              sizeof(struct pkt_rx_queue) * rx_queues,
                                              0, numa_node);
    if (internals->rx_queues == NULL) {
        MINI_XDP_LOG(ERR,
                     "Failed to allocate memory for rx queues.\n");
        goto err_free_internals;
    }

    // 分配tx队列空间
    internals->tx_queues = rte_zmalloc_socket(NULL,
                                              sizeof(struct pkt_tx_queue) * tx_queues,
                                              0, numa_node);
    if (internals->tx_queues == NULL) {
        MINI_XDP_LOG(ERR,
                     "Failed to allocate memory for tx queues.\n");
        goto err_free_rx;
    }

    // 设置队列信息
    internals->tx_queues[0].pair = &internals->rx_queues[0];
    internals->rx_queues[0].pair = &internals->tx_queues[0];
    // 由于队列均只有一个，因xsk绑定队列都设置成0（首个队列）
    internals->rx_queues[0].xsk_queue_idx = 0;
    internals->tx_queues[0].xsk_queue_idx = 0;

    ret = get_iface_info(if_name, &internals->eth_addr,
                         &internals->if_index);
    if (ret)
        goto err_free_tx;

    // 新建vdev接口，配置沿用父接口
    eth_dev = rte_eth_vdev_allocate(dev, 0);
    if (eth_dev == NULL)
        goto err_free_tx;

    // PMD私有数据
    eth_dev->data->dev_private = internals;
    // 接口状态等信息
    eth_dev->data->dev_link = pmd_link;
    eth_dev->data->mac_addrs = &internals->eth_addr;
    eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;
    // 设置handle
    eth_dev->dev_ops = &ops;
    // 注册收包句柄
    eth_dev->rx_pkt_burst = eth_af_xdp_rx;
    // 注册发包句柄
    eth_dev->tx_pkt_burst = eth_af_xdp_tx;

    return eth_dev;

    err_free_tx:
    rte_free(internals->tx_queues);
    err_free_rx:
    rte_free(internals->rx_queues);
    err_free_internals:
    rte_free(internals);
    return NULL;
}

// 初始化驱动接口
static int
rte_pmd_mini_xdp_probe(struct rte_vdev_device *dev) {
    struct rte_kvargs *kvlist;
    char if_name[IFNAMSIZ] = {'\0'};
    char prog_path[PATH_MAX] = {'\0'};
    struct rte_eth_dev *eth_dev = NULL;
    const char *name = rte_vdev_device_name(dev);

    MINI_XDP_LOG(INFO,
                 "Initializing pmd_mini_xdp for %s\n",
                 name);

    // 不允许启动第二个实例
    // miniXDP单队列，没有并行的意义
    if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
        MINI_XDP_LOG(ERR,
                     "Failed to probe %s. MINI_XDP PMD does not support secondary processes.\n",
                     name);
        return -ENOTSUP;
    }

    // 解析参数
    kvlist = rte_kvargs_parse(rte_vdev_device_args(dev), valid_arguments);
    if (kvlist == NULL) {
        MINI_XDP_LOG(ERR,
                     "Invalid kvargs key\n");
        return -EINVAL;
    }

    // 把设备绑定到与当前运行核相同的物理socket上
    if (dev->device.numa_node == SOCKET_ID_ANY)
        dev->device.numa_node = rte_socket_id();

    // 解析参数
    if (parse_parameters(kvlist, if_name, prog_path) < 0) {
        MINI_XDP_LOG(ERR,
                     "Invalid kvargs value\n");
        return -EINVAL;
    }

    if (strlen(if_name) == 0) {
        MINI_XDP_LOG(ERR,
                     "Network interface must be specified\n");
        return -EINVAL;
    }

    // 生成vdev设备
    eth_dev = init_internals(dev, if_name, prog_path);
    if (eth_dev == NULL) {
        MINI_XDP_LOG(ERR,
                     "Failed to init device internals\n");
        return -1;
    }

    // 收尾操作
    rte_eth_dev_probing_finish(eth_dev);

    return 0;
}

// 移除驱动接口
static int
rte_pmd_mini_xdp_remove(struct rte_vdev_device *dev) {
    struct rte_eth_dev *eth_dev = NULL;

    MINI_XDP_LOG(INFO, "Removing MINI_XDP ethdev on numa socket %u\n",
                 rte_socket_id());

    if (dev == NULL)
        return -1;

    /* find the ethdev entry */
    eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(dev));
    if (eth_dev == NULL)
        return 0;

    eth_dev_close(eth_dev);
    rte_eth_dev_release_port(eth_dev);

    return 0;
}

static struct rte_vdev_driver pmd_mini_xdp_drv = {
        .probe = rte_pmd_mini_xdp_probe,
        .remove = rte_pmd_mini_xdp_remove,
};
RTE_PMD_REGISTER_VDEV(net_mini_xdp, pmd_mini_xdp_drv);
RTE_PMD_REGISTER_PARAM_STRING(net_mini_xdp, "iface=<string> xdp_prog=<string> ");
