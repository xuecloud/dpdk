#include <bpf/xsk.h>
#include <poll.h>

#ifdef XDP_USE_NEED_WAKEUP
static int
tx_syscall_needed(struct xsk_ring_prod *q) {
	return xsk_ring_prod__needs_wakeup(q);
}
#else
static int
tx_syscall_needed(struct xsk_ring_prod *q __rte_unused) {
	return 1;
}
#endif
