#ifndef MINI_XDP_DEPS_H_
#define MINI_XDP_DEPS_H_

#include <rte_atomic.h>
#include <rte_branch_prediction.h>

/* This is to fix the xsk.h's dependency on asm/barrier.h */
#define smp_rmb() rte_rmb()
#define smp_wmb() rte_wmb()

#endif /* MINI_XDP_DEPS_H_ */
