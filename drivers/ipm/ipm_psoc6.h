/*
 * Copyright (c) 2018, Cypress Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#ifndef __IPM_PSOC6__
#define __IPM_PSOC6__

#include <kernel.h>
#include <ipm.h>
#include <device.h>
#include <init.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PSOC6_IPM_MAX_ID_VAL (0)
#define PSOC6_IPM_MAX_CHANNEL (15)


#if defined(CONFIG_SOC_PSOC6_M0)

#define PSOC6_IPM_INT_BASE PSOC6_IPM7_IRQ_SRV_BASE
#define PSOC6_IPM_ROLE (PSOC6_IPM_SERVER)
#define PSOC6_IPM_SRV_INT (PSOC6_IPM_INT_BASE)
#define PSOC6_IPM_CLNT_INT (PSOC6_IPM_INT_BASE)

#else

#define PSOC6_IPM_INT_BASE PSOC6_IPM7_IRQ_CLIENT_BASE
#define PSOC6_IPM_ROLE (PSOC6_IPM_CLIENT)
#define PSOC6_IPM_SRV_INT (PSOC6_IPM_INT_BASE + \
DT_PSOC6_IPM_NOTIFY_INT_CHANNEL)
#define PSOC6_IPM_CLNT_INT (PSOC6_IPM_INT_BASE + \
DT_PSOC6_IPM_RELEASE_INT_CHANNEL)

#endif

#ifdef __cplusplus
}
#endif

#endif /* __IPM_PSOC6__ */
