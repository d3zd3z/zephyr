/*
 * Copyright (c) 2018, Cypress Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <device.h>
#include <string.h>
#include <ipm.h>
#include <soc.h>
#include "cy_sysint.h"
#include "cy_ipc_drv.h"
#include "ipm_psoc6.h"

enum psoc6_ipm_instance_role {
	PSOC6_IPM_SERVER = 0,
	PSOC6_IPM_CLIENT = 1
};

struct psoc6_ipm_config_t {
	u32_t channel;
	s32_t int_base;
	s32_t notify_chn;
	s32_t release_chn;
	enum psoc6_ipm_instance_role role;
};

struct psoc6_ipm_data {
	ipm_callback_t callback;
	void *callback_ctx;
};

static void psoc6_ipm_notify_isr(void *arg)
{
	struct device *dev = arg;
	struct psoc6_ipm_data *data = dev->driver_data;
	const struct psoc6_ipm_config_t *config = dev->config->config_info;
	u32_t value;
	u32_t interrupt_masked;

	/*
	 * Check that there is really the IPC Notify interrupt,
	 * because the same line can be used for the IPC Release interrupt.
	 */
	interrupt_masked = Cy_IPC_Drv_ExtractAcquireMask(
		Cy_IPC_Drv_GetInterruptStatusMasked(
			Cy_IPC_Drv_GetIntrBaseAddr(config->notify_chn)));

	if (interrupt_masked == (1uL << config->channel)) {
		Cy_IPC_Drv_ClearInterrupt(
			Cy_IPC_Drv_GetIntrBaseAddr(config->notify_chn),
				CY_IPC_NO_NOTIFICATION, interrupt_masked);

		if (Cy_IPC_Drv_ReadMsgWord(
			Cy_IPC_Drv_GetIpcBaseAddress(config->channel),
				&value) == CY_IPC_DRV_SUCCESS) {
			if (data->callback) {
				data->callback(data->callback_ctx, 0, &value);
			}
		/* Release the REE IPC channel with the Release interrupt */
			Cy_IPC_Drv_LockRelease(
				Cy_IPC_Drv_GetIpcBaseAddress(config->channel),
				(1uL << config->release_chn));
		}
	}
}

static void psoc6_ipm_release_isr(void *arg)
{
	struct device *dev = arg;
	struct psoc6_ipm_data *data = dev->driver_data;
	const struct psoc6_ipm_config_t *config = dev->config->config_info;
	u32_t interrupt_masked;

	interrupt_masked = Cy_IPC_Drv_ExtractReleaseMask(
		Cy_IPC_Drv_GetInterruptStatusMasked(
			Cy_IPC_Drv_GetIntrBaseAddr(config->release_chn)));

	if ((interrupt_masked & (1uL << config->channel)) != 0u) {
		Cy_IPC_Drv_ClearInterrupt(
			Cy_IPC_Drv_GetIntrBaseAddr(config->release_chn),
			(1uL << config->channel), CY_IPC_NO_NOTIFICATION);

		if (data->callback) {
			data->callback(data->callback_ctx, 0, NULL);
		}
	}
}

static int psoc6_ipm_send(struct device *d, int wait, u32_t id,
			const void *data, int size)
{
	const struct psoc6_ipm_config_t *config = d->config->config_info;
	IPC_STRUCT_Type *ipc_base;
	cy_en_ipcdrv_status_t ipc_status;
	u32_t data32;
	int flags;

	ipc_base = Cy_IPC_Drv_GetIpcBaseAddress(config->channel);

	if (id > PSOC6_IPM_MAX_ID_VAL) {
		return -EINVAL;
	}

	if (config->role != PSOC6_IPM_CLIENT) {
		return -EINVAL;
	}

	if (size > sizeof(u32_t)) {
		return -EMSGSIZE;
	}

	/* Mutex is required to lock other tasks until we confirm that there are
	 * no errors
	 */
	flags = irq_lock();

	/* Attempt to acquire the IPC channel by reading the IPC_ACQUIRE
	 * register. If the channel was acquired, the REE has ownership of the
	 * channel for data transmission.
	 */
	ipc_status = Cy_IPC_Drv_LockAcquire(ipc_base);
	if (ipc_status != CY_IPC_DRV_SUCCESS) {
		irq_unlock(flags);
		return -EBUSY;
	}

	memcpy(&data32, data, size);
	Cy_IPC_Drv_WriteDataValue(ipc_base, data32);
	/* Generates a notify event on the TEE interrupt line.*/
	Cy_IPC_Drv_AcquireNotify(ipc_base, (1uL << config->notify_chn));

	irq_unlock(flags);

	if (wait) {
		/* Loop until remote clears the status bit */
		while (Cy_IPC_Drv_IsLockAcquired(ipc_base)) {
		}
	}

	return 0;
}

static int psoc6_ipm_max_data_size_get(struct device *d)
{
	ARG_UNUSED(d);

	return sizeof(u32_t);
}

static u32_t psoc6_ipm_max_id_val_get(struct device *d)
{
	ARG_UNUSED(d);

	return PSOC6_IPM_MAX_ID_VAL;
}

static void psoc6_ipm_register_callback(struct device *d,
						ipm_callback_t cb,
						void *context)
{
	struct psoc6_ipm_data *driver_data = d->driver_data;

	driver_data->callback = cb;
	driver_data->callback_ctx = context;
}

static int psoc6_ipm_set_enabled(struct device *d, int enable)
{
	return 0;
}

static void psoc6_ipm_server_init(const struct psoc6_ipm_config_t *config);
static void psoc6_ipm_client_init(const struct psoc6_ipm_config_t *config);

static int psoc6_ipm_init(struct device *dev)
{
	const struct psoc6_ipm_config_t *config = dev->config->config_info;

	if (config->role == PSOC6_IPM_SERVER) {
		psoc6_ipm_server_init(config);
	} else {
		psoc6_ipm_client_init(config);
	}

	return 0;
}

const struct ipm_driver_api psoc6_ipm_api_funcs = {
	.send = psoc6_ipm_send,
	.register_callback = psoc6_ipm_register_callback,
	.max_data_size_get = psoc6_ipm_max_data_size_get,
	.max_id_val_get = psoc6_ipm_max_id_val_get,
	.set_enabled = psoc6_ipm_set_enabled
};

struct psoc6_ipm_config_t psoc6_ipm_config_cm0_srv = {
	.channel = DT_PSOC6_IPM_CHANNEL,
	.int_base = PSOC6_IPM_INT_BASE,
	.notify_chn = DT_PSOC6_IPM_NOTIFY_INT_CHANNEL,
	.release_chn = DT_PSOC6_IPM_RELEASE_INT_CHANNEL,
	.role = PSOC6_IPM_ROLE
};

struct psoc6_ipm_data psoc6_ipm_data_cm0_srv;

DEVICE_AND_API_INIT(mailbox_7, PSOC6_IPM7_LABEL,
	psoc6_ipm_init,
	&psoc6_ipm_data_cm0_srv,
	&psoc6_ipm_config_cm0_srv,
	PRE_KERNEL_1, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
	&psoc6_ipm_api_funcs);

static void psoc6_ipm_server_init(const struct psoc6_ipm_config_t *config)
{
#if defined(CONFIG_SOC_PSOC6_M0)
	if (config->int_base > SysTick_IRQn) {
		/* Configure the interrupt mux */
		Cy_SysInt_SetInterruptSource(config->int_base,
			(cy_en_intr_t)CY_IPC_INTR_NUM_TO_VECT(
				(int32_t)config->notify_chn));
	}
#endif
	Cy_IPC_Drv_SetInterruptMask(
		Cy_IPC_Drv_GetIntrBaseAddr(config->notify_chn),
		CY_IPC_NO_NOTIFICATION, (1uL << config->channel));

	IRQ_CONNECT(PSOC6_IPM_SRV_INT,
			PSOC6_IPM7_IRQ_SRV_BASE_PRIORITY,
			psoc6_ipm_notify_isr, DEVICE_GET(mailbox_7), 0);

	irq_enable(PSOC6_IPM_SRV_INT);
}

static void psoc6_ipm_client_init(const struct psoc6_ipm_config_t *config)
{
#if defined(CONFIG_SOC_PSOC6_M0)
	if (config->int_base > SysTick_IRQn) {
		/* Configure the interrupt mux */
		Cy_SysInt_SetInterruptSource(config->int_base,
			(cy_en_intr_t)CY_IPC_INTR_NUM_TO_VECT(
				(int32_t)config->release_chn));
	}
#endif
	Cy_IPC_Drv_SetInterruptMask(
		Cy_IPC_Drv_GetIntrBaseAddr(config->release_chn),
		(1uL << config->channel), CY_IPC_NO_NOTIFICATION);

	IRQ_CONNECT(PSOC6_IPM_CLNT_INT,
		PSOC6_IPM7_IRQ_CLIENT_BASE_PRIORITY,
		psoc6_ipm_release_isr, DEVICE_GET(mailbox_7), 0);

	irq_enable(PSOC6_IPM_CLNT_INT);
}
