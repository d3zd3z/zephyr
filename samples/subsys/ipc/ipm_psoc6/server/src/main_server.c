/*
 * Copyright (c) 2018, Cypress Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr.h>

#include "cy_sysint.h"
#include "cy_wdt.h"
#include <ipm.h>
#include <device.h>
#include <init.h>
#include <misc/printk.h>
#include <string.h>

#define SLEEP_TIME 10000

void message_ipm_notify_callback(void *context, u32_t id, volatile void *data)
{
	u32_t *data32 = (u32_t *)data;

	printk("Received %u via IPC\n", *data32);
}

void main(void)
{
	struct device *ipm;

	/* Disable watchdog */
	Cy_WDT_Unlock();
	Cy_WDT_Disable();

	ipm = device_get_binding(PSOC6_IPM7_LABEL);
	ipm_register_callback(ipm, message_ipm_notify_callback, NULL);
	ipm_set_enabled(ipm, 1);

	printk("PSoC6 IPM Server example has started\n");

	/* Enable CM4 */
	Cy_SysEnableCM4(CONFIG_SLAVE_BOOT_ADDRESS_PSOC6);

	while (1) {
		k_sleep(SLEEP_TIME);
	}
}
