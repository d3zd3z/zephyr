/*
 * Copyright (c) 2018, Cypress Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cy_sysint.h"
#include <misc/printk.h>
#include <zephyr.h>
#include <ipm.h>

#define SLEEP_TIME 2000

void message_ipm_release_callback(void *context, u32_t id, volatile void *data)
{
	int *flag = context;

	printk("Received Release acknowledge via IPC\n");
	*flag = 1;
}

void main(void)
{
	struct device *ipm;
	int ipm_error;
	int flag = 1;
	u32_t counter = 0;

	ipm = device_get_binding(PSOC6_IPM7_LABEL);
	ipm_register_callback(ipm, message_ipm_release_callback, &flag);

	printk("PSoC6 IPM Client example has started\n");

	while (1) {
		if (flag) {
			flag = 0;
			printk("sending messages \" %u \" to CM0p\n", counter);
			ipm_error = ipm_send(ipm, 1, 0, &counter, 4);

			if (ipm_error != 0) {
				printk("ipm_send returned error %i\n",
					ipm_error);
			}
			counter++;
		}
		k_sleep(SLEEP_TIME);
	}
}

