/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <sys/printk.h>
#include <storage/flash_map.h>

void showit(uintptr_t offset) {
	uint32_t *addr = (uint32_t *)offset;
	printk("Fetching from %p\n", addr);
	uint32_t value = *addr;
	printk("    Got: 0x%08x\n", value);
}

#if 0
void flashy(void) {
	int ret;
	const struct flash_area *fa;

	ret = flash_area_open(SOC_FLASH_0_ID, &fa);
	printk("flash_area_open: %d\n", ret);
	if (ret != 0) {
		return;
	}
}
#endif

void main(void)
{
	printk("Hello World! %s\n", CONFIG_BOARD);
	printk("MPU: 0x%08x\n", *((uint32_t *) 0xe000ed94));

	// flashy();
#if 0
	/* Try disabling the MPU */
	// *((uint32_t *) 0xe000ed94) = 0;
	printk("MPU: 0x%08x\n", *((uint32_t *) 0xe000ed94));
	for (uintptr_t offset = 4; offset < 0x80000; offset *= 2) {
		showit(offset);
	}
#endif
#if 0
	showit(0);
	showit(0x0fff8);
	showit(0x10000);
	showit(0x12000);
	showit(0x20000);
	showit(0x22000);
#endif
}
