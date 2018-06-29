/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <misc/printk.h>
#include <time.h>

void main(void)
{
	printk("Hello World! %s\n", CONFIG_ARCH);

	time_t now = time(NULL);
	printk("Time gotten is %ld\n", now);
}
