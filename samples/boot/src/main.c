/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <zephyr.h>
#include <flash.h>
#include <device.h>
#include <misc/printk.h>
#include <asm_inline.h>

#include <boot_config.h>
#include <boot/update.h>
#include <boot/chain_boot.h>

void main(void)
{
	struct device *flash_dev;
	void *base;

	printk("------------------------------------------------------------\n");
	printk("Bootloader on %s\n", CONFIG_ARCH);

	flash_dev = device_get_binding(BOOT_FLASH_DEVICE);
	if (!flash_dev) {
		printk(BOOT_FLASH_DEVICE " flash device not found\n");
		while (1)
			;
	}

	/*
	 * Determine if there is a bootable image.
	 */
	base = boot_find_image(flash_dev);
	printk("Boot: %p\n", base);
	chain_boot(base);
}
