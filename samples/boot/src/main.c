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

void main(void)
{
	typedef void jump_fn(void);
	struct vector_table *vt;
	jump_fn *fn;
	struct device *flash_dev;

	printk("------------------------------------------------------------\n");
	printk("Bootloader on %s\n", CONFIG_ARCH);

	flash_dev = device_get_binding(BOOT_FLASH_DEVICE);
	if (!flash_dev) {
		printk(BOOT_FLASH_DEVICE " flash device not found\n");
		while (1)
			;
	}

	printk("This is where we would then boot\n");

	/*
	 * Determine if there is a bootable image.
	 */
	if (bootutil_img_validate(BOOT_FLASH_BASE + FLASH_PRIMARY_BASE)) {
		printk("No bootable image\n");
		while (1)
			;
	}

#if 0
	find_bootable(flash_dev);

	// tflash();

	/* Let's print out the beginning of each sector. */
#if 0
	{
		int i;
		for (i = 0; i < ARRAY_SIZE(sectors); i++) {
			printk("Flash sector 0x%x\n", sectors[i].start);
			pdump((void *)sectors[i].start, 64);
		}
	}
#endif

	if (bootutil_img_validate(0x08020000)) {
		printk("Image doesn't validate\n");
		while (1)
			;
	}

	vt = (struct vector_table *)0x08020000;
	printk("Initial MSP: %p\n", (void *)vt->msp);
	printk("      Reset: %p\n", (void *)vt->reset);

	_MspSet(vt->msp);
	fn = (jump_fn *)vt->reset;
	fn();
#endif
}
