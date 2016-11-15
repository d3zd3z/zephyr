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

#include "image_validate.h"

/*
 * This matches the ARM vector table.
 */
struct vector_table {
	uint32_t msp;
	uint32_t reset;
};

/*
 * Flash configuration.  Once we know what is going on here, this
 * should be made into an API that multiple flash devices can
 * implement. */
static const struct flash_map {
	uint32_t start;
	uint32_t len;
} sectors[] = {
	{ .start = 0x00000000 , .len = KB(16) },
	{ .start = 0x00004000 , .len = KB(16) },
	{ .start = 0x00008000 , .len = KB(16) },
	{ .start = 0x0000c000 , .len = KB(16) },
	{ .start = 0x00010000 , .len = KB(64) },
	{ .start = 0x00020000 , .len = KB(128) },
	{ .start = 0x00040000 , .len = KB(128) },
	{ .start = 0x00060000 , .len = KB(128) },
};

/*
 * However, for the bootloader's flash programming, we aren't really
 * interested in generic use of flash, but instead what is available
 * for the bootloader. */
#if 1
/* The flash device in use. */
#define BOOT_FLASH_DEVICE "STM32F4_FLASH"

/* The offset of the flash memory, in the CPUs address space. */
#define BOOT_FLASH_BASE   0x08000000

/* The offset and size, from the base of the flash, of the primary
 * flash code segment. */
#define FLASH_PRIMARY_BASE  0x00020000
#define FLASH_PRIMARY_SIZE  KB(128)

/* The offset and size of the upgrade flash segment. */
#define FLASH_UPGRADE_BASE  0x00040000
#define FLASH_UPGRADE_SIZE  KB(128)
#endif

#if 0
static void tflash()
{
	struct device *flash_dev;
	int rc;

	flash_dev = device_get_binding("STM32F4_FLASH");
	if (!flash_dev) {
		printk("STM32F4 flash drive not found\n");
		return;
	}
	printk("flash at %p\n", flash_dev);

	rc = flash_erase(flash_dev, 0x00060000, KB(128));
	if (rc < 0) {
		printk("  erase FAIL: %d\n", rc);
	} else {
		printk("  erase PASS\n");
	}
}
#endif

static void find_bootable()
{
	int primary_good;
	int upgrade_good;

	primary_good = bootutil_img_validate(FLASH_PRIMARY_BASE +
					     BOOT_FLASH_BASE);
	printk("primary good: %d\n", primary_good);

	upgrade_good = bootutil_img_validate(FLASH_UPGRADE_BASE +
					     BOOT_FLASH_BASE);
	printk("upgrade good: %d\n", upgrade_good);
}

void main(void)
{
	typedef void jump_fn(void);
	struct vector_table *vt;
	jump_fn *fn;

	printk("------------------------------------------------------------\n");
	printk("Bootloader on %s\n", CONFIG_ARCH);

	find_bootable();

	// tflash();

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
}
