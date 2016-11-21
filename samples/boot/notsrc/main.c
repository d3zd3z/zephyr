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
#include "pdump.h"

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

/* The offset and size of the scratch segment.  This initial
 * implementation assumes the segments are erased and flashed in their
 * entirety. */
#define FLASH_SCRATCH_BASE 0x00060000
#define FLASH_SCRATCH_SIZE KB(128)
#endif

/* The offset and size of the recovery flash segment. */

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

/*
 * For devices with large sectors (where the segments are programmed
 * in their entirety, and the scratch area is large enough to hold a
 * full code segment, programming proceeds through various states.
 */

struct segment_state {
	uint32_t magic_head;
	uint8_t  state[8];
	uint32_t magic_tail;
};

#define SEGMENT_MAGIC_HEAD 0xef0db758
#define SEGMENT_MAGIC_TAIL 0x22d596d0

/*
 * Verify that the given memory contains all 0xFFs (unprogrammed)
 */
static bool all_ffs(const void *base, size_t len)
{
	const uint8_t *ptr = base;

	while (len--) {
		if (*(ptr++) != 0xFF)
			return false;
	}

	return true;
}

static void get_segment_state(struct device *flash_dev,
			      uintptr_t base, size_t len)
{
	int rc;
	struct segment_state seg;
	const uintptr_t seg_base = base + len - sizeof(struct segment_state);

	rc = flash_read(flash_dev,
			seg_base,
			&seg, sizeof(seg));
	if (rc != 0) {
		printk("Error reading from flash: %d\n", rc);
		return;
	}

	/* If the segment state is not programmed, create an initial
	 * one. */
	if (all_ffs(&seg, sizeof(seg))) {
		printk("Segment is unprogrammed\n");
		seg.magic_head = SEGMENT_MAGIC_HEAD;
		seg.magic_tail = SEGMENT_MAGIC_TAIL;

		rc = flash_write_protection_set(flash_dev, false);
		if (rc != 0) {
			printk("Error disabling write protection\n");
			return;
		}

		rc = flash_write(flash_dev,
				 seg_base,
				 &seg, sizeof(seg));
		if (rc != 0) {
			printk("Error writing segment data\n");
			return;
		}
	}

	if (seg.magic_head != SEGMENT_MAGIC_HEAD ||
	    seg.magic_tail != SEGMENT_MAGIC_TAIL) {
		printk("Segment state is corrupt, considering block corrupt\n");
		return;
	}

	printk("Segment magic head=%x, tail=%x\n", seg.magic_head,
	       seg.magic_tail);
}

static void find_bootable(struct device *flash_dev)
{
	int primary_good;
	int upgrade_good;
	int scratch_good;
	int rc;

	primary_good = bootutil_img_validate(FLASH_PRIMARY_BASE +
					     BOOT_FLASH_BASE);
	printk("primary good: %d\n", primary_good);

	upgrade_good = bootutil_img_validate(FLASH_UPGRADE_BASE +
					     BOOT_FLASH_BASE);
	printk("upgrade good: %d\n", upgrade_good);

	scratch_good = bootutil_img_validate(FLASH_SCRATCH_BASE +
					     BOOT_FLASH_BASE);
	printk("scratch good: %d\n", scratch_good);

	get_segment_state(flash_dev, FLASH_PRIMARY_BASE, FLASH_PRIMARY_SIZE);

	/*
	 * If there is a valid update image, start the process of
	 * loading it into the primary segment.  This step can be
	 * interrupted at any time, because we will not have erased
	 * the upgrade segment.
	 */
	if (upgrade_good == 0) {
		rc = flash_write_protection_set(flash_dev, false);
		if (rc != 0) {
			printk("Error disabling write protection\n");
			return;
		}

		/*
		 * TODO: Add support for small sectors.  Right now, we
		 * assume the entire segment is a single erasable
		 * region.  In the simple case, this should erase the
		 * entire region.
		 */
		printk("Upgrade: Erasing primary segment\n");
		rc = flash_erase(flash_dev, FLASH_PRIMARY_BASE,
				 FLASH_PRIMARY_SIZE);
		if (rc != 0) {
			printk("Error erasing primary segment\n");
			return;
		}

		/*
		 * It is device specific whether it is possible to
		 * read from segments other than the one we are
		 * writing to.  For now, just support the simple case
		 * where that is possible.
		 */
		rc = flash_write_protection_set(flash_dev, false);
		if (rc != 0) {
			printk("Error disabling write protection\n");
			return;
		}

		printk("Upgrade: Writing code in primary segment\n");
		rc = flash_write(flash_dev, FLASH_PRIMARY_BASE,
				 (void *)(FLASH_UPGRADE_BASE + BOOT_FLASH_BASE),
				 FLASH_PRIMARY_SIZE);
		if (rc != 0) {
			printk("Error writing primary segment\n");
			return;
		}

		/*
		 * Now that the primary segment has been written, it
		 * is safe to erase the upgrade segment.
		 *
		 * TODO: Perhaps we should verify the signature of the
		 * boot segment.
		 */
		rc = flash_write_protection_set(flash_dev, false);
		if (rc != 0) {
			printk("Error disabling write protection\n");
			return;
		}

		printk("Upgrade: Erasing upgrade\n");
		rc = flash_erase(flash_dev, FLASH_UPGRADE_BASE,
				 FLASH_UPGRADE_SIZE);
		if (rc != 0) {
			printk("Error erasing upgrade segment\n");
			return;
		}
	}
}

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
}
