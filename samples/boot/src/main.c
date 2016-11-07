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
#include <misc/printk.h>
#include <asm_inline.h>
#include <boot/signature_header.h>

#include <mbedtls/sha256.h>

/*
 * This matches the ARM vector table.
 */
struct vector_table {
	uint32_t msp;
	uint32_t reset;
};

uint8_t hash[32];

static void find_signature(uintptr_t flash_base)
{
	struct signature_header *head;
	uintptr_t base;

	head = (struct signature_header *)
		(flash_base + SIGNATURE_HEADER_OFFSET);
	printk("Head: %p\n", head);
	if (head->magic1 != SIGNATURE_HEADER_MAGIC1 ||
	    head->magic2 != SIGNATURE_HEADER_MAGIC2)
		return;
	printk("rom_start      = 0x%x\n", head->rom_start);
	printk("rom_end        = 0x%x\n", head->rom_end);
	printk("data_rom_start = 0x%x\n", head->data_rom_start);
	printk("data_ram_start = 0x%x\n", head->data_ram_start);
	printk("data_ram_end   = 0x%x\n", head->data_ram_end);

	base = head->data_rom_start;
	base += (head->data_ram_end - head->data_ram_start);
	printk("Base: 0x%x\n", base);
	printk("Checking signature: %p, len=0x%x\n",
	       (void *)flash_base,
	       base - flash_base);
	{
		mbedtls_sha256_context ctx;

		mbedtls_sha256_init(&ctx);
		mbedtls_sha256_starts(&ctx, 0);
		mbedtls_sha256_update(&ctx, (const uint8_t *)flash_base,
				      base - flash_base);
		mbedtls_sha256_finish(&ctx, hash);
		mbedtls_sha256_free(&ctx);
	}
	printk("Done, sig at %p\n", hash);
	for (;;)
		;
}

void main(void)
{
	typedef void jump_fn(void);
	struct vector_table *vt;
	jump_fn *fn;

	printk("Bootloader on %s\n", CONFIG_ARCH);

	find_signature(0x08020000);

	vt = (struct vector_table *)0x08020000;
	printk("Initial MSP: %p\n", (void *)vt->msp);
	printk("      Reset: %p\n", (void *)vt->reset);

	_MspSet(vt->msp);
	fn = (jump_fn *)vt->reset;
	fn();
}
