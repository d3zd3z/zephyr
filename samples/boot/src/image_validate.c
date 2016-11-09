/*
 * ??? TODO: Fix license for Zephyr inclusion.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <zephyr.h>
#include <misc/printk.h>
#include <boot/signature_header.h>
#include <mbedtls/sha256.h>

#include "image_validate.h"
#include "image_rsa.h"
#include "image_ec.h"

/** Indicates that no image is present. */
#define NO_IMAGE 0

/**
 * @brief Search for an image signature.
 *
 * Given a particular flash base address, determine if there is a
 * potentially signed image at that address.  Returns the offset of
 * the signature if there is a valid image at `flash_base`.  If there
 * is no image, returns 0.
 */
static uintptr_t find_signature(uintptr_t flash_base)
{
	struct signature_header *head;
	uintptr_t base;

	/**
	 * TODO: We need to make sure that the image is entirely
	 * contained within the flash (possibly this sector, or even
	 * greater depth).
	 */
	head = (struct signature_header *)
		(flash_base + SIGNATURE_HEADER_OFFSET);
	printk("Head: %p\n", head);
	if (head->magic1 != SIGNATURE_HEADER_MAGIC1 ||
	    head->magic2 != SIGNATURE_HEADER_MAGIC2)
		return NO_IMAGE;
	printk("rom_start      = 0x%x\n", head->rom_start);
	printk("rom_end        = 0x%x\n", head->rom_end);
	printk("data_rom_start = 0x%x\n", head->data_rom_start);
	printk("data_ram_start = 0x%x\n", head->data_ram_start);
	printk("data_ram_end   = 0x%x\n", head->data_ram_end);

	base = head->data_rom_start;
	base += (head->data_ram_end - head->data_ram_start);
	printk("Base: 0x%x\n", base);
	return base;
}

/**
 * @brief compute SHA256 hash of image.
 *
 * @param flash_base The base address of the image
 * @param sig_base   The start address of the signature
 * @param hash_out   The 32-bytes of the computed hash.
 *
 * The image is assumed to occupy the space between the flash_base and
 * the sig_base.
 */
static void img_hash(uintptr_t flash_base, uintptr_t sig_base,
		     uint8_t *hash_out)
{
	mbedtls_sha256_context ctx;

	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);

	mbedtls_sha256_update(&ctx, (const uint8_t *)flash_base,
			      sig_base - flash_base);
	mbedtls_sha256_finish(&ctx, hash_out);
	mbedtls_sha256_free(&ctx);
}

int
bootutil_img_validate(uintptr_t flash_base)
{
	uintptr_t sig_base;
	uint8_t hash[32];
	int i;
	int rc;

	sig_base = find_signature(flash_base);
	if (sig_base == NO_IMAGE)
		return -1;

	img_hash(flash_base, sig_base, hash);
	rc = bootutil_ec_verify_sig(hash, 32, (uint8_t *)sig_base, 256, 0);
	printk("Bootutil verify: %d\n", rc);

	for (i = 0; i < 32; i++)
		printk(" %x", hash[i]);
	printk("\n");

	return 0;
}
