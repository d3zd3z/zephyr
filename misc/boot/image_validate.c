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
#include <string.h>

#include <boot/image_validate.h>

#ifdef CONFIG_BOOT_VERIFY_RSA_SIGNATURE
#include <boot/image_rsa.h>
#endif
#ifdef CONFIG_BOOT_VERIFY_ECDSA_SIGNATURE
#include <boot/image_ec.h>
#endif

static const char magic[8] = "zSiGnata";

#if !defined(CONFIG_BOOT_VERIFY_RSA_SIGNATURE) && \
	!defined(CONFIG_BOOT_VERIFY_ECDSA_SIGNATURE)
#error "Bootloader must select at least one signature type"
#endif

struct signature_types {
	uint8_t algo;
	uint8_t hash;
	int (*verify)(uint8_t *hash, uint32_t hlen,
		      struct image_signature *sig,
		      uint8_t key_id);
};
static const struct signature_types signature_types[] = {
#ifdef CONFIG_BOOT_VERIFY_RSA_SIGNATURE
	{
		.algo = SIG_ALGO_RSA,
		.hash = SIG_HASH_SHA256,
		.verify = bootutil_rsa_verify_sig,
	},
#endif
#ifdef CONFIG_BOOT_VERIFY_ECDSA_SIGNATURE
	{
		.algo = SIG_ALGO_ECDSA,
		.hash = SIG_HASH_SHA256,
		.verify = bootutil_ec_verify_sig,
	},
#endif
};

/* Externs for the allocator from mbedtls. */
extern void *(*mbedtls_calloc)(size_t n, size_t size);
extern void (*mbedtls_free)(void *ptr);

/**
 * @brief Bootloader calloc.
 *
 * This calls into Zephyr's heap allocator.
 */
static void *boot_calloc(size_t n, size_t size)
{
	size_t total = n * size;
	void *buf = k_malloc(total);
	if (!buf) {
		printk("Failure to allocate %d bytes\n", total);
		return 0;
	}
	// printk("boot_calloc: %d = %p\n", total, buf);
	memset(buf, 0, total);
	return buf;
}

/**
 * @brief Bootloader free
 *
 * Calls into Zephyr's heap allocator.
 */
static void boot_free(void *ptr)
{
	k_free(ptr);
}

/**
 * @brief Initialize mbedTLS allocator for bootloader
 */
static void init_boot_alloc(void)
{
	mbedtls_calloc = boot_calloc;
	mbedtls_free = boot_free;
}


/**
 * @brief Search for an image signature.
 *
 * Given a particular flash base address, determine if there is a
 * potentially signed image at that address.  Returns the offset of
 * the signature if there is a valid image at `flash_base`.  If there
 * is no image, returns NO_IMAGE.  *image_size will be set to the
 * image size in bytes.
 */
static struct image_signature *find_signature(uintptr_t flash_base,
					      size_t *image_size)
{
	struct signature_header *head;
	struct image_signature *sig;
	uintptr_t base;

	/**
	 * TODO: We need to make sure that the image is entirely
	 * contained within the flash (possibly this sector, or even
	 * greater depth).
	 */
	head = (struct signature_header *)
		(flash_base + SIGNATURE_HEADER_OFFSET);
	// printk("Head: %p\n", head);
	if (head->magic1 != SIGNATURE_HEADER_MAGIC1 ||
	    head->magic2 != SIGNATURE_HEADER_MAGIC2)
		return NO_IMAGE;
	// printk("rom_start      = 0x%x\n", head->rom_start);
	// printk("rom_end        = 0x%x\n", head->rom_end);
	// printk("data_rom_start = 0x%x\n", head->data_rom_start);
	// printk("data_ram_start = 0x%x\n", head->data_ram_start);
	// printk("data_ram_end   = 0x%x\n", head->data_ram_end);

	/*
	 * Note that the image might not be positioned at its ultimate
	 * destination, so we should based our position merely on
	 * lengths added to the passed base.
	 */
	/*
	 * TODO: Validate that these sizes keep everything in the
	 * section.
	 */
	base = flash_base;
	base += head->rom_end - head->rom_start;
	base += head->data_ram_end - head->data_ram_start;

	*image_size = base - flash_base;

	/* Pad the base to the next 16-byte boundary. */
	base = (base + 15) & ~15;

	/* Determine if we have a signature at this address. */
	// printk("Base: 0x%x\n", base);

	sig = (struct image_signature *)base;
	if (memcmp(sig, magic, 8)) {
		printk("No image magic found\n");
		return NO_IMAGE;
	}

	if (sig->version != SIG_VERSION) {
		printk("Signature version mismatch\n");
		return NO_IMAGE;
	}

	return sig;
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
static void img_hash(uintptr_t flash_base, size_t image_size,
		     uint8_t *hash_out)
{
	mbedtls_sha256_context ctx;

	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);

	mbedtls_sha256_update(&ctx, (const uint8_t *)flash_base,
			      image_size);
	mbedtls_sha256_finish(&ctx, hash_out);
	mbedtls_sha256_free(&ctx);
}

int
bootutil_img_validate(uintptr_t flash_base)
{
	struct image_signature *sig_base;
	size_t image_size;
	uint8_t hash[32];
	int rc;
	int i;

	init_boot_alloc();

	sig_base = find_signature(flash_base, &image_size);
	if (sig_base == NO_IMAGE)
		return -1;

	for (i = 0; i < ARRAY_SIZE(signature_types); i++) {
		if (sig_base->algo == signature_types[i].algo &&
		    sig_base->hash == signature_types[i].hash)
			break;
	}

	if (i == ARRAY_SIZE(signature_types)) {
		printk("Unsupported signature type\n");
		return -1;
	}

	img_hash(flash_base, image_size, hash);

	rc = signature_types[i].verify(hash, 32, sig_base, 0);

	if (rc != 0) {
		printk("Signature verification error\n");
		return -1;
	}

	return 0;
}
