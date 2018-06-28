/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <misc/printk.h>
#include <time.h>

/* Use SHA512 version. */

#include "monocypher.h"

static const uint8_t zeros[1024] = {0};

void main(void)
{
	printk("Hello World! %s\n", CONFIG_ARCH);

	time_t now = time(NULL);
	printk("Time gotten is %ld\n", now);

	u32_t a, b;
	uint8_t pub_key[32];
	uint8_t sec_key[32];
	uint8_t signature[64];

	a = k_cycle_get_32();
	crypto_sign_public_key(pub_key, sec_key);
	b = k_cycle_get_32();
	printk("Time for key gen: %d\n", b - a);

	// Now sign something.
	a = k_cycle_get_32();
	crypto_sign(signature, sec_key, pub_key, zeros, sizeof(zeros));
	b = k_cycle_get_32();
	printk("Time for signature: %d\n", b - a);

	// And check
	a = k_cycle_get_32();
	int good = crypto_check(signature, pub_key, zeros, sizeof(zeros));
	b = k_cycle_get_32();
	printk("Check is: %d\n", good);
	printk("Time for check: %d\n", b - a);
}
