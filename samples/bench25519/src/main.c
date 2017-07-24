/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <string.h>
#include <misc/printk.h>

// #include "tweetnacl.h"
#include <sha512.h>
#include <ed25519.h>

#define crypto_hash crypto_hash_sha512
#define crypto_sign_keypair ed25519_sign_keypair
#define crypto_sign_seed_keypair ed25519_sign_seed_keypair
#define crypto_sign ed25519_sign
#define crypto_sign_open ed25519_sign_open
#define randombytes ed25519_randombytes

/*
 * Proper key generation needs random bytes.  To avoid this taking up
 * too much time in the benchmark, just use a simple generator.
 * (note this isn't used if we use the seed_keypair function).
 */
uint32_t state = 0xdeafbeef;
void randombytes(uint8_t *buf, uint64_t len)
{
	while (len > 0) {
		uint32_t x = state;
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		state = x;

		*buf = state & 0xFF;

		buf++;
		len--;
	}
}

/*
 * Benchmark a single function.
 */
void bench(char *name, void (*func)(void))
{
	uint32_t a, b;

	a = k_cycle_get_32();
	func();
	b = k_cycle_get_32();
	printk("Bench %s: %d\n", name, b - a);
}

void empty(void)
{
}

/*
 * Compute a hash over 192k of flash.
 */
void hash(void)
{
	uint8_t hash[crypto_hash_BYTES];
	crypto_hash(hash, (uint8_t *)0, 192 * 1024);
}

/*
 * Generate and use these here.
 */
uint8_t publickey[crypto_sign_PUBLICKEYBYTES];
uint8_t secretkey[crypto_sign_SECRETKEYBYTES];
uint8_t sigm[256 + 64];
uint8_t msg[256 + 64];
unsigned long long sigmlen;

void keygen(void)
{
	uint8_t seed[32];
	memset(seed, 0, 32);

	crypto_sign_seed_keypair(publickey, secretkey, seed);
	// crypto_sign_keypair(publickey, secretkey);
}

void signit(void)
{
	crypto_sign(sigm, &sigmlen, (uint8_t *)0, 32, secretkey);
	if (sigmlen != 256+64) {
		printk("Bad signing len: %d\n", (int)sigmlen);
	}
}

void checkit(void)
{
	unsigned long long msglen;
	int result;
	result = crypto_sign_open(msg, &msglen, sigm, sigmlen, publickey);
	if (result != 0) {
		printk("Bad signature: %d\n", result);
	}
}

void main(void)
{
	printk("Hello World! %s\n", CONFIG_ARCH);
	bench("empty", empty);
	bench("hash", hash);
	bench("keygen", keygen);
	bench("signit", signit);
	bench("checkit", checkit);
}
