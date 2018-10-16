/*
 * Copyright (C) 2018 Linaro Ltd
 *
 *  SPDX-License-Identifier: Apache-2.0
 */

/*
 * Implement the CPRNG API using CRBG-CTR from mbed TLS./
 */

#include <zephyr.h>
#include <cprng.h>
#include <entropy.h>

#include <mbedtls/ctr_drbg.h>

static int get_prng_entropy(void *vgen, unsigned char *buf, size_t len)
{
	int ret;
	struct cprng_gen *gen = vgen;

	ret = entropy_get_entropy(gen->entropy_dev, buf, len);
	if (ret == 0) {
		return 0;
	} else {
		return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
	}
}

int cprng_init(struct cprng_gen *gen)
{
	mbedtls_ctr_drbg_init(&gen->context);
	return 0;
}

int cprng_seed(struct cprng_gen *gen, struct device *entropy)
{
	int ret;

	gen->entropy_dev = entropy;
	ret = mbedtls_ctr_drbg_seed(&gen->context,
				    get_prng_entropy,
				    gen,
				    "Zephyr", /* TODO: Config? */
				    6);
	if (ret != 0) {
		return -EINVAL;
	} else {
		return 0;
	}
}

int cprng_generate(struct cprng_gen *gen,
		   u8_t *buffer,
		   u16_t length)
{
	int ret;

	ret = mbedtls_ctr_drbg_random(&gen->context,
				      buffer, length);

	if (ret != 0) {
		return -EINVAL;
	} else {
		return 0;
	}
}
