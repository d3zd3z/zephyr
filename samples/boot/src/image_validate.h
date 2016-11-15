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

#ifndef __BOOT_IMAGE_VALIDATE_H__
#define __BOOT_IMAGE_VALIDATE_H__

#include <stdint.h>

int bootutil_img_validate(uintptr_t flash_base);

/** Indicates that no image is present. */
#define NO_IMAGE ((struct image_signature *) -1)

/* This is the format of the signature appended to the image. */
struct image_signature {
	uint8_t magic[8];
	uint8_t version; /* Version of this signature header. */
	uint8_t algo; /* Algorithm for the signature. */
	uint8_t hash; /* Hash function used. */
	uint8_t __pad; /* Some padding. */

	/* TODO: We will need more things here, such as a possible
	 * certificate chain and other stuff. */
	uint32_t sig_len;
};

#define SIG_VERSION 1

#define SIG_ALGO_RSA 1
#define SIG_ALGO_ECDSA 2

#define SIG_HASH_SHA256 1

#endif /* __BOOT_IMAGE_VALIDATE_H__ */
