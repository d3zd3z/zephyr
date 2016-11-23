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

#ifndef __BOOT_IMAGE_RSA_H__
#define __BOOT_IMAGE_RSA_H__

struct image_signature;

int
bootutil_rsa_verify_sig(uint8_t *hash, uint32_t hlen,
			struct image_signature *sig,
			uint8_t key_id);

#endif /* __BOOT_IMAGE_RSA_H__ */
