/*
 * Copyright (C) 2016 Linaro Limited
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

#ifndef __BOOT_UPDATE_H__
#define __BOOT_UPDATE_H__

struct device;

/**
 * @brief Check for boot update
 *
 * Checks the configured flash device for a bootable image, and
 * possible update.  Whether the image is updated or not, returns a
 * pointer to the beginning of a verified boot image that should be
 * run.  Generally, this will be the main image.
 */
void *boot_find_image(struct device *flash_dev);

/** Indicates there is no image present. */
#define NO_BOOT_IMAGE ((void *) -2)

#endif /* __BOOT_UPDATE_H__ */
