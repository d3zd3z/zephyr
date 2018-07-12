/* DNS queries. */

/*
 * Copyright (c) 2018 Linaro Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __DNS_H__
#define __DNS_H__

int ipv4_lookup(const char *host, char *ip, size_t ip_len);

#endif /* __DNS_H__ */
