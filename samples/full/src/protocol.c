/* Protocol implementation. */
/*
 * Copyright (c) 2018 Linaro Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG

#include "protocol.h"

#include <zephyr.h>
#include <logging/sys_log.h>
#include <string.h>
#include <jwt.h>

#include "mqtt.h"

#include <mbedtls/platform.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <mbedtls/debug.h>

#ifdef CONFIG_STDOUT_CONSOLE
# include <stdio.h>
# define PRINT printf
#else
# define PRINT printk
#endif

/*
 * TODO: Properly export these.
 */
time_t k_time(time_t *ptr);

/*
 * mbed TLS has its own "memory buffer alloc" heap, but it needs some
 * data.  This size can be tuned.
 */
#ifdef MBEDTLS_MEMORY_BUFFER_ALLOC_C
#  include <mbedtls/memory_buffer_alloc.h>
static unsigned char heap[65536];
#else
#  error "TODO: no memory buffer configured"
#endif

/*
 * This is the hard-coded root certificate that we accept.
 */
#include "globalsign.inc"

static int entropy_source(void *data, unsigned char *output, size_t len,
			  size_t *olen)
{
	u32_t seed;

	// TODO: Don't use sys_rand32_get(), but instead use the
	// entropy device, and fail if it isn't available.

	ARG_UNUSED(data);

	seed = sys_rand32_get();

	if (len > sizeof(seed)) {
		len = sizeof(seed);
	}

	memcpy(output, &seed, len);

	*olen = len;

	return 0;
}

static void my_debug(void *ctx, int level,
		     const char *file, int line, const char *str)
{
	const char *p, *basename;
	int len;

	ARG_UNUSED(ctx);

	/* Extract basename from file */
	for (p = basename = file; *p != '\0'; p++) {
		if (*p == '/' || *p == '\\') {
			basename = p + 1;
		}

	}

	/* Avoid printing double newlines */
	len = strlen(str);
	if (str[len - 1] == '\n') {
		((char *)str)[len - 1] = '\0';
	}

	SYS_LOG_INF("%s:%04d: |%d| %s", basename, line, level, str);
}

static mbedtls_ssl_context the_ssl;
static mbedtls_ssl_config the_conf;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static int sock;

static int tcp_tx(void *ctx,
		  const unsigned char *buf,
		  size_t len)
{
	int sock = *((int *) ctx);

	/* Ideally, don't try to send more than is allowed.  TLS will
	 * reassemble on the other end. */

	mbedtls_debug_print_buf(&the_ssl, 4, __FILE__, __LINE__, "tcp_tx", buf, len);
	printf("SEND: %d to %d\n", len, sock);

	int res = zsock_send(sock, buf, len, ZSOCK_MSG_DONTWAIT);
	if (res >= 0) {
		return res;
	}

	if (res != len) {
		printf("Short send: %d\n", res);
	}

	// printk("----- SEND -----\n");
	// pdump(buf, res);
	// printk("----- END SEND -----\n");

	switch errno {
	case EAGAIN:
		printf("Waiting for write, res: %d\n", len);
		return MBEDTLS_ERR_SSL_WANT_WRITE;

	default:
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
}

static int tcp_rx(void *ctx,
		  unsigned char *buf,
		  size_t len)
{
	int res;
	int sock = *((int *) ctx);

	res = zsock_recv(sock, buf, len, ZSOCK_MSG_DONTWAIT);
	mbedtls_debug_print_buf(&the_ssl, 4, __FILE__, __LINE__, "tcp_rx", buf, res);
	if (res >= 0) {
		printf("RECV: %d from %d\n", res, sock);
		// printk("----- RECV -----\n");
		// pdump(buf, res);
		// printk("----- END RECV -----\n");
	}

	if (res >= 0) {
		return res;
	}

	switch errno {
	case EAGAIN:
		return MBEDTLS_ERR_SSL_WANT_READ;

	default:
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
}

const char *pers = "mini_client";  // What is this?

/*
 * A TLS client, using mbed TLS.
 */
void tls_client(const char *hostname, struct zsock_addrinfo *host, int port)
{
	int res;

	mbedtls_platform_set_time(k_time);

#ifdef MBEDTLS_X509_CRT_PARSE_C
	mbedtls_x509_crt ca;
#else
#	error "Must define MBEDTLS_X509_CRT_PARSE_C"
#endif

	mbedtls_platform_set_printf(PRINT);

	/*
	 * 0. Initialize mbed TLS.
	 */
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ssl_init(&the_ssl);
	mbedtls_ssl_config_init(&the_conf);
	mbedtls_x509_crt_init(&ca);

	SYS_LOG_INF("Seeding the random number generator...");
	mbedtls_entropy_init(&entropy);
	mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
				   MBEDTLS_ENTROPY_MAX_GATHER,
				   MBEDTLS_ENTROPY_SOURCE_STRONG);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
				  (const unsigned char *)pers,
				  strlen(pers)) != 0) {
		SYS_LOG_ERR("Unable to init drbg");
		return;
	}

	SYS_LOG_INF("Setting up the TLS structure");
	if (mbedtls_ssl_config_defaults(&the_conf,
					MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
		SYS_LOG_ERR("Unable to setup ssl config");
		return;
	}

	mbedtls_ssl_conf_dbg(&the_conf, my_debug, NULL);

	mbedtls_ssl_conf_rng(&the_conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	/* MBEDTLS_MEMORY_BUFFER_ALLOC_C */
	mbedtls_memory_buffer_alloc_init(heap, sizeof(heap));

	/* Load the intended root cert in. */
	if (mbedtls_x509_crt_parse_der(&ca, globalsign_certificate,
				       sizeof(globalsign_certificate)) != 0) {
		SYS_LOG_ERR("Unable to decode root cert");
		return;
	}

	/* And configure tls to require the other side of the
	 * connection to use a cert signed by this certificate.
	 * This makes things fragile, as we are tied to a specific
	 * certificate. */
	mbedtls_ssl_conf_ca_chain(&the_conf, &ca, NULL);
	mbedtls_ssl_conf_authmode(&the_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	// mbedtls_debug_set_threshold(2);
	if (mbedtls_ssl_setup(&the_ssl, &the_conf) != 0) {
		SYS_LOG_ERR("Error running mbedtls_ssl_setup");
		return;
	}

	/* Certificate verification requires matching against an
	 * expected hostname.  Use the one we looked up.
	 * TODO: Make this only occur once in the code.
	 */
	if (mbedtls_ssl_set_hostname(&the_ssl, hostname) != 0) {
		SYS_LOG_ERR("Error setting target hostname");
	}

	SYS_LOG_INF("tls init done");

	SYS_LOG_INF("Connecting to tcp '%s'", hostname);
	SYS_LOG_INF("Creating socket");
	sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		SYS_LOG_ERR("Failed to create socket");
		return;
	}

	SYS_LOG_INF("connecting...");
	res = zsock_connect(sock, host->ai_addr, host->ai_addrlen);
	if (res == -1) {
		SYS_LOG_ERR("Failed to connect to socket");
		return;
	}
	SYS_LOG_INF("Connected");

	mbedtls_ssl_set_bio(&the_ssl, &sock, tcp_tx, tcp_rx, NULL);

	SYS_LOG_INF("Performing TLS handshake");
	SYS_LOG_INF("State: %d", the_ssl.state);
	// mbedtls_debug_set_threshold(2);

	res = mbedtls_ssl_handshake(&the_ssl);
	while (1) {
		if (res != 0) {
			if (res != MBEDTLS_ERR_SSL_WANT_READ) {
				SYS_LOG_ERR("TLS handshake failed");
				SYS_LOG_ERR("state: %d, result: %x", the_ssl.state, res);
				return;
			}
		} else {
			if (the_ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
				break;
			} else {
				SYS_LOG_ERR("Shouldn't really get here");
				return;
			}
		}

		/* We need to wait for data on the incoming socket,
		 * and keep trying. */
		struct zsock_pollfd fds[1] = {
			[0] = {
				.fd = sock,
				.events = ZSOCK_POLLIN,
				.revents = 0,
			},
		};

		res = zsock_poll(fds, 1, 250);
		if (res < 0) {
			SYS_LOG_ERR("Socket poll error: %d\n", errno);
			return;
		}
		if (res > 1) {
			SYS_LOG_ERR("Weird return from poll: %d\n", res);
			return;
		}

		SYS_LOG_ERR("Waited, try next step");
		res = mbedtls_ssl_handshake(&the_ssl);
		SYS_LOG_ERR("Step returned: %d (state=%d)", res, the_ssl.state);
	}

	SYS_LOG_INF("State: %d", the_ssl.state);

	SYS_LOG_ERR("Done with TCP client startup");
}

static const char client_id[] = "projects/iot-work-199419/locations/us-central1/"
	"registries/my-registry/devices/zepfull";
#define AUDIENCE "iot-work-199419"

static u8_t send_buf[1024];
static u8_t recv_buf[1024];
static u8_t token[512];

extern unsigned char zepfull_private_der[];
extern unsigned int zepfull_private_der_len;

void mqtt_startup(void)
{
	struct mqtt_connect_msg conmsg;
	struct jwt_builder jb;

	time_t now = k_time(NULL);

	int res = jwt_init_builder(&jb, token, sizeof(token));
	if (res != 0) {
		printk("Error with JWT token\n");
		return;
	}

	res = jwt_add_payload(&jb, now + 60 * 60, now,
			      AUDIENCE);
	if (res != 0) {
		printk("Error with JWT token\n");
		return;
	}

	res = jwt_sign(&jb, zepfull_private_der, zepfull_private_der_len);
	if (res != 0) {
		printk("Error with JWT token\n");
		return;
	}

	memset(&conmsg, 0, sizeof(conmsg));

	conmsg.clean_session = 1;
	conmsg.client_id = (char *)client_id;  /* Discard const */
	conmsg.client_id_len = strlen(client_id);
	conmsg.keep_alive = 60; /* One minute */
	conmsg.password = token;
	conmsg.password_len = jwt_payload_len(&jb);

	printk("len1 = %d, len2 = %d\n", conmsg.password_len,
	       strlen(token));

	u16_t send_len = 0;
	res = mqtt_pack_connect(send_buf, &send_len, sizeof(send_buf),
				    &conmsg);
	printk("build packet: res = %d, len=%d\n", res, send_len);

	pdump(send_buf, send_len);
	res = mbedtls_ssl_write(&the_ssl, send_buf, send_len);
	printk("Send result: %d\n", res);
	if (res < 0) {
		return;
	}
	if (res != send_len) {
		printk("Short send\n");
	}

	/* Try to receive something. */
	while (1) {
		struct zsock_pollfd fds[1] = {
			[0] = {
				.fd = sock,
				.events = ZSOCK_POLLIN,
				.revents = 0,
			},
		};

		res = zsock_poll(fds, 1, 5000);
		if (res < 0) {
			printk("Socket poll error: %d\n", errno);
			return;
		}
		if (res == 0) {
			printk("Moving on\n");
			break;
		}

		res = mbedtls_ssl_read(&the_ssl, recv_buf, sizeof(recv_buf));
		if (res < 0) {
			// printk("Read error: %d\n", res);
		} else {
			printk("Read data: %d bytes:\n", res);
			pdump(recv_buf, res);
		}
	}

#if 1
	/* Try subscribing to the device state message. */
	static const char *topics[] = {
		"/devices/zepfull/config",
	};
	static const enum mqtt_qos qoss[] = {
		MQTT_QoS1,
	};
	res = mqtt_pack_subscribe(send_buf, &send_len, sizeof(send_buf),
				  123, 1, topics, qoss);
	printk("Subscribe packet: res=%d, len=%d\n", res, send_len);
#else
#define TOPIC "/devices/zepfull/state"
#define MESSAGE "Hereismystate"
	/* Try sending a state update. */
	struct mqtt_publish_msg pmsg = {
		.dup = 0,
		.qos = MQTT_QoS1,
		.retain = 1,
		.pkt_id = 0xfd12,
		.topic = TOPIC,
		.topic_len = strlen(TOPIC),
		.msg = MESSAGE,
		.msg_len = strlen(MESSAGE),
	};
	res = mqtt_pack_publish(send_buf, &send_len, sizeof(send_buf),
				&pmsg);
	printk("Publish packet: res=%d, len=%d\n", res, send_len);
#endif
	pdump(send_buf, send_len);
	res = mbedtls_ssl_write(&the_ssl, send_buf, send_len);
	printk("Send result: %d\n", res);
	if (res < 0) {
		return;
	}
	if (res != send_len) {
		printk("Short send\n");
	}

	/* Try to receive something. */
	while (1) {
		struct zsock_pollfd fds[1] = {
			[0] = {
				.fd = sock,
				.events = ZSOCK_POLLIN,
				.revents = 0,
			},
		};

		res = zsock_poll(fds, 1, 5000);
		if (res < 0) {
			printk("Socket poll error: %d\n", errno);
			return;
		}
		if (res == 0) {
			printk(".");
		}

		res = mbedtls_ssl_read(&the_ssl, recv_buf, sizeof(recv_buf));
		if (res < 0) {
			// printk("Read error: %d\n", res);
		} else {
			printk("Read data: %d bytes:\n", res);
			pdump(recv_buf, res);
		}
	}
}

