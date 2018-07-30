/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <string.h>
#include <misc/printk.h>
#include <uart.h>

static struct device *uart0_dev;
static struct device *uart1_dev;
static char rx_buf0[512];
static char rx_buf1[512];

static void uart0_isr(struct device *dev)
{
	int rx = 0, tx = 0;

	if (uart_irq_rx_ready(dev)) {
		rx = uart_fifo_read(dev, rx_buf0, 32);
		tx = uart_fifo_fill(uart1_dev, rx_buf0, rx);

		if (rx != tx)
			printk("wtf\n");
	}
}

static void uart1_isr(struct device *dev)
{
	int rx = 0, tx = 0;

	if (uart_irq_rx_ready(dev)) {
		rx = uart_fifo_read(dev, rx_buf1, 32);
		tx = uart_fifo_fill(uart0_dev, rx_buf1, rx);

		if (rx != tx)
			printk("wtf\n");
	}
}

void main(void)
{
	uart0_dev = device_get_binding("UART_0");
	uart1_dev = device_get_binding("UART_1");

	printk("starting loopback test.  Please type into either uart\n");
	if (!(uart0_dev && uart1_dev)) {
		printk("problem with uarts\n");
		return;
	}

	uart_irq_callback_set(uart0_dev, uart0_isr);

	uart_irq_callback_set(uart1_dev, uart1_isr);

	uart_irq_rx_enable(uart0_dev);
	uart_irq_rx_enable(uart1_dev);

	while (1) {
		k_sleep(1000);
	}
}
