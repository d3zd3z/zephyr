/*
 * Copyright (c) 2016 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @brief Driver for UART on ARM CMSDK APB UART.
 *
 * UART has two wires for RX and TX, and does not provide CTS or RTS.
 */

#include <kernel.h>
#include "uart_pl011_drv.h"
#include "cmsis_compiler.h"

#include <arch/cpu.h>
#include <clock_control/arm_clock_control.h>
#include <misc/__assert.h>
#include <board.h>
#include <init.h>
#include <uart.h>
#include <linker/sections.h>

/* UART registers struct */
struct uart_cmsdk_apb {
	/* offset: 0x000 (r/w) data register    */
	volatile u32_t  data;
	/* offset: 0x004 (r/w) status register  */
	volatile u32_t  state;
	/* offset: 0x008 (r/w) control register */
	volatile u32_t  ctrl;
	union {
		/* offset: 0x00c (r/ ) interrupt status register */
		volatile u32_t  intstatus;
		/* offset: 0x00c ( /w) interrupt clear register  */
		volatile u32_t  intclear;
	};
	/* offset: 0x010 (r/w) baudrate divider register */
	volatile u32_t  bauddiv;
};


#define FREQ_IRLPBAUD16_MIN             (1420000u)     /* 1.42 MHz */
#define FREQ_IRLPBAUD16_MAX             (2120000u)     /* 2.12 MHz */
#define SAMPLING_FACTOR                 (16u)
#define UART_PL011_FBRD_WIDTH           (6u)

/**
 * \brief UART PL011 register map structure
 */
struct _uart_pl011_reg_map_t {
    volatile uint32_t uartdr;          /*!< Offset: 0x000 (R/W) Data register */
    union {
        volatile uint32_t uartrsr;
                /*!< Offset: 0x004 (R/ ) Receive status register */
        volatile uint32_t uartecr;
                /*!< Offset: 0x004 ( /W) Error clear register */
    };
    volatile uint32_t reserved_0[4];   /*!< Offset: 0x008-0x014 Reserved */
    volatile uint32_t uartfr;          /*!< Offset: 0x018 (R/ ) Flag register */
    volatile uint32_t reserved_1;      /*!< Offset: 0x01C       Reserved */
    volatile uint32_t uartilpr;
                /*!< Offset: 0x020 (R/W) IrDA low-power counter register */
    volatile uint32_t uartibrd;
                /*!< Offset: 0x024 (R/W) Integer baud rate register */
    volatile uint32_t uartfbrd;
                /*!< Offset: 0x028 (R/W) Fractional baud rate register */
    volatile uint32_t uartlcr_h;
                /*!< Offset: 0x02C (R/W) Line control register */
    volatile uint32_t uartcr;
                /*!< Offset: 0x030 (R/W) Control register */
    volatile uint32_t uartifls;
                /*!< Offset: 0x034 (R/W) Interrupt FIFO level select register */
    volatile uint32_t uartimsc;
                /*!< Offset: 0x038 (R/W) Interrupt mask set/clear register */
    volatile uint32_t uartris;
                /*!< Offset: 0x03C (R/ ) Raw interrupt status register */
    volatile uint32_t uartmis;
                /*!< Offset: 0x040 (R/ ) Masked interrupt status register */
    volatile uint32_t uarticr;
                /*!< Offset: 0x044 ( /W) Interrupt clear register */
    volatile uint32_t uartdmacr;
                /*!< Offset: 0x048 (R/W) DMA control register */
    volatile uint32_t reserved_2[13];  /*!< Offset: 0x04C-0x07C Reserved */
    volatile uint32_t reserved_3[4];
                /*!< Offset: 0x080-0x08C Reserved for test purposes */
    volatile uint32_t reserved_4[976]; /*!< Offset: 0x090-0xFCC Reserved */
    volatile uint32_t reserved_5[4];
                /*!< Offset: 0xFD0-0xFDC Reserved for future ID expansion */
    volatile uint32_t uartperiphid0;
                /*!< Offset: 0xFE0 (R/ ) UARTPeriphID0 register */
    volatile uint32_t uartperiphid1;
                /*!< Offset: 0xFE4 (R/ ) UARTPeriphID1 register */
    volatile uint32_t uartperiphid2;
                /*!< Offset: 0xFE8 (R/ ) UARTPeriphID2 register */
    volatile uint32_t uartperiphid3;
                /*!< Offset: 0xFEC (R/ ) UARTPeriphID3 register */
    volatile uint32_t uartpcellid0;
                /*!< Offset: 0xFF0 (R/ ) UARTPCellID0 register */
    volatile uint32_t uartpcellid1;
                /*!< Offset: 0xFF4 (R/ ) UARTPCellID1 register */
    volatile uint32_t uartpcellid2;
                /*!< Offset: 0xFF8 (R/ ) UARTPCellID2 register */
    volatile uint32_t uartpcellid3;
                /*!< Offset: 0xFFC (R/ ) UARTPCellID3 register */
};

#define UART_PL011_UARTFR_CTS_MASK (                    \
            0x1u<<UART_PL011_UARTFR_CTS_OFF)
#define UART_PL011_UARTFR_DSR_MASK (                    \
            0x1u<<UART_PL011_UARTFR_DSR_OFF)
#define UART_PL011_UARTFR_DCD_MASK (                    \
            0x1u<<UART_PL011_UARTFR_DCD_OFF)
#define UART_PL011_UARTFR_BUSYBIT (                     \
            0x1u<<UART_PL011_UARTFR_BUSYBIT_OFF)
#define UART_PL011_UARTFR_RX_FIFO_EMPTY (               \
            0x1u<<UART_PL011_UARTFR_RX_FIFO_EMPTY_OFF)
#define UART_PL011_UARTFR_TX_FIFO_FULL (                \
            0x1u<<UART_PL011_UARTFR_TX_FIFO_FULL_OFF)
#define UART_PL011_UARTFR_RI_MASK (                     \
            0x1u<<UART_PL011_UARTFR_RI_OFF)

#define UART_PL011_UARTLCR_H_BRK_MASK (                 \
            0x1u<<UART_PL011_UARTLCR_H_BRK_OFF)
#define UART_PL011_UARTLCR_H_PARITY_MASK (              \
            0x1u<<UART_PL011_UARTLCR_H_PEN_OFF          \
          | 0x1u<<UART_PL011_UARTLCR_H_EPS_OFF          \
          | 0x1u<<UART_PL011_UARTLCR_H_SPS_OFF)
#define UART_PL011_UARTLCR_H_STOPBIT_MASK (             \
            0x1u<<UART_PL011_UARTLCR_H_STP2_OFF)
#define UART_PL011_UARTLCR_H_FEN_MASK (                 \
            0x1u<<UART_PL011_UARTLCR_H_FEN_OFF)
#define UART_PL011_UARTLCR_H_WLEN_MASK (                \
            0x3u<<UART_PL011_UARTLCR_H_WLEN_OFF)
#define UART_PL011_FORMAT_MASK (                        \
            UART_PL011_UARTLCR_H_PARITY_MASK            \
          | UART_PL011_UARTLCR_H_STOPBIT_MASK           \
          | UART_PL011_UARTLCR_H_WLEN_MASK)

#define UART_PL011_UARTCR_EN_MASK (                     \
            0x1u<<UART_PL011_UARTCR_UARTEN_OFF)
#define UART_PL011_UARTCR_SIREN_MASK (                  \
            0x1u<<UART_PL011_UARTCR_SIREN_OFF)
#define UART_PL011_UARTCR_SIRLP_MASK (                  \
            0x1u<<UART_PL011_UARTCR_SIRLP_OFF)
#define UART_PL011_UARTCR_LBE_MASK (                    \
            0x1u<<UART_PL011_UARTCR_LBE_OFF)
#define UART_PL011_UARTCR_TX_EN_MASK (                  \
            0x1u<<UART_PL011_UARTCR_TXE_OFF)
#define UART_PL011_UARTCR_RX_EN_MASK (                  \
            0x1u<<UART_PL011_UARTCR_RXE_OFF)
#define UART_PL011_UARTCR_DTR_MASK (                    \
            0x1u<<UART_PL011_UARTCR_DTR_OFF)
#define UART_PL011_UARTCR_RTS_MASK (                    \
            0x1u<<UART_PL011_UARTCR_RTS_OFF)
#define UART_PL011_UARTCR_OUT1_MASK (                   \
            0x1u<<UART_PL011_UARTCR_OUT1_OFF)
#define UART_PL011_UARTCR_OUT2_MASK (                   \
            0x1u<<UART_PL011_UARTCR_OUT2_OFF)
#define UART_PL011_UARTCR_RTSE_MASK (                   \
            0x1u<<UART_PL011_UARTCR_RTSE_OFF)
#define UART_PL011_UARTCR_CTSE_MASK (                   \
            0x1u<<UART_PL011_UARTCR_CTSE_OFF)

#define UART_PL011_UARTIFLS_TX_FIFO_LVL_MASK (          \
            0x7u<<UART_PL011_UARTIFLS_TX_OFF)
#define UART_PL011_UARTIFLS_RX_FIFO_LVL_MASK (          \
            0x7u<<UART_PL011_UARTIFLS_RX_OFF)

#define UART_PL011_UARTDMACR_RX_MASK (                  \
            0x1u<<UART_PL011_UARTDMACR_RXEN_OFF         \
          | 0x1u<<UART_PL011_UARTDMACR_ON_ERR_OFF)
#define UART_PL011_UARTDMACR_TX_MASK (                  \
            0x1u<<UART_PL011_UARTDMACR_TXEN_OFF)

static void _uart_pl011_enable(struct _uart_pl011_reg_map_t* p_uart)
{
    p_uart->uartcr |=  UART_PL011_UARTCR_EN_MASK;
}

static void _uart_pl011_disable(struct _uart_pl011_reg_map_t* p_uart)
{
    p_uart->uartcr &= ~UART_PL011_UARTCR_EN_MASK;
}

static bool _uart_pl011_is_enabled(struct _uart_pl011_reg_map_t* p_uart)
{
    return (bool)(p_uart->uartcr & UART_PL011_UARTCR_EN_MASK);
}

static void _uart_pl011_enable_fifo(struct _uart_pl011_reg_map_t* p_uart)
{
    p_uart->uartlcr_h |= UART_PL011_UARTLCR_H_FEN_MASK;
}

static void _uart_pl011_disable_fifo(struct _uart_pl011_reg_map_t* p_uart)
{
    p_uart->uartlcr_h &= ~UART_PL011_UARTLCR_H_FEN_MASK;
}

static bool _uart_pl011_is_fifo_enabled(struct _uart_pl011_reg_map_t* p_uart)
{
    return (bool)(p_uart->uartlcr_h & UART_PL011_UARTLCR_H_FEN_MASK);
}

static enum uart_pl011_error_t _uart_pl011_set_baudrate(
                    struct _uart_pl011_reg_map_t* p_uart,
                    uint32_t clk, uint32_t baudrate)
{
    /* Avoiding float calculations, bauddiv is left shifted by 6 */
    uint64_t bauddiv = (((uint64_t)clk)<<UART_PL011_FBRD_WIDTH)
                       /(SAMPLING_FACTOR*baudrate);

    /* Valid bauddiv value
     * uart_clk (min) >= 16 x baud_rate (max)
     * uart_clk (max) <= 16 x 65535 x baud_rate (min)
     */
    if((bauddiv < (1u<<UART_PL011_FBRD_WIDTH))
       || (bauddiv > (65535u<<UART_PL011_FBRD_WIDTH))) {
        return UART_PL011_ERR_INVALID_BAUD;
    }

    p_uart->uartibrd = (uint32_t)(bauddiv >> UART_PL011_FBRD_WIDTH);
    p_uart->uartfbrd = (uint32_t)(bauddiv &
                                 ((1u << UART_PL011_FBRD_WIDTH) - 1u));

    __DMB();

    /* In order to internally update the contents of uartibrd or uartfbrd, a
     * uartlcr_h write must always be performed at the end
     * ARM DDI 0183F, Pg 3-13
     */
    p_uart->uartlcr_h = p_uart->uartlcr_h;

    return UART_PL011_ERR_NONE;
}

static void _uart_pl011_set_format(struct _uart_pl011_reg_map_t* p_uart,
                    enum uart_pl011_wlen_t word_len,
                    enum uart_pl011_parity_t parity,
                    enum uart_pl011_stopbit_t stop_bits)
{
    uint32_t ctrl_reg = p_uart->uartlcr_h & ~(UART_PL011_FORMAT_MASK);

    /* Making sure other bit are not changed */
    word_len  &= UART_PL011_UARTLCR_H_WLEN_MASK;
    parity    &= UART_PL011_UARTLCR_H_PARITY_MASK;
    stop_bits &= UART_PL011_UARTLCR_H_STOPBIT_MASK;

    p_uart->uartlcr_h = ctrl_reg | word_len | parity | stop_bits;

}

static void _uart_pl011_set_cr_bit(struct _uart_pl011_reg_map_t* p_uart,
                    uint32_t mask)
{
    bool uart_enabled = _uart_pl011_is_enabled(p_uart);
    bool fifo_enabled = _uart_pl011_is_fifo_enabled(p_uart);

    /* UART must be disabled before any Control Register or
     * Line Control Register are reprogrammed */
    _uart_pl011_disable(p_uart);

    /* Flush the transmit FIFO by disabling bit 4 (FEN) in
     * the line control register (UARTCLR_H) */
    _uart_pl011_disable_fifo(p_uart);

    p_uart->uartcr |= (mask);

    /* Enabling the FIFOs if previously enabled */
    if(fifo_enabled) {
        _uart_pl011_enable_fifo(p_uart);
    }

    /* Enabling the UART if previously enabled */
    if(uart_enabled) {
        _uart_pl011_enable(p_uart);
    }
}

static void _uart_pl011_clear_cr_bit(struct _uart_pl011_reg_map_t* p_uart,
                    uint32_t mask)
{
    bool uart_enabled = _uart_pl011_is_enabled(p_uart);
    bool fifo_enabled = _uart_pl011_is_fifo_enabled(p_uart);

    /* UART must be disabled before any Control Register or
     * Line Control Register are reprogrammed */
    _uart_pl011_disable(p_uart);

    /* Flush the transmit FIFO by disabling bit 4 (FEN) in
     * the line control register (UARTCLR_H) */
    _uart_pl011_disable_fifo(p_uart);

    p_uart->uartcr &= ~(mask);

    /* Enabling the FIFOs if previously enabled */
    if(fifo_enabled) {
        _uart_pl011_enable_fifo(p_uart);
    }

    /* Enabling the UART if previously enabled */
    if(uart_enabled) {
        _uart_pl011_enable(p_uart);
    }
}

static void _uart_pl011_set_lcr_h_bit(struct _uart_pl011_reg_map_t* p_uart,
                    uint32_t mask)
{
    bool uart_enabled = _uart_pl011_is_enabled(p_uart);

    /* UART must be disabled before any Control Register or
     * Line Control Register are reprogrammed */
    _uart_pl011_disable(p_uart);

    p_uart->uartlcr_h |= (mask);

    /* Enabling the UART if previously enabled */
    if(uart_enabled) {
        _uart_pl011_enable(p_uart);
    }
}

static void _uart_pl011_clear_lcr_h_bit(struct _uart_pl011_reg_map_t* p_uart,
                    uint32_t mask)
{
    bool uart_enabled = _uart_pl011_is_enabled(p_uart);

    /* UART must be disabled before any Control Register or
     * Line Control Register are reprogrammed */
    _uart_pl011_disable(p_uart);

    p_uart->uartlcr_h &= ~(mask);

    /* Enabling the UART if previously enabled */
    if(uart_enabled) {
        _uart_pl011_enable(p_uart);
    }
}


static bool _uart_pl011_is_readable(struct _uart_pl011_reg_map_t* uart)
{
    if((uart->uartcr & UART_PL011_UARTCR_EN_MASK) &&
                /* UART is enabled */
        (uart->uartcr & UART_PL011_UARTCR_RX_EN_MASK) &&
                /* Receive is enabled */
        ((uart->uartfr & UART_PL011_UARTFR_RX_FIFO_EMPTY) == 0)) {
                /* Receive Fifo is not empty */
        return true;
    }

    return false;

}

static enum uart_pl011_error_t _uart_pl011_read(
                    struct _uart_pl011_reg_map_t* uart, uint8_t* byte)
{
    *byte = uart->uartdr;

    return (enum uart_pl011_error_t)(uart->uartrsr
                                         & UART_PL011_RX_ERR_MASK);
}

static bool _uart_pl011_is_writable(struct _uart_pl011_reg_map_t* uart)
{
    if((uart->uartcr & UART_PL011_UARTCR_EN_MASK) &&
                /* UART is enabled */
        (uart->uartcr & UART_PL011_UARTCR_TX_EN_MASK) &&
                /* Transmit is enabled */
        ((uart->uartfr & UART_PL011_UARTFR_TX_FIFO_FULL) == 0)) {
                /* Transmit Fifo is not full */
        return true;
    }
    return false;

}

static void _uart_pl011_write(struct _uart_pl011_reg_map_t* uart, uint8_t byte)
{
    uart->uartdr = byte;

    return;
}


/* UART Bits */
/* CTRL Register */
#define UART_TX_EN	(1 << 0)
#define UART_RX_EN	(1 << 1)
#define UART_TX_IN_EN	(1 << 2)
#define UART_RX_IN_EN	(1 << 3)
#define UART_TX_OV_EN	(1 << 4)
#define UART_RX_OV_EN	(1 << 5)
#define UART_HS_TM_TX	(1 << 6)

/* STATE Register */
#define UART_TX_BF	(1 << 0)
#define UART_RX_BF	(1 << 1)
#define UART_TX_B_OV	(1 << 2)
#define UART_RX_B_OV	(1 << 3)

/* INTSTATUS Register */
#define UART_TX_IN	(1 << 0)
#define UART_RX_IN	(1 << 1)
#define UART_TX_OV_IN	(1 << 2)
#define UART_RX_OV_IN	(1 << 3)

/* Device data structure */
struct uart_cmsdk_apb_dev_data {
	u32_t baud_rate;	/* Baud rate */
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	uart_irq_callback_t irq_cb;
#endif
	/* UART Clock control in Active State */
	const struct arm_clock_control_t uart_cc_as;
	/* UART Clock control in Sleep State */
	const struct arm_clock_control_t uart_cc_ss;
	/* UART Clock control in Deep Sleep State */
	const struct arm_clock_control_t uart_cc_dss;
};

/* convenience defines */
#define DEV_CFG(dev) \
	((const struct uart_device_config * const)(dev)->config->config_info)
#define DEV_DATA(dev) \
	((struct uart_cmsdk_apb_dev_data * const)(dev)->driver_data)
#define UART_STRUCT(dev) \
	((volatile struct uart_cmsdk_apb *)(DEV_CFG(dev))->base)

static const struct uart_driver_api uart_cmsdk_apb_driver_api;

/**
 * @brief Set the baud rate
 *
 * This routine set the given baud rate for the UART.
 *
 * @param dev UART device struct
 *
 * @return N/A
 */
static void baudrate_set(struct device *dev)
{
	volatile struct uart_cmsdk_apb *uart = UART_STRUCT(dev);
	const struct uart_device_config * const dev_cfg = DEV_CFG(dev);
	struct uart_cmsdk_apb_dev_data *const dev_data = DEV_DATA(dev);
	/*
	 * If baudrate and/or sys_clk_freq are 0 the configuration remains
	 * unchanged. It can be useful in case that Zephyr it is run via
	 * a bootloader that brings up the serial and sets the baudrate.
	 */
	if ((dev_data->baud_rate != 0) && (dev_cfg->sys_clk_freq != 0)) {
		/* calculate baud rate divisor */
		uart->bauddiv = (dev_cfg->sys_clk_freq / dev_data->baud_rate);
	}
}

/**
 * @brief Initialize UART channel
 *
 * This routine is called to reset the chip in a quiescent state.
 * It is assumed that this function is called only once per UART.
 *
 * @param dev UART device struct
 *
 * @return 0
 */
static int uart_cmsdk_apb_init(struct device *dev)
{
    enum uart_pl011_error_t err;

	volatile struct _uart_pl011_reg_map_t *uart = UART_STRUCT(dev);
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	const struct uart_device_config * const dev_cfg = DEV_CFG(dev);
#endif
struct uart_cmsdk_apb_dev_data *const dev_data = DEV_DATA(dev);

	/* Set baud rate */
//	baudrate_set(dev);
    err = _uart_pl011_set_baudrate(uart, CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC,
                            dev_data->baud_rate);

    if(err != UART_PL011_ERR_NONE) {
        return err;
    }

    /* Setting the default character format */
    _uart_pl011_set_format(uart, UART_PL011_WLEN_8,
                                 UART_PL011_PARITY_DISABLED,
                                 UART_PL011_STOPBIT_1);

    /* Enabling the FIFOs */
    _uart_pl011_enable_fifo(uart);

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	dev_cfg->irq_config_func(dev);
#endif

    _uart_pl011_enable(uart);

	return 0;
}

/**
 * @brief Poll the device for input.
 *
 * @param dev UART device struct
 * @param c Pointer to character
 *
 * @return 0 if a character arrived, -1 if the input buffer if empty.
 */

static int uart_cmsdk_apb_poll_in(struct device *dev, unsigned char *c)
{
	volatile struct _uart_pl011_reg_map_t *uart = UART_STRUCT(dev);

	/* If the receiver is not ready returns -1 */
	if (!_uart_pl011_is_readable(uart)) {
		return -1;
	}

	/* got a character */
	*c = (unsigned char)uart->uartdr;

	return 0;
}

/**
 * @brief Output a character in polled mode.
 *
 * Checks if the transmitter is empty. If empty, a character is written to
 * the data register.
 *
 * @param dev UART device struct
 * @param c Character to send
 *
 * @return Sent character
 */
static unsigned char uart_cmsdk_apb_poll_out(struct device *dev,
					     unsigned char c)
{
	volatile struct uart_cmsdk_apb *uart = UART_STRUCT(dev);

	/* Wait for transmitter to be ready */
	while (uart->state & UART_TX_BF) {
		; /* Wait */
	}

	/* Send a character */
	uart->data = (u32_t)c;
	return c;
}

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
/**
 * @brief Fill FIFO with data
 *
 * @param dev UART device struct
 * @param tx_data Data to transmit
 * @param len Number of bytes to send
 *
 * @return the number of characters that have been read
 */
static int uart_cmsdk_apb_fifo_fill(struct device *dev,
				    const u8_t *tx_data, int len)
{
	volatile struct uart_cmsdk_apb *uart = UART_STRUCT(dev);
    int i = len;

	/* No hardware FIFO present */
    while(i) {
	if (len && !(uart->state & UART_TX_BF)) {
		uart->data = *(tx_data + len - i);
//		return 1;
	}
    i--;
        }

	return 0;
}

/**
 * @brief Read data from FIFO
 *
 * @param dev UART device struct
 * @param rx_data Pointer to data container
 * @param size Container size in bytes
 *
 * @return the number of characters that have been read
 */
static int uart_cmsdk_apb_fifo_read(struct device *dev,
				    u8_t *rx_data, const int size)
{
	volatile struct _uart_pl011_reg_map_t *uart = UART_STRUCT(dev);
    int rx_nbr_bytes = 0;

    uint8_t* p_data = (uint8_t*)rx_data;

    if ((rx_data == NULL) || (size == 0U)) {
        // Invalid parameters
        return -1;
    }

    while(rx_nbr_bytes != size) {

        if (!_uart_pl011_is_readable(uart)) {
            break;
        }

        /* As UART has received one byte, the read can not
         * return any receive error at this point */
        (void)_uart_pl011_read(uart, p_data);

        rx_nbr_bytes++;
        p_data++;
    }

	return rx_nbr_bytes;
}

/**
 * @brief Enable TX interrupt
 *
 * @param dev UART device struct
 *
 * @return N/A
 */
static void uart_cmsdk_apb_irq_tx_enable(struct device *dev)
{
	UART_STRUCT(dev)->ctrl |= UART_TX_IN_EN;
}

/**
 * @brief Disable TX interrupt
 *
 * @param dev UART device struct
 *
 * @return N/A
 */
static void uart_cmsdk_apb_irq_tx_disable(struct device *dev)
{
	UART_STRUCT(dev)->ctrl &= ~UART_TX_IN_EN;
}

/**
 * @brief Verify if Tx interrupt has been raised
 *
 * @param dev UART device struct
 *
 * @return 1 if an interrupt is ready, 0 otherwise
 */
static int uart_cmsdk_apb_irq_tx_ready(struct device *dev)
{
	return !(UART_STRUCT(dev)->state & UART_TX_BF);
}

/**
 * @brief Enable RX interrupt
 *
 * @param dev UART device struct
 *
 * @return N/A
 */
static void uart_cmsdk_apb_irq_rx_enable(struct device *dev)
{
	UART_STRUCT(dev)->ctrl |= UART_RX_IN_EN;
}

/**
 * @brief Disable RX interrupt
 *
 * @param dev UART device struct
 *
 * @return N/A
 */
static void uart_cmsdk_apb_irq_rx_disable(struct device *dev)
{
	UART_STRUCT(dev)->ctrl &= ~UART_RX_IN_EN;
}

/**
 * @brief Verify if Tx empty interrupt has been raised
 *
 * @param dev UART device struct
 *
 * @return 1 if an interrupt is ready, 0 otherwise
 */
static int uart_cmsdk_apb_irq_tx_complete(struct device *dev)
{
	return uart_cmsdk_apb_irq_tx_ready(dev);
}

/**
 * @brief Verify if Rx interrupt has been raised
 *
 * @param dev UART device struct
 *
 * @return 1 if an interrupt is ready, 0 otherwise
 */
static int uart_cmsdk_apb_irq_rx_ready(struct device *dev)
{
	return UART_STRUCT(dev)->state & UART_RX_BF;
}

/**
 * @brief Enable error interrupt
 *
 * @param dev UART device struct
 *
 * @return N/A
 */
static void uart_cmsdk_apb_irq_err_enable(struct device *dev)
{
	ARG_UNUSED(dev);
}

/**
 * @brief Disable error interrupt
 *
 * @param dev UART device struct
 *
 * @return N/A
 */
static void uart_cmsdk_apb_irq_err_disable(struct device *dev)
{
	ARG_UNUSED(dev);
}

/**
 * @brief Verify if Tx or Rx interrupt is pending
 *
 * @param dev UART device struct
 *
 * @return 1 if Tx or Rx interrupt is pending, 0 otherwise
 */
static int uart_cmsdk_apb_irq_is_pending(struct device *dev)
{
	/* Return true if rx buffer full or tx buffer empty */
	return (UART_STRUCT(dev)->state & (UART_RX_BF | UART_TX_BF))
					!= UART_TX_BF;
}

/**
 * @brief Update the interrupt status
 *
 * @param dev UART device struct
 *
 * @return always 1
 */
static int uart_cmsdk_apb_irq_update(struct device *dev)
{
	return 1;
}

/**
 * @brief Set the callback function pointer for an Interrupt.
 *
 * @param dev UART device structure
 * @param cb Callback function pointer.
 *
 * @return N/A
 */
static void uart_cmsdk_apb_irq_callback_set(struct device *dev,
					    uart_irq_callback_t cb)
{
	DEV_DATA(dev)->irq_cb = cb;
}

/**
 * @brief Interrupt service routine.
 *
 * Calls the callback function, if exists.
 *
 * @param arg argument to interrupt service routine.
 *
 * @return N/A
 */
void uart_cmsdk_apb_isr(void *arg)
{
	struct device *dev = arg;
	volatile struct uart_cmsdk_apb *uart = UART_STRUCT(dev);
	struct uart_cmsdk_apb_dev_data *data = DEV_DATA(dev);

	/* Clear pending interrupts */
	uart->intclear = UART_RX_IN | UART_TX_IN;

	/* Verify if the callback has been registered */
	if (data->irq_cb) {
		data->irq_cb(dev);
	}
}

#endif /* CONFIG_UART_INTERRUPT_DRIVEN */


static const struct uart_driver_api uart_cmsdk_apb_driver_api = {
	.poll_in = uart_cmsdk_apb_poll_in,
	.poll_out = uart_cmsdk_apb_poll_out,
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	.fifo_fill = uart_cmsdk_apb_fifo_fill,
	.fifo_read = uart_cmsdk_apb_fifo_read,
	.irq_tx_enable = uart_cmsdk_apb_irq_tx_enable,
	.irq_tx_disable = uart_cmsdk_apb_irq_tx_disable,
	.irq_tx_ready = uart_cmsdk_apb_irq_tx_ready,
	.irq_rx_enable = uart_cmsdk_apb_irq_rx_enable,
	.irq_rx_disable = uart_cmsdk_apb_irq_rx_disable,
	.irq_tx_complete = uart_cmsdk_apb_irq_tx_complete,
	.irq_rx_ready = uart_cmsdk_apb_irq_rx_ready,
	.irq_err_enable = uart_cmsdk_apb_irq_err_enable,
	.irq_err_disable = uart_cmsdk_apb_irq_err_disable,
	.irq_is_pending = uart_cmsdk_apb_irq_is_pending,
	.irq_update = uart_cmsdk_apb_irq_update,
	.irq_callback_set = uart_cmsdk_apb_irq_callback_set,
#endif /* CONFIG_UART_INTERRUPT_DRIVEN */
};

#ifdef CONFIG_UART_CMSDK_APB_PORT0

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
static void uart_cmsdk_apb_irq_config_func_0(struct device *dev);
#endif

static const struct uart_device_config uart_cmsdk_apb_dev_cfg_0 = {
	.base = (u8_t *)CMSDK_APB_UART0,
	.sys_clk_freq = CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC,
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	.irq_config_func = uart_cmsdk_apb_irq_config_func_0,
#endif
};

static struct uart_cmsdk_apb_dev_data uart_cmsdk_apb_dev_data_0 = {
	.baud_rate = CONFIG_UART_CMSDK_APB_PORT0_BAUD_RATE,
	.uart_cc_as = {.bus = CMSDK_APB, .state = SOC_ACTIVE,
		       .device = CMSDK_APB_UART0,},
	.uart_cc_ss = {.bus = CMSDK_APB, .state = SOC_SLEEP,
		       .device = CMSDK_APB_UART0,},
	.uart_cc_dss = {.bus = CMSDK_APB, .state = SOC_DEEPSLEEP,
			.device = CMSDK_APB_UART0,},
};

DEVICE_AND_API_INIT(uart_cmsdk_apb_0,
		    CONFIG_UART_CMSDK_APB_PORT0_NAME,
		    &uart_cmsdk_apb_init,
		    &uart_cmsdk_apb_dev_data_0,
		    &uart_cmsdk_apb_dev_cfg_0, PRE_KERNEL_1,
		    CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &uart_cmsdk_apb_driver_api);

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
#ifdef CMSDK_APB_UART_0_IRQ
static void uart_cmsdk_apb_irq_config_func_0(struct device *dev)
{
	IRQ_CONNECT(CMSDK_APB_UART_0_IRQ,
		    CONFIG_UART_CMSDK_APB_PORT0_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_0),
		    0);
	irq_enable(CMSDK_APB_UART_0_IRQ);
}
#else
static void uart_cmsdk_apb_irq_config_func_0(struct device *dev)
{
	IRQ_CONNECT(CMSDK_APB_UART_0_IRQ_TX,
		    CONFIG_UART_CMSDK_APB_PORT0_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_0),
		    0);
	irq_enable(CMSDK_APB_UART_0_IRQ_TX);

	IRQ_CONNECT(CMSDK_APB_UART_0_IRQ_RX,
		    CONFIG_UART_CMSDK_APB_PORT0_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_0),
		    0);
	irq_enable(CMSDK_APB_UART_0_IRQ_RX);
}
#endif
#endif

#endif /* CONFIG_UART_CMSDK_APB_PORT0 */

#ifdef CONFIG_UART_CMSDK_APB_PORT1

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
static void uart_cmsdk_apb_irq_config_func_1(struct device *dev);
#endif

static const struct uart_device_config uart_cmsdk_apb_dev_cfg_1 = {
	.base = (u8_t *)CMSDK_APB_UART1,
	.sys_clk_freq = CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC,
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	.irq_config_func = uart_cmsdk_apb_irq_config_func_1,
#endif
};

static struct uart_cmsdk_apb_dev_data uart_cmsdk_apb_dev_data_1 = {
	.baud_rate = CONFIG_UART_CMSDK_APB_PORT1_BAUD_RATE,
	.uart_cc_as = {.bus = CMSDK_APB, .state = SOC_ACTIVE,
		       .device = CMSDK_APB_UART1,},
	.uart_cc_ss = {.bus = CMSDK_APB, .state = SOC_SLEEP,
		       .device = CMSDK_APB_UART1,},
	.uart_cc_dss = {.bus = CMSDK_APB, .state = SOC_DEEPSLEEP,
			.device = CMSDK_APB_UART1,},
};

DEVICE_AND_API_INIT(uart_cmsdk_apb_1,
		    CONFIG_UART_CMSDK_APB_PORT1_NAME,
		    &uart_cmsdk_apb_init,
		    &uart_cmsdk_apb_dev_data_1,
		    &uart_cmsdk_apb_dev_cfg_1, PRE_KERNEL_1,
		    CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &uart_cmsdk_apb_driver_api);

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
#ifdef CMSDK_APB_UART_1_IRQ
static void uart_cmsdk_apb_irq_config_func_1(struct device *dev)
{
	IRQ_CONNECT(CMSDK_APB_UART_1_IRQ,
		    CONFIG_UART_CMSDK_APB_PORT1_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_1),
		    0);
	irq_enable(CMSDK_APB_UART_1_IRQ);
}
#else
static void uart_cmsdk_apb_irq_config_func_1(struct device *dev)
{
	IRQ_CONNECT(CMSDK_APB_UART_1_IRQ_TX,
		    CONFIG_UART_CMSDK_APB_PORT1_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_1),
		    0);
	irq_enable(CMSDK_APB_UART_1_IRQ_TX);

	IRQ_CONNECT(CMSDK_APB_UART_1_IRQ_RX,
		    CONFIG_UART_CMSDK_APB_PORT1_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_1),
		    0);
	irq_enable(CMSDK_APB_UART_1_IRQ_RX);
}
#endif
#endif

#endif /* CONFIG_UART_CMSDK_APB_PORT1 */

#ifdef CONFIG_UART_CMSDK_APB_PORT2

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
static void uart_cmsdk_apb_irq_config_func_2(struct device *dev);
#endif

static const struct uart_device_config uart_cmsdk_apb_dev_cfg_2 = {
	.base = (u8_t *)CMSDK_APB_UART2,
	.sys_clk_freq = CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC,
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	.irq_config_func = uart_cmsdk_apb_irq_config_func_2,
#endif
};

static struct uart_cmsdk_apb_dev_data uart_cmsdk_apb_dev_data_2 = {
	.baud_rate = CONFIG_UART_CMSDK_APB_PORT2_BAUD_RATE,
	.uart_cc_as = {.bus = CMSDK_APB, .state = SOC_ACTIVE,
		       .device = CMSDK_APB_UART2,},
	.uart_cc_ss = {.bus = CMSDK_APB, .state = SOC_SLEEP,
		       .device = CMSDK_APB_UART2,},
	.uart_cc_dss = {.bus = CMSDK_APB, .state = SOC_DEEPSLEEP,
			.device = CMSDK_APB_UART2,},
};

DEVICE_AND_API_INIT(uart_cmsdk_apb_2,
		    CONFIG_UART_CMSDK_APB_PORT2_NAME,
		    &uart_cmsdk_apb_init,
		    &uart_cmsdk_apb_dev_data_2,
		    &uart_cmsdk_apb_dev_cfg_2, PRE_KERNEL_1,
		    CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &uart_cmsdk_apb_driver_api);

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
#ifdef CMSDK_APB_UART_2_IRQ
static void uart_cmsdk_apb_irq_config_func_2(struct device *dev)
{
	IRQ_CONNECT(CMSDK_APB_UART_2_IRQ,
		    CONFIG_UART_CMSDK_APB_PORT2_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_2),
		    0);
	irq_enable(CMSDK_APB_UART_2_IRQ);
}
#else
static void uart_cmsdk_apb_irq_config_func_2(struct device *dev)
{
	IRQ_CONNECT(CMSDK_APB_UART_2_IRQ_TX,
		    CONFIG_UART_CMSDK_APB_PORT2_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_2),
		    0);
	irq_enable(CMSDK_APB_UART_2_IRQ_TX);

	IRQ_CONNECT(CMSDK_APB_UART_2_IRQ_RX,
		    CONFIG_UART_CMSDK_APB_PORT2_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_2),
		    0);
	irq_enable(CMSDK_APB_UART_2_IRQ_RX);
}
#endif
#endif

#endif /* CONFIG_UART_CMSDK_APB_PORT2 */

#ifdef CONFIG_UART_CMSDK_APB_PORT3

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
static void uart_cmsdk_apb_irq_config_func_3(struct device *dev);
#endif

static const struct uart_device_config uart_cmsdk_apb_dev_cfg_3 = {
	.base = (u8_t *)CMSDK_APB_UART3,
	.sys_clk_freq = CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC,
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	.irq_config_func = uart_cmsdk_apb_irq_config_func_3,
#endif
};

static struct uart_cmsdk_apb_dev_data uart_cmsdk_apb_dev_data_3 = {
	.baud_rate = CONFIG_UART_CMSDK_APB_PORT3_BAUD_RATE,
	.uart_cc_as = {.bus = CMSDK_APB, .state = SOC_ACTIVE,
		       .device = CMSDK_APB_UART3,},
	.uart_cc_ss = {.bus = CMSDK_APB, .state = SOC_SLEEP,
		       .device = CMSDK_APB_UART3,},
	.uart_cc_dss = {.bus = CMSDK_APB, .state = SOC_DEEPSLEEP,
			.device = CMSDK_APB_UART3,},
};

DEVICE_AND_API_INIT(uart_cmsdk_apb_3,
		    CONFIG_UART_CMSDK_APB_PORT3_NAME,
		    &uart_cmsdk_apb_init,
		    &uart_cmsdk_apb_dev_data_3,
		    &uart_cmsdk_apb_dev_cfg_3, PRE_KERNEL_1,
		    CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &uart_cmsdk_apb_driver_api);

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
#ifdef CMSDK_APB_UART_3_IRQ
static void uart_cmsdk_apb_irq_config_func_3(struct device *dev)
{
	IRQ_CONNECT(CMSDK_APB_UART_3_IRQ,
		    CONFIG_UART_CMSDK_APB_PORT3_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_3),
		    0);
	irq_enable(CMSDK_APB_UART_3_IRQ);
}
#else
static void uart_cmsdk_apb_irq_config_func_3(struct device *dev)
{
	IRQ_CONNECT(CMSDK_APB_UART_3_IRQ_TX,
		    CONFIG_UART_CMSDK_APB_PORT3_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_3),
		    0);
	irq_enable(CMSDK_APB_UART_3_IRQ_TX);

	IRQ_CONNECT(CMSDK_APB_UART_3_IRQ_RX,
		    CONFIG_UART_CMSDK_APB_PORT3_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_3),
		    0);
	irq_enable(CMSDK_APB_UART_3_IRQ_RX);
}
#endif
#endif

#endif /* CONFIG_UART_CMSDK_APB_PORT3 */

#ifdef CONFIG_UART_CMSDK_APB_PORT4

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
static void uart_cmsdk_apb_irq_config_func_4(struct device *dev);
#endif

static const struct uart_device_config uart_cmsdk_apb_dev_cfg_4 = {
	.base = (u8_t *)CMSDK_APB_UART4,
	.sys_clk_freq = CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC,
#ifdef CONFIG_UART_INTERRUPT_DRIVEN
	.irq_config_func = uart_cmsdk_apb_irq_config_func_4,
#endif
};

static struct uart_cmsdk_apb_dev_data uart_cmsdk_apb_dev_data_4 = {
	.baud_rate = CONFIG_UART_CMSDK_APB_PORT4_BAUD_RATE,
	.uart_cc_as = {.bus = CMSDK_APB, .state = SOC_ACTIVE,
		       .device = CMSDK_APB_UART4,},
	.uart_cc_ss = {.bus = CMSDK_APB, .state = SOC_SLEEP,
		       .device = CMSDK_APB_UART4,},
	.uart_cc_dss = {.bus = CMSDK_APB, .state = SOC_DEEPSLEEP,
			.device = CMSDK_APB_UART4,},
};

DEVICE_AND_API_INIT(uart_cmsdk_apb_4,
		    CONFIG_UART_CMSDK_APB_PORT4_NAME,
		    &uart_cmsdk_apb_init,
		    &uart_cmsdk_apb_dev_data_4,
		    &uart_cmsdk_apb_dev_cfg_4, PRE_KERNEL_1,
		    CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &uart_cmsdk_apb_driver_api);

#ifdef CONFIG_UART_INTERRUPT_DRIVEN
#ifdef CMSDK_APB_UART_4_IRQ
static void uart_cmsdk_apb_irq_config_func_4(struct device *dev)
{
	IRQ_CONNECT(CMSDK_APB_UART_4_IRQ,
		    CONFIG_UART_CMSDK_APB_PORT4_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_4),
		    0);
	irq_enable(CMSDK_APB_UART_4_IRQ);
}
#else
static void uart_cmsdk_apb_irq_config_func_4(struct device *dev)
{
	IRQ_CONNECT(CMSDK_APB_UART_4_IRQ_TX,
		    CONFIG_UART_CMSDK_APB_PORT4_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_4),
		    0);
	irq_enable(CMSDK_APB_UART_4_IRQ_TX);

	IRQ_CONNECT(CMSDK_APB_UART_4_IRQ_RX,
		    CONFIG_UART_CMSDK_APB_PORT4_IRQ_PRI,
		    uart_cmsdk_apb_isr,
		    DEVICE_GET(uart_cmsdk_apb_4),
		    0);
	irq_enable(CMSDK_APB_UART_4_IRQ_RX);
}
#endif
#endif

#endif /* CONFIG_UART_CMSDK_APB_PORT4 */
