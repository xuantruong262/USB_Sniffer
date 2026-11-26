/*
 * Pico USB Sniffer - continuous streaming USB Low/Full Speed sniffer
 *
 * Capture engine derived from pico-usb-sniffer-lite
 *   https://github.com/therealdreg/pico-usb-sniffer-lite
 *   https://github.com/ataradov/usb-sniffer-lite
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022, Alex Taradov <alex@taradov.com>. All rights reserved.
 * Copyright (c) 2025, David Reguera Garcia aka Dreg
 *
 * Architecture (built for hours-long continuous streaming):
 *
 *   PIO1 ──START──► PIO0 ──RX FIFO──► core1 ──raw ring (128 KB)──► core0 ──CDC──► PC
 *
 *   core1 : dedicated, interrupt free loop. Moves raw PIO words into a large
 *           lock-free ring buffer and timestamps every end-of-packet.
 *           Packets that do not fit are dropped *whole* and counted.
 *   core0 : table driven NRZI/bit-unstuff decoder, CRC checks, optional
 *           folding of idle traffic (SOF / keep-alive / IN+NAK polling),
 *           binary record framing, TinyUSB CDC, command handling.
 *           It never blocks on USB: if the PC is slow the ring absorbs bursts
 *           and the overflow is reported as REC_DROP instead of stalling.
 *
 * Wiring:  GP10 = D+, GP11 = D-, GND = GND, GP12 internal (leave unconnected)
 */

#include <string.h>

#include "hardware/clocks.h"
#include "hardware/gpio.h"
#include "hardware/pio.h"
#include "hardware/structs/timer.h"
#include "hardware/sync.h"
#include "pico/bootrom.h"
#include "pico/multicore.h"
#include "pico/stdlib.h"
#include "tusb.h"

#include "protocol.h"
#include "usb_sniffer.pio.h"

#define FW_VERSION 2

// D+ and D- must be consecutive (D- = D+ + 1), START = D+ + 2
#define DP_PIN 10
#define DM_PIN 11
#define START_PIN 12

#ifdef PICO_DEFAULT_LED_PIN
#define LED_PIN PICO_DEFAULT_LED_PIN
#endif

#define SNIFFER_CLK_KHZ 120000

// Raw capture ring buffer: 32768 words = 128 KB (~85 ms of 100% busy FS bus)
#define RING_BITS 15
#define RING_WORDS (1u << RING_BITS)
#define RING_MASK (RING_WORDS - 1u)

#define MAX_PKT_BYTES 1100        // FS isochronous max is 1023 + PID + CRC + SYNC
#define MIN_TX_SPACE 1500         // worst case output of processing one packet
#define FOLD_FLUSH_US 100000      // emit fold summaries at least every 100 ms
#define PENDING_IN_TIMEOUT_US 3000
#define STATUS_PERIOD_US 500000

enum
{
    Pid_Reserved = 0,
    Pid_Out = 1,
    Pid_In = 9,
    Pid_Sof = 5,
    Pid_Setup = 13,
    Pid_Data0 = 3,
    Pid_Data1 = 11,
    Pid_Data2 = 7,
    Pid_MData = 15,
    Pid_Ack = 2,
    Pid_Nak = 10,
    Pid_Stall = 14,
    Pid_Nyet = 6,
    Pid_PreErr = 12,
    Pid_Split = 8,
    Pid_Ping = 4,
};

// ---------------------------------------------------------------------------
// Shared state core0 <-> core1
// ---------------------------------------------------------------------------
static uint32_t g_ring[RING_WORDS];
static volatile uint32_t g_wr_commit; // core1: index after last complete packet
static volatile uint32_t g_rd;        // core0: index of next word to consume
static volatile bool g_run_req;
static volatile bool g_core1_active;
static volatile uint32_t g_c1_packets;
static volatile uint32_t g_c1_dropped;
static volatile uint32_t g_c1_max_fill;
static volatile uint32_t g_c1_rxstall;

// ---------------------------------------------------------------------------
// CRC tables (from pico-usb-sniffer-lite)
// ---------------------------------------------------------------------------
static const uint16_t crc16_usb_tab[256] = {
    0x0000, 0xc0c1, 0xc181, 0x0140, 0xc301, 0x03c0, 0x0280, 0xc241, 0xc601, 0x06c0, 0x0780, 0xc741, 0x0500, 0xc5c1,
    0xc481, 0x0440, 0xcc01, 0x0cc0, 0x0d80, 0xcd41, 0x0f00, 0xcfc1, 0xce81, 0x0e40, 0x0a00, 0xcac1, 0xcb81, 0x0b40,
    0xc901, 0x09c0, 0x0880, 0xc841, 0xd801, 0x18c0, 0x1980, 0xd941, 0x1b00, 0xdbc1, 0xda81, 0x1a40, 0x1e00, 0xdec1,
    0xdf81, 0x1f40, 0xdd01, 0x1dc0, 0x1c80, 0xdc41, 0x1400, 0xd4c1, 0xd581, 0x1540, 0xd701, 0x17c0, 0x1680, 0xd641,
    0xd201, 0x12c0, 0x1380, 0xd341, 0x1100, 0xd1c1, 0xd081, 0x1040, 0xf001, 0x30c0, 0x3180, 0xf141, 0x3300, 0xf3c1,
    0xf281, 0x3240, 0x3600, 0xf6c1, 0xf781, 0x3740, 0xf501, 0x35c0, 0x3480, 0xf441, 0x3c00, 0xfcc1, 0xfd81, 0x3d40,
    0xff01, 0x3fc0, 0x3e80, 0xfe41, 0xfa01, 0x3ac0, 0x3b80, 0xfb41, 0x3900, 0xf9c1, 0xf881, 0x3840, 0x2800, 0xe8c1,
    0xe981, 0x2940, 0xeb01, 0x2bc0, 0x2a80, 0xea41, 0xee01, 0x2ec0, 0x2f80, 0xef41, 0x2d00, 0xedc1, 0xec81, 0x2c40,
    0xe401, 0x24c0, 0x2580, 0xe541, 0x2700, 0xe7c1, 0xe681, 0x2640, 0x2200, 0xe2c1, 0xe381, 0x2340, 0xe101, 0x21c0,
    0x2080, 0xe041, 0xa001, 0x60c0, 0x6180, 0xa141, 0x6300, 0xa3c1, 0xa281, 0x6240, 0x6600, 0xa6c1, 0xa781, 0x6740,
    0xa501, 0x65c0, 0x6480, 0xa441, 0x6c00, 0xacc1, 0xad81, 0x6d40, 0xaf01, 0x6fc0, 0x6e80, 0xae41, 0xaa01, 0x6ac0,
    0x6b80, 0xab41, 0x6900, 0xa9c1, 0xa881, 0x6840, 0x7800, 0xb8c1, 0xb981, 0x7940, 0xbb01, 0x7bc0, 0x7a80, 0xba41,
    0xbe01, 0x7ec0, 0x7f80, 0xbf41, 0x7d00, 0xbdc1, 0xbc81, 0x7c40, 0xb401, 0x74c0, 0x7580, 0xb541, 0x7700, 0xb7c1,
    0xb681, 0x7640, 0x7200, 0xb2c1, 0xb381, 0x7340, 0xb101, 0x71c0, 0x7080, 0xb041, 0x5000, 0x90c1, 0x9181, 0x5140,
    0x9301, 0x53c0, 0x5280, 0x9241, 0x9601, 0x56c0, 0x5780, 0x9741, 0x5500, 0x95c1, 0x9481, 0x5440, 0x9c01, 0x5cc0,
    0x5d80, 0x9d41, 0x5f00, 0x9fc1, 0x9e81, 0x5e40, 0x5a00, 0x9ac1, 0x9b81, 0x5b40, 0x9901, 0x59c0, 0x5880, 0x9841,
    0x8801, 0x48c0, 0x4980, 0x8941, 0x4b00, 0x8bc1, 0x8a81, 0x4a40, 0x4e00, 0x8ec1, 0x8f81, 0x4f40, 0x8d01, 0x4dc0,
    0x4c80, 0x8c41, 0x4400, 0x84c1, 0x8581, 0x4540, 0x8701, 0x47c0, 0x4680, 0x8641, 0x8201, 0x42c0, 0x4380, 0x8341,
    0x4100, 0x81c1, 0x8081, 0x4040,
};

static const uint8_t crc5_usb_tab[256] = {
    0x00, 0x0e, 0x1c, 0x12, 0x11, 0x1f, 0x0d, 0x03, 0x0b, 0x05, 0x17, 0x19, 0x1a, 0x14, 0x06, 0x08, 0x16, 0x18, 0x0a,
    0x04, 0x07, 0x09, 0x1b, 0x15, 0x1d, 0x13, 0x01, 0x0f, 0x0c, 0x02, 0x10, 0x1e, 0x05, 0x0b, 0x19, 0x17, 0x14, 0x1a,
    0x08, 0x06, 0x0e, 0x00, 0x12, 0x1c, 0x1f, 0x11, 0x03, 0x0d, 0x13, 0x1d, 0x0f, 0x01, 0x02, 0x0c, 0x1e, 0x10, 0x18,
    0x16, 0x04, 0x0a, 0x09, 0x07, 0x15, 0x1b, 0x0a, 0x04, 0x16, 0x18, 0x1b, 0x15, 0x07, 0x09, 0x01, 0x0f, 0x1d, 0x13,
    0x10, 0x1e, 0x0c, 0x02, 0x1c, 0x12, 0x00, 0x0e, 0x0d, 0x03, 0x11, 0x1f, 0x17, 0x19, 0x0b, 0x05, 0x06, 0x08, 0x1a,
    0x14, 0x0f, 0x01, 0x13, 0x1d, 0x1e, 0x10, 0x02, 0x0c, 0x04, 0x0a, 0x18, 0x16, 0x15, 0x1b, 0x09, 0x07, 0x19, 0x17,
    0x05, 0x0b, 0x08, 0x06, 0x14, 0x1a, 0x12, 0x1c, 0x0e, 0x00, 0x03, 0x0d, 0x1f, 0x11, 0x14, 0x1a, 0x08, 0x06, 0x05,
    0x0b, 0x19, 0x17, 0x1f, 0x11, 0x03, 0x0d, 0x0e, 0x00, 0x12, 0x1c, 0x02, 0x0c, 0x1e, 0x10, 0x13, 0x1d, 0x0f, 0x01,
    0x09, 0x07, 0x15, 0x1b, 0x18, 0x16, 0x04, 0x0a, 0x11, 0x1f, 0x0d, 0x03, 0x00, 0x0e, 0x1c, 0x12, 0x1a, 0x14, 0x06,
    0x08, 0x0b, 0x05, 0x17, 0x19, 0x07, 0x09, 0x1b, 0x15, 0x16, 0x18, 0x0a, 0x04, 0x0c, 0x02, 0x10, 0x1e, 0x1d, 0x13,
    0x01, 0x0f, 0x1e, 0x10, 0x02, 0x0c, 0x0f, 0x01, 0x13, 0x1d, 0x15, 0x1b, 0x09, 0x07, 0x04, 0x0a, 0x18, 0x16, 0x08,
    0x06, 0x14, 0x1a, 0x19, 0x17, 0x05, 0x0b, 0x03, 0x0d, 0x1f, 0x11, 0x12, 0x1c, 0x0e, 0x00, 0x1b, 0x15, 0x07, 0x09,
    0x0a, 0x04, 0x16, 0x18, 0x10, 0x1e, 0x0c, 0x02, 0x01, 0x0f, 0x1d, 0x13, 0x0d, 0x03, 0x11, 0x1f, 0x1c, 0x12, 0x00,
    0x0e, 0x06, 0x08, 0x1a, 0x14, 0x17, 0x19, 0x0b, 0x05,
};

static uint16_t crc16_usb(const uint8_t *data, int size)
{
    uint16_t crc = 0xffff;
    for (int i = 0; i < size; i++)
    {
        crc = crc16_usb_tab[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    }
    return crc;
}

static uint8_t crc5_usb(const uint8_t *data, int size)
{
    uint8_t crc = 0xff;
    for (int i = 0; i < size; i++)
    {
        crc = crc5_usb_tab[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    }
    return crc;
}

// ---------------------------------------------------------------------------
// Table driven bit unstuffing
//   index : (stuff_state << L) | L decoded bits (first bit = MSB)
//   entry : [7:0] output bits (first bit = bit 0), [11:8] output bit count,
//           [14:12] new stuff state (0..6), [15] stuff error
// ---------------------------------------------------------------------------
static uint32_t g_unstuff8[7 * 256];
static uint32_t g_unstuff7[7 * 128];

static uint32_t unstuff_entry(uint32_t state, uint32_t bits, int len)
{
    uint32_t out = 0, cnt = 0, err = 0;
    for (int i = len - 1; i >= 0; i--)
    {
        uint32_t bit = (bits >> i) & 1;
        if (state == 6)
        {
            if (bit)
            {
                err = 1;
            }
            state = 0;
            continue;
        }
        state = bit ? state + 1 : 0;
        out |= bit << cnt;
        cnt++;
    }
    return out | (cnt << 8) | (state << 12) | (err << 15);
}

static void build_unstuff_tables(void)
{
    for (uint32_t s = 0; s < 7; s++)
    {
        for (uint32_t x = 0; x < 256; x++)
        {
            g_unstuff8[(s << 8) | x] = unstuff_entry(s, x, 8);
        }
        for (uint32_t x = 0; x < 128; x++)
        {
            g_unstuff7[(s << 7) | x] = unstuff_entry(s, x, 7);
        }
    }
}

// ---------------------------------------------------------------------------
// Tap pins (D+ / D-)
// ---------------------------------------------------------------------------
// RP2040 pad input Schmitt trigger. Its hysteresis lowers the falling
// threshold; near the driving end of the cable a FS falling edge first steps
// to an intermediate level and only settles when the reflection returns, so
// K states (D+ low) of that driver can be seen late or missed (PID/CRC/STUFF
// errors on device responses that the host ACKed). Default off; build with
// -DSNIFFER_INPUT_SCHMITT=1 to restore the previous behaviour.
#ifndef SNIFFER_INPUT_SCHMITT
#define SNIFFER_INPUT_SCHMITT 0
#endif

static void tap_pin_init(uint pin)
{
    gpio_init(pin);
    gpio_set_dir(pin, GPIO_IN);
    gpio_disable_pulls(pin); // passive tap: do not load the bus
    gpio_set_input_hysteresis_enabled(pin, SNIFFER_INPUT_SCHMITT != 0);
}

static void tap_pins_init(void)
{
    tap_pin_init(DP_PIN);
    tap_pin_init(DM_PIN);
}

// ---------------------------------------------------------------------------
// PIO setup
// ---------------------------------------------------------------------------
static void pio_teardown(void)
{
    pio_sm_set_enabled(pio0, 0, false);
    pio_sm_set_enabled(pio1, 0, false);
    pio_clear_instruction_memory(pio0);
    pio_clear_instruction_memory(pio1);
}

static void pio_setup(bool fs)
{
    pio_teardown();

    static uint16_t instr[32];
    memcpy(instr, tar_pio0_program_instructions, sizeof(instr));
    const uint16_t *tpl =
        fs ? usb_full_speed_template_program_instructions : usb_low_speed_template_program_instructions;
    instr[1] = tpl[0];
    instr[2] = tpl[1];
    struct pio_program prog0 = tar_pio0_program;
    prog0.instructions = instr;

    float div = (float)clock_get_hz(clk_sys) / (fs ? 120000000.0f : 15000000.0f);

    tap_pins_init();
    gpio_init(START_PIN);
    gpio_set_dir(START_PIN, GPIO_OUT);
    gpio_put(START_PIN, false);

    // PIO1: start synchroniser, drives START
    pio_gpio_init(pio1, START_PIN);
    uint off1 = pio_add_program(pio1, &tar_pio1_program);
    pio_sm_set_consecutive_pindirs(pio1, 0, START_PIN, 1, true);
    pio_sm_config c1 = tar_pio1_program_get_default_config(off1);
    sm_config_set_set_pins(&c1, START_PIN, 1);
    sm_config_set_in_pins(&c1, DP_PIN);
    sm_config_set_in_shift(&c1, false, false, 32);
    sm_config_set_out_shift(&c1, false, false, 32);
    sm_config_set_clkdiv(&c1, div);
    pio_sm_init(pio1, 0, off1, &c1);
    pio_sm_set_enabled(pio1, 0, false);

    // PIO0: sampler, loaded at offset 0, entry point instruction 31
    pio_add_program_at_offset(pio0, &prog0, 0);
    pio_sm_set_consecutive_pindirs(pio0, 0, DP_PIN, 3, false);
    pio_sm_config c0 = tar_pio0_program_get_default_config(0);
    sm_config_set_in_pins(&c0, DP_PIN);
    sm_config_set_jmp_pin(&c0, fs ? DP_PIN : DM_PIN);
    sm_config_set_in_shift(&c0, false, true, 31);
    sm_config_set_out_shift(&c0, false, false, 32);
    sm_config_set_fifo_join(&c0, PIO_FIFO_JOIN_RX);
    sm_config_set_clkdiv(&c0, div);
    pio_sm_init(pio0, 0, 31, &c0);
    pio_sm_set_enabled(pio0, 0, false);
    pio_sm_clear_fifos(pio0, 0);
    pio0->fdebug = 0xffffffffu;
}

// ---------------------------------------------------------------------------
// core1: capture loop (no interrupts, runs from RAM)
// ---------------------------------------------------------------------------
static void __no_inline_not_in_flash_func(capture_loop)(void)
{
    pio_hw_t *p = pio0;
    const uint32_t empty_mask = 1u << (PIO_FSTAT_RXEMPTY_LSB + 0);
    const uint32_t stall_mask = 1u << (PIO_FDEBUG_RXSTALL_LSB + 0);
    uint32_t wr = g_wr_commit;
    uint32_t commit = wr;
    uint32_t max_fill = 0;
    uint32_t pkts = 0;
    uint32_t drops = 0;
    bool dropping = false;

    pio_sm_set_enabled(pio0, 0, true);
    pio_sm_set_enabled(pio1, 0, true);

    while (true)
    {
        if (p->fstat & empty_mask)
        {
            if (!g_run_req)
            {
                break;
            }
            if (p->fdebug & stall_mask)
            {
                p->fdebug = stall_mask;
                g_c1_rxstall++;
            }
            continue;
        }

        uint32_t v = p->rxf[0];
        uint32_t used = wr - g_rd;

        if (!(v & 0x80000000u))
        {
            // data word
            if (dropping)
            {
                continue;
            }
            if (used >= RING_WORDS - 2u)
            {
                dropping = true;
                continue;
            }
            g_ring[wr & RING_MASK] = v;
            wr++;
        }
        else
        {
            // end of packet: size word + timestamp
            uint32_t t = timer_hw->timerawl;
            if (dropping || used > RING_WORDS - 2u)
            {
                dropping = false;
                wr = commit;
                g_c1_dropped = ++drops;
                continue;
            }
            g_ring[wr & RING_MASK] = v;
            g_ring[(wr + 1) & RING_MASK] = t;
            wr += 2;
            __dmb();
            g_wr_commit = commit = wr;
            g_c1_packets = ++pkts;
            if (used > max_fill)
            {
                g_c1_max_fill = max_fill = used;
            }
        }
    }

    pio_sm_set_enabled(pio0, 0, false);
    pio_sm_set_enabled(pio1, 0, false);
}

static void __no_inline_not_in_flash_func(core1_main)(void)
{
    while (true)
    {
        while (!g_run_req)
        {
            tight_loop_contents();
        }
        g_core1_active = true;
        capture_loop();
        __dmb();
        g_core1_active = false;
    }
}

// ---------------------------------------------------------------------------
// Record output
// ---------------------------------------------------------------------------
static uint8_t g_rec[MAX_PKT_BYTES + 64];
static int g_rec_len;
static uint32_t g_records_out;

static inline void put_u8(uint8_t v)
{
    g_rec[g_rec_len++] = v;
}
static inline void put_u16(uint16_t v)
{
    g_rec[g_rec_len++] = (uint8_t)v;
    g_rec[g_rec_len++] = (uint8_t)(v >> 8);
}
static inline void put_u32(uint32_t v)
{
    put_u16((uint16_t)v);
    put_u16((uint16_t)(v >> 16));
}
static inline void put_u64(uint64_t v)
{
    put_u32((uint32_t)v);
    put_u32((uint32_t)(v >> 32));
}
static inline void put_bytes(const void *d, int n)
{
    memcpy(&g_rec[g_rec_len], d, n);
    g_rec_len += n;
}

static void rec_begin(uint8_t type)
{
    g_rec_len = 0;
    put_u8(PROTO_MAGIC);
    put_u8(type);
    put_u16(0);
}

static void rec_end(void)
{
    uint16_t len = (uint16_t)(g_rec_len - 4);
    g_rec[2] = (uint8_t)len;
    g_rec[3] = (uint8_t)(len >> 8);
    if (tud_cdc_connected())
    {
        tud_cdc_write(g_rec, g_rec_len);
        g_records_out++;
    }
}

static void send_text(const char *s)
{
    rec_begin(REC_TEXT);
    put_bytes(s, (int)strlen(s));
    rec_end();
}

static void send_info(void)
{
    static const char txt[] = "Pico USB Sniffer fw " __DATE__ " " __TIME__;
    rec_begin(REC_INFO);
    put_u16(PROTO_VERSION);
    put_u16(FW_VERSION);
    put_u32(clock_get_hz(clk_sys));
    put_u32(RING_WORDS);
    put_u8(DP_PIN);
    put_u8(DM_PIN);
    put_bytes(txt, (int)strlen(txt));
    rec_end();
}

// ---------------------------------------------------------------------------
// Capture session state (core0)
// ---------------------------------------------------------------------------
enum
{
    STATE_IDLE,
    STATE_RUNNING,
    STATE_STOPPING
};

static int g_state = STATE_IDLE;
static bool g_fs;
static bool g_fold_sof;
static bool g_fold_nak;
static uint32_t g_reported_drops;
static uint32_t g_syncerr;
static uint64_t g_next_status;
static uint8_t g_stop_reason;

typedef struct
{
    bool valid;
    uint64_t ts;
    uint16_t nbits;
    uint8_t data[4];
} pending_in_t;

typedef struct
{
    bool open;
    uint64_t t_first;
    uint64_t t_last;
    uint32_t sof;
    uint32_t keepalive;
    uint32_t other_nak;
    uint16_t frame_first;
    uint16_t frame_last;
    uint8_t n;
    struct
    {
        uint8_t addr;
        uint8_t ep;
        uint32_t count;
    } e[FOLD_MAX_EP];
} fold_t;

static pending_in_t g_pin;
static fold_t g_fold;

static void send_packet(uint64_t ts, uint16_t nbits, uint16_t flags, const uint8_t *data, int n)
{
    rec_begin(REC_PACKET);
    put_u64(ts);
    put_u16(nbits);
    put_u16(flags);
    put_bytes(data, n);
    rec_end();
}

static void send_ts(uint8_t type, uint64_t ts)
{
    rec_begin(type);
    put_u64(ts);
    rec_end();
}

static void fold_flush(void)
{
    if (!g_fold.open)
    {
        return;
    }
    rec_begin(REC_FOLD);
    put_u64(g_fold.t_first);
    put_u64(g_fold.t_last);
    put_u32(g_fold.sof);
    put_u16(g_fold.frame_first);
    put_u16(g_fold.frame_last);
    put_u32(g_fold.keepalive);
    put_u32(g_fold.other_nak);
    put_u8(g_fold.n);
    for (int i = 0; i < g_fold.n; i++)
    {
        put_u8(g_fold.e[i].addr);
        put_u8(g_fold.e[i].ep);
        put_u32(g_fold.e[i].count);
    }
    rec_end();
    memset(&g_fold, 0, sizeof(g_fold));
}

static void fold_open(uint64_t ts)
{
    if (g_fold.open && (ts - g_fold.t_first) > FOLD_FLUSH_US)
    {
        fold_flush();
    }
    if (!g_fold.open)
    {
        g_fold.open = true;
        g_fold.t_first = ts;
    }
    g_fold.t_last = ts;
}

static void fold_add_nak(uint64_t ts, const uint8_t *in_tok)
{
    fold_open(ts);
    uint16_t v = (uint16_t)(in_tok[2] | (in_tok[3] << 8));
    uint8_t addr = v & 0x7f;
    uint8_t ep = (v >> 7) & 0xf;
    for (int i = 0; i < g_fold.n; i++)
    {
        if (g_fold.e[i].addr == addr && g_fold.e[i].ep == ep)
        {
            g_fold.e[i].count++;
            return;
        }
    }
    if (g_fold.n < FOLD_MAX_EP)
    {
        g_fold.e[g_fold.n].addr = addr;
        g_fold.e[g_fold.n].ep = ep;
        g_fold.e[g_fold.n].count = 1;
        g_fold.n++;
    }
    else
    {
        g_fold.other_nak++;
    }
}

static void pending_in_emit(void)
{
    if (g_pin.valid)
    {
        g_pin.valid = false;
        fold_flush();
        send_packet(g_pin.ts, g_pin.nbits, 0, g_pin.data, 4);
    }
}

// Handles one decoded packet: folding / forwarding
static void handle_packet(uint64_t ts, uint16_t nbits, uint16_t flags, const uint8_t *data, int n)
{
    int pid = (n >= 2) ? (data[1] & 0x0f) : -1;
    bool clean = (flags == 0);

    if (g_pin.valid)
    {
        if (clean && pid == Pid_Nak)
        {
            g_pin.valid = false;
            fold_add_nak(g_pin.ts, g_pin.data);
            g_fold.t_last = ts;
            return;
        }
        pending_in_emit();
    }

    if (clean && pid == Pid_Sof && g_fold_sof)
    {
        uint16_t frame = (uint16_t)(((data[3] << 8) | data[2]) & 0x7ff);
        fold_open(ts);
        if (g_fold.sof == 0 && g_fold.keepalive == 0)
        {
            g_fold.frame_first = frame;
        }
        g_fold.frame_last = frame;
        g_fold.sof++;
        return;
    }

    // IN polling of endpoint 0 is part of a control transfer (the PC tool
    // shows it as "[N POLL]" inside the transfer), so it is never folded
    if (clean && pid == Pid_In && g_fold_nak && n == 4 && (((data[3] << 8) | data[2]) & 0x0780) != 0)
    {
        g_pin.valid = true;
        g_pin.ts = ts;
        g_pin.nbits = nbits;
        memcpy(g_pin.data, data, 4);
        return;
    }

    fold_flush();
    send_packet(ts, nbits, flags, data, n);
}

static void handle_keepalive(uint64_t ts)
{
    pending_in_emit();
    if (g_fold_sof)
    {
        fold_open(ts);
        g_fold.keepalive++;
        return;
    }
    fold_flush();
    send_ts(REC_KEEPALIVE, ts);
}

// ---------------------------------------------------------------------------
// Packet decoder (NRZI + bit unstuff + checks), same semantics as the
// reference implementation, table driven for ~4x the throughput.
// ---------------------------------------------------------------------------
static uint8_t g_pkt[MAX_PKT_BYTES];

#define EMIT_ENTRY(e)                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        uint32_t _e = (e);                                                                                             \
        state = (_e >> 12) & 7;                                                                                        \
        stuff_err |= _e & 0x8000;                                                                                      \
        acc |= (_e & 0xff) << nacc;                                                                                    \
        nacc += (_e >> 8) & 0xf;                                                                                       \
        if (nacc >= 8)                                                                                                 \
        {                                                                                                              \
            if (n < MAX_PKT_BYTES)                                                                                     \
                g_pkt[n] = (uint8_t)acc;                                                                               \
            n++;                                                                                                       \
            acc >>= 8;                                                                                                 \
            nacc -= 8;                                                                                                 \
        }                                                                                                              \
    } while (0)

static int __not_in_flash_func(decode_packet)(uint32_t rd, uint32_t size, uint16_t *flags_out)
{
    int remaining = (int)size - 1; // the last sample is the SE0 bit
    uint32_t v = 0x80000000u;
    uint32_t acc = 0;
    uint32_t nacc = 0;
    uint32_t state = 0;
    uint32_t stuff_err = 0;
    uint16_t flags = 0;
    int n = 0;

    while (remaining > 0)
    {
        uint32_t w = g_ring[rd++ & RING_MASK];
        int bc;
        if (remaining < 31)
        {
            w <<= (30 - remaining);
            bc = remaining;
        }
        else
        {
            bc = 31;
        }
        uint32_t x = v ^ (w ^ (w << 1));
        uint32_t d = ~x; // NRZI decoded bits, first bit at bit 31
        v = x << bc;
        remaining -= bc;

        while (bc >= 8)
        {
            EMIT_ENTRY(g_unstuff8[(state << 8) | (d >> 24)]);
            d <<= 8;
            bc -= 8;
        }
        if (bc == 7)
        {
            EMIT_ENTRY(g_unstuff7[(state << 7) | (d >> 25)]);
        }
        else
        {
            while (bc--)
            {
                uint32_t bit = d >> 31;
                d <<= 1;
                if (state == 6)
                {
                    if (bit)
                    {
                        stuff_err = 1;
                    }
                    state = 0;
                    continue;
                }
                state = bit ? state + 1 : 0;
                acc |= bit << nacc;
                nacc++;
                if (nacc == 8)
                {
                    if (n < MAX_PKT_BYTES)
                    {
                        g_pkt[n] = (uint8_t)acc;
                    }
                    n++;
                    acc = 0;
                    nacc = 0;
                }
            }
        }
    }

    if (stuff_err)
    {
        flags |= PKT_ERR_STUFF;
    }
    if (nacc)
    {
        flags |= PKT_ERR_NBIT;
    }
    if (n > MAX_PKT_BYTES)
    {
        n = MAX_PKT_BYTES;
        flags |= PKT_TRUNCATED | PKT_ERR_SIZE;
    }

    if (n < 2)
    {
        flags |= PKT_ERR_SIZE;
        if (n == 1 && g_pkt[0] != (g_fs ? 0x80 : 0x81))
        {
            flags |= PKT_ERR_SYNC;
        }
        *flags_out = flags;
        return n;
    }

    if (g_pkt[0] != (g_fs ? 0x80 : 0x81))
    {
        flags |= PKT_ERR_SYNC;
    }

    int pid = g_pkt[1] & 0x0f;
    int npid = (~g_pkt[1] >> 4) & 0x0f;
    if (pid != npid || pid == Pid_Reserved)
    {
        flags |= PKT_ERR_PID;
    }

    if (pid == Pid_Sof || pid == Pid_In || pid == Pid_Out || pid == Pid_Setup || pid == Pid_Ping || pid == Pid_Split)
    {
        if ((pid == Pid_Split && n != 5) || (pid != Pid_Split && n != 4))
        {
            flags |= PKT_ERR_SIZE;
        }
        else if (crc5_usb(&g_pkt[2], n - 2) != 0x09)
        {
            flags |= PKT_ERR_CRC;
        }
    }
    else if (pid == Pid_Data0 || pid == Pid_Data1 || pid == Pid_Data2 || pid == Pid_MData)
    {
        if (n < 4)
        {
            flags |= PKT_ERR_SIZE;
        }
        else if (!(flags & PKT_TRUNCATED) && crc16_usb(&g_pkt[2], n - 2) != 0xb001)
        {
            flags |= PKT_ERR_CRC;
        }
    }

    *flags_out = flags;
    return n;
}

// Consumes one committed packet from the ring
static void __not_in_flash_func(process_one)(void)
{
    uint32_t rd = g_rd;
    __dmb();

    uint32_t i = rd;
    while (!(g_ring[i & RING_MASK] & 0x80000000u))
    {
        i++;
    }
    uint32_t size = 0xffffffffu - g_ring[i & RING_MASK];
    uint32_t ts32 = g_ring[(i + 1) & RING_MASK];

    uint64_t now = time_us_64();
    uint64_t ts_end = now - (uint32_t)((uint32_t)now - ts32);

    if (size == 0)
    {
        pending_in_emit();
        fold_flush();
        send_ts(REC_RESET, ts_end);
    }
    else if (size == 1)
    {
        if (!g_fs)
        {
            handle_keepalive(ts_end);
        }
    }
    else if (size > 0xffff)
    {
        g_syncerr++;
        pending_in_emit();
        fold_flush();
        rec_begin(REC_SYNCERR);
        put_u64(ts_end);
        put_u32(size);
        rec_end();
    }
    else
    {
        uint16_t flags;
        int n = decode_packet(rd, size, &flags);
        uint32_t dur = g_fs ? ((size * 5461u) >> 16) : ((size * 43691u) >> 16);
        handle_packet(ts_end - dur, (uint16_t)size, flags, g_pkt, n);
    }

    __dmb();
    g_rd = i + 2;
}

static void send_status(void)
{
    rec_begin(REC_STATUS);
    put_u64(time_us_64());
    put_u32(g_c1_packets);
    put_u32(g_c1_dropped);
    put_u32(g_wr_commit - g_rd);
    put_u32(g_c1_max_fill);
    put_u32(RING_WORDS);
    put_u32(g_c1_rxstall);
    put_u32(g_records_out);
    put_u32(g_syncerr);
    rec_end();
}

static int detect_line(void)
{
    // Majority vote over ~10 ms: idle J state is D+ high (FS) or D- high (LS)
    int dp = 0, dm = 0;
    for (int i = 0; i < 2000; i++)
    {
        dp += gpio_get(DP_PIN);
        dm += gpio_get(DM_PIN);
        busy_wait_us_32(5);
    }
    if (dp > 200 && dp > dm)
    {
        return 1;
    }
    if (dm > 200 && dm > dp)
    {
        return 2;
    }
    return 0;
}

static void led_set(bool on)
{
#ifdef LED_PIN
    gpio_put(LED_PIN, on);
#else
    (void)on;
#endif
}

static void core1_stop(void)
{
    g_run_req = false;
    __dmb();
    uint64_t t0 = time_us_64();
    while (g_core1_active && (time_us_64() - t0) < 100000)
    {
        tight_loop_contents();
    }
    pio_teardown();
}

static void capture_start(char speed, bool fold_sof, bool fold_nak)
{
    if (g_state != STATE_IDLE)
    {
        core1_stop();
        g_state = STATE_IDLE;
    }

    tap_pins_init();
    busy_wait_us_32(100);

    int line = detect_line();
    bool is_auto = (speed != 'F' && speed != 'L');
    if (speed == 'F')
    {
        g_fs = true;
    }
    else if (speed == 'L')
    {
        g_fs = false;
    }
    else
    {
        g_fs = (line != 2);
    }

    g_fold_sof = fold_sof;
    g_fold_nak = fold_nak;
    memset(&g_fold, 0, sizeof(g_fold));
    memset(&g_pin, 0, sizeof(g_pin));
    g_wr_commit = 0;
    g_rd = 0;
    g_c1_packets = 0;
    g_c1_dropped = 0;
    g_c1_max_fill = 0;
    g_c1_rxstall = 0;
    g_reported_drops = 0;
    g_syncerr = 0;
    g_records_out = 0;

    pio_setup(g_fs);

    rec_begin(REC_START);
    put_u64(time_us_64());
    put_u8(g_fs ? 1 : 0);
    put_u8(g_fold_sof);
    put_u8(g_fold_nak);
    put_u8(is_auto);
    put_u8((uint8_t)line);
    rec_end();

    send_text(SNIFFER_INPUT_SCHMITT ? "Input Schmitt trigger: on" : "Input Schmitt trigger: off");
    if (line == 0)
    {
        send_text("WARNING: no idle J state detected on D+/D- (device not attached, bus not powered or wiring?)");
    }

    __dmb();
    g_run_req = true;
    uint64_t t0 = time_us_64();
    while (!g_core1_active && (time_us_64() - t0) < 100000)
    {
        tight_loop_contents();
    }

    g_next_status = time_us_64() + STATUS_PERIOD_US;
    g_state = STATE_RUNNING;
    led_set(true);
}

static void capture_finish(void)
{
    pending_in_emit();
    fold_flush();
    send_status();
    rec_begin(REC_STOP);
    put_u64(time_us_64());
    put_u8(g_stop_reason);
    rec_end();
    g_state = STATE_IDLE;
    led_set(false);
}

static void capture_request_stop(uint8_t reason)
{
    if (g_state != STATE_RUNNING)
    {
        return;
    }
    g_stop_reason = reason;
    core1_stop();
    g_state = STATE_STOPPING; // drain the ring first
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
static char g_cmd[4];
static int g_cmd_len;

static void handle_cmd_byte(char c)
{
    if (g_cmd_len == 0)
    {
        switch (c)
        {
        case 'S':
            g_cmd[g_cmd_len++] = c;
            return;
        case 'P':
            capture_request_stop(0);
            return;
        case 'I':
            send_info();
            return;
        case 'R':
            core1_stop();
            reset_usb_boot(0, 0);
            return;
        default:
            return; // ignore whitespace / unknown
        }
    }

    g_cmd[g_cmd_len++] = c;
    if (g_cmd_len == 4)
    {
        g_cmd_len = 0;
        capture_start(g_cmd[1], g_cmd[2] == '1', g_cmd[3] == '1');
    }
}

static void poll_commands(void)
{
    uint8_t buf[32];
    while (tud_cdc_available())
    {
        uint32_t n = tud_cdc_read(buf, sizeof(buf));
        for (uint32_t i = 0; i < n; i++)
        {
            handle_cmd_byte((char)buf[i]);
        }
    }
}

void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts)
{
    (void)itf;
    (void)rts;
    // drop stale data on (re)open and close
    tud_cdc_write_clear();
    g_cmd_len = 0;
    (void)dtr;
}

// ---------------------------------------------------------------------------
// main (core0)
// ---------------------------------------------------------------------------
int main(void)
{
    // 120 MHz: exact PIO dividers for 15 MHz (LS) and 120 MHz (FS)
    set_sys_clock_khz(SNIFFER_CLK_KHZ, true);

#ifdef LED_PIN
    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);
    led_set(false);
#endif

    build_unstuff_tables();
    pio_teardown();

    multicore_launch_core1(core1_main);

    tusb_init();

    uint64_t led_t = 0;
    bool led_on = false;

    while (true)
    {
        tud_task();
        poll_commands();

        if (g_state != STATE_IDLE)
        {
            if (!tud_cdc_connected())
            {
                // host closed the port: stop and discard
                if (g_state == STATE_RUNNING)
                {
                    core1_stop();
                }
                g_state = STATE_IDLE;
                led_set(false);
                continue;
            }

            int budget = 48;
            while (budget-- > 0 && g_rd != g_wr_commit && tud_cdc_write_available() >= MIN_TX_SPACE)
            {
                process_one();
            }

            uint64_t now = time_us_64();
            bool empty = (g_rd == g_wr_commit);

            if (empty && tud_cdc_write_available() >= MIN_TX_SPACE)
            {
                if (g_pin.valid && (now - g_pin.ts) > PENDING_IN_TIMEOUT_US)
                {
                    pending_in_emit();
                }
                if (g_fold.open && (now - g_fold.t_first) > FOLD_FLUSH_US)
                {
                    fold_flush();
                }
            }

            if (g_c1_dropped != g_reported_drops && tud_cdc_write_available() >= 64)
            {
                uint32_t total = g_c1_dropped;
                rec_begin(REC_DROP);
                put_u64(now);
                put_u32(total);
                put_u32(total - g_reported_drops);
                rec_end();
                g_reported_drops = total;
            }

            if (now >= g_next_status && tud_cdc_write_available() >= 64)
            {
                send_status();
                g_next_status = now + STATUS_PERIOD_US;
            }

            if (g_state == STATE_STOPPING && empty && tud_cdc_write_available() >= MIN_TX_SPACE)
            {
                capture_finish();
            }

            if (g_state == STATE_RUNNING && now - led_t > 250000)
            {
                led_t = now;
                led_on = !led_on;
                led_set(led_on);
            }
        }

        tud_cdc_write_flush();
    }
}
