#ifndef _TUSB_CONFIG_H_
#define _TUSB_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CFG_TUSB_MCU
#error CFG_TUSB_MCU must be defined
#endif

#define CFG_TUSB_RHPORT0_MODE (OPT_MODE_DEVICE | OPT_MODE_FULL_SPEED)

#ifndef CFG_TUSB_OS
#define CFG_TUSB_OS OPT_OS_PICO
#endif

#define CFG_TUD_ENABLED 1

#ifndef CFG_TUSB_MEM_SECTION
#define CFG_TUSB_MEM_SECTION
#endif
#ifndef CFG_TUSB_MEM_ALIGN
#define CFG_TUSB_MEM_ALIGN __attribute__((aligned(4)))
#endif

#define CFG_TUD_ENDPOINT0_SIZE 64

#define CFG_TUD_CDC 1
#define CFG_TUD_MSC 0
#define CFG_TUD_HID 0
#define CFG_TUD_MIDI 0
#define CFG_TUD_VENDOR 0

// Large TX FIFO absorbs USB host scheduling jitter; multi-packet transfers
// (512 bytes = 8 x 64 byte packets) reduce per-transfer overhead.
#define CFG_TUD_CDC_RX_BUFSIZE 1024 // must be >= CFG_TUD_CDC_EP_BUFSIZE or OUT is never armed
#define CFG_TUD_CDC_TX_BUFSIZE 16384
#define CFG_TUD_CDC_EP_BUFSIZE 512

#ifdef __cplusplus
}
#endif

#endif
