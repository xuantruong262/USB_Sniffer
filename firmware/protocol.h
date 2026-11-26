/*
 * Pico USB Sniffer - device -> PC streaming protocol
 *
 * Byte stream over USB CDC. Every record:
 *
 *   +------+------+--------+--------+-----------------+
 *   | 0xA5 | type | len_lo | len_hi | payload[len]    |
 *   +------+------+--------+--------+-----------------+
 *
 * All multi-byte fields are little endian. Timestamps are microseconds of the
 * Pico 64-bit timer (never wrap).
 *
 * PC -> device commands (ASCII):
 *   'I'               info request
 *   'S' <spd> <s> <n> start; spd = 'A' auto | 'F' full | 'L' low,
 *                     s = '1'/'0' fold SOF/keep-alive, n = '1'/'0' fold IN+NAK
 *   'P'               stop
 *   'R'               reboot into BOOTSEL (UF2 bootloader)
 *
 * Keep this file in sync with pc_tool/protocol.py
 */
#ifndef PROTOCOL_H
#define PROTOCOL_H

#define PROTO_MAGIC 0xA5
#define PROTO_VERSION 1

enum
{
    REC_INFO = 0x01,      // u16 proto, u16 fw, u32 sys_clk, u32 ring_words, u8 dp, u8 dm, char text[]
    REC_START = 0x02,     // u64 ts, u8 speed(0=LS,1=FS), u8 fold_sof, u8 fold_nak, u8 auto, u8 line(1=J FS,2=J LS,0=none)
    REC_STOP = 0x03,      // u64 ts, u8 reason(0=command, 1=host gone)
    REC_PACKET = 0x10,    // u64 ts_start, u16 nbits, u16 flags, u8 bytes[] (SYNC, PID, ...)
    REC_RESET = 0x11,     // u64 ts
    REC_KEEPALIVE = 0x12, // u64 ts (Low Speed EOP keep-alive)
    REC_SYNCERR = 0x13,   // u64 ts, u32 raw size
    REC_FOLD = 0x20,      // u64 t_first, u64 t_last, u32 sof, u16 frame_first, u16 frame_last,
                          // u32 keepalive, u32 other_nak, u8 n, n * {u8 addr, u8 ep, u32 count}
    REC_STATUS = 0x30,    // u64 ts, u32 packets, u32 dropped, u32 fill, u32 max_fill, u32 ring_words,
                          // u32 rxstall, u32 records, u32 syncerr
    REC_DROP = 0x31,      // u64 ts, u32 total, u32 delta
    REC_TEXT = 0x40,      // char text[]
    REC_HOST_EVENT = 0x41 // written by the PC tool only (into capture files)
};

// REC_PACKET flags
#define PKT_ERR_STUFF 0x0001
#define PKT_ERR_CRC 0x0002
#define PKT_ERR_PID 0x0004
#define PKT_ERR_SYNC 0x0008
#define PKT_ERR_NBIT 0x0010
#define PKT_ERR_SIZE 0x0020
#define PKT_TRUNCATED 0x0040

#define FOLD_MAX_EP 8

#endif
