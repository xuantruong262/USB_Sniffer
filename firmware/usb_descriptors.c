/*
 * Pico USB Sniffer - USB descriptors (single CDC interface)
 */
#include <string.h>

#include "pico/unique_id.h"
#include "pico/usb_reset_interface.h"
#include "pico/usb_reset_tusb.h"
#include "tusb.h"

#define USB_VID 0x2E8A // Raspberry Pi
#define USB_PID 0x000A // Raspberry Pi Pico SDK CDC
#define USB_BCD 0x0210 // 2.1: BOS / MS OS 2.0 descriptor for the reset interface

static const tusb_desc_device_t desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = USB_BCD,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = USB_VID,
    .idProduct = USB_PID,
    .bcdDevice = 0x0100,
    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01,
};

const uint8_t *tud_descriptor_device_cb(void)
{
    return (const uint8_t *)&desc_device;
}

enum
{
    ITF_NUM_CDC = 0,
    ITF_NUM_CDC_DATA,
    ITF_NUM_RESET, // picotool reset interface (must match PICO_USB_RESET_MS_OS_20_DESCRIPTOR_ITF)
    ITF_NUM_TOTAL
};

#define EPNUM_CDC_NOTIF 0x81
#define EPNUM_CDC_OUT 0x02
#define EPNUM_CDC_IN 0x82

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN + TUD_RPI_RESET_DESC_LEN)

static const uint8_t desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 100),
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC, 4, EPNUM_CDC_NOTIF, 8, EPNUM_CDC_OUT, EPNUM_CDC_IN, 64),
    TUD_RPI_RESET_DESCRIPTOR(ITF_NUM_RESET, 5),
};

_Static_assert(ITF_NUM_RESET == PICO_USB_RESET_MS_OS_20_DESCRIPTOR_ITF, "reset interface number mismatch");

const uint8_t *tud_descriptor_configuration_cb(uint8_t index)
{
    (void)index;
    return desc_configuration;
}

static char serial_str[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];

static const char *string_desc_arr[] = {
    (const char[]){0x09, 0x04}, // 0: English (0x0409)
    "Raspberry Pi",             // 1: Manufacturer
    "Pico USB Sniffer",         // 2: Product
    serial_str,                 // 3: Serial (board unique id)
    "Pico USB Sniffer CDC",     // 4: CDC interface
    "Reset",                    // 5: picotool reset interface
};

static uint16_t desc_str[32 + 1];

const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
    (void)langid;
    uint8_t chr_count;

    if (index == 0)
    {
        memcpy(&desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    }
    else
    {
        if (index >= sizeof(string_desc_arr) / sizeof(string_desc_arr[0]))
        {
            return NULL;
        }
        if (index == 3 && serial_str[0] == 0)
        {
            pico_get_unique_board_id_string(serial_str, sizeof(serial_str));
        }
        const char *str = string_desc_arr[index];
        chr_count = (uint8_t)strlen(str);
        if (chr_count > 32)
        {
            chr_count = 32;
        }
        for (uint8_t i = 0; i < chr_count; i++)
        {
            desc_str[1 + i] = str[i];
        }
    }

    desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
    return desc_str;
}
