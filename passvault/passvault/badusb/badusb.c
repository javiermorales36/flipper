#include "badusb.h"

void pv_initialize_hid(void) {
    furi_hal_usb_unlock();
    furi_check(furi_hal_usb_set_config(&usb_hid, NULL));
    furi_delay_ms(100);
}

void pv_release_all_keys(void) {
    furi_hal_hid_kb_release_all();
}

void pv_type_string(const char* str) {
    for(size_t i = 0; str[i]; i++) {
        furi_hal_hid_kb_press(HID_ASCII_TO_KEY(str[i]));
        furi_hal_hid_kb_release(HID_ASCII_TO_KEY(str[i]));
        furi_delay_ms(10);
    }
}

void pv_press_key(uint8_t key) {
    furi_hal_hid_kb_press(key);
    furi_delay_ms(50);
    furi_hal_hid_kb_release(key);
}
