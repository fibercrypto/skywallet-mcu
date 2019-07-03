/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include "firmware/fsm_impl.h"
#include "messages.pb.h"
#include "messages.h"
#include "string.h"
#include "usb.h"
#include "setup.h"

extern char *criticalMessage;
// FIXME: Softw interrupt for firmware panic no triggering ISR ...
/*
void FIRMWARE_PANIC_ISR(void)
{
    char *panic_msg = get_panic_msg();
    msg_out_panic(panic_msg)
    fault_handler("Firmware panic");
}
*/

extern uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));

void msg_out_panic(const char *panic_msg) {
    RESP_INIT(Failure)
    resp->has_msg_type = false;
    resp->has_code = true;
    resp->code = FailureType_Failure_FirmwarePanic;
    if (panic_msg != 0) {
        resp->has_message = true;
        strlcpy(resp->message, panic_msg, sizeof(resp->message));
    }
    msg_write(MessageType_MessageType_Failure, resp);
#if !defined(EMULATOR) || EMULATOR != 1
    usbFlush();
#endif //  !defined(EMULATOR) || EMULATOR != 1
}

static char *panic_msg = NULL;
char *get_panic_msg(void) {
    return panic_msg;
}

#if EMULATOR == 1
#include <unistd.h>
#include "oled.h"
#include "layout2.h"
void __attribute__((noreturn)) panic(char *msg) {
  layoutDialog(&bmp_icon_error, NULL, NULL, NULL, NULL, msg, "detected.", "Please unplug", "the device.", NULL);
  while (1) {
    oledRefresh();
    sleep(1);
  } // loop forever
}
#else
#include "setup_vector.h"
void panic(char *msg) {
    panic_msg = msg;
    nvic_generate_software_interrupt(FIRMWARE_PANIC_NVIC);
}

void hard_fault_handler(void)
{
    // FIXME: Remove panic logic once EXTI0 triggered correctly
    char *oled_msg  = "Hard fault";
    if (panic_msg != 0) {
        oled_msg = "Firmware panic";
        msg_out_panic(panic_msg);
    }
    fault_handler(oled_msg);
}
#endif //  EMULATOR == 1
