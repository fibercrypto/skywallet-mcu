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

#include <string.h>
#include "error_common.h"
#include "setup.h"
#include "usb.h"

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

#include "setup_vector.h"
void panic(char *msg) {
  set_panic_msg(msg);
  nvic_generate_software_interrupt(FIRMWARE_PANIC_NVIC);
}

void hard_fault_handler(void) {
  // FIXME: Remove panic logic once EXTI0 triggered correctly
  char *panic_msg = get_panic_msg();
  char *oled_msg = "Hard fault";
  if (panic_msg != 0) {
    oled_msg = "Firmware panic";
    msg_out_panic(panic_msg);
  }
  fault_handler(oled_msg);
}
