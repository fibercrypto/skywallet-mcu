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

#include <unistd.h>

#include "layout.h"
#include "oled.h"
void __attribute__((noreturn)) panic(char *msg) {
  layoutDialog(&bmp_icon_error, NULL, NULL, NULL, NULL, msg, "detected.",
               "Please unplug", "the device.", NULL);
  while (1) {
    oledRefresh();
    sleep(1);
  }  // loop forever
}
