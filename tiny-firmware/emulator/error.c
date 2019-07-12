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

#ifdef TESTING
#include <stdio.h>
#else
#include "layout.h"
#include "oled.h"
#endif //  TESTING

void __attribute__((noreturn)) panic(char *msg) {
#ifdef TESTING
    printf("msg: %s\n", msg);
#else
    layoutDialog(&bmp_icon_error, NULL, NULL, NULL, NULL, msg, "detected.",
                 "Please unplug", "the device.", NULL);
#endif //  TESTING
  while (1) {
#if !defined(TESTING)
    oledRefresh();
#endif //  !deffined(TESTING)
    sleep(1);
  }  // loop forever
}
