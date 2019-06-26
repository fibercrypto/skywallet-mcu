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

#ifndef __SETUP_VECTOR_H__
#define __SETUP_VECTOR_H__

#include <libopencm3/cm3/nvic.h>

// Custom interrupt bindings
#define FIRMWARE_PANIC_ISR  exti0_isr
#define FIRMWARE_PANIC_NVIC NVIC_EXTI0_IRQ
#define FIRMWARE_PANIC_EXTI EXTI0

#endif
