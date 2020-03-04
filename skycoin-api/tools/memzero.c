/*
 * This file is part of the FiberCrypto project, https://fibercryp.to/ 
 *
 * Copyright (C) 2020 Simelo.Tech
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include <string.h>

void memzero(void* s, size_t n)
{
    memset(s, 0, n);
}
