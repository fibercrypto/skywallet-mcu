/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SKYCOIN_CRYPTO_BIP44_H
#define SKYCOIN_CRYPTO_BIP44_H

#include <stddef.h>
#include <stdint.h>

int hdnode_ckd_address_from_path(const uint8_t* seed, size_t seed_len, const char* path, uint8_t* out_addrs, size_t* out_addrs_size);

int hdnode_address_for_branch(const uint8_t* seed, size_t seed_len, uint32_t purpose, uint32_t coin_type, uint32_t account, uint32_t change, uint32_t address_index, char* out_addrs, size_t* out_addrs_size);

int hdnode_keypair_for_branch(const uint8_t* seed, size_t seed_len, uint32_t purpose, uint32_t coin_type, uint32_t account, uint32_t change, uint32_t address_index, uint8_t* seckey, uint8_t* pubkey);

#endif // SKYCOIN_CRYPTO_BIP44_H
