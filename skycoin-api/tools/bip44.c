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

#include "bip44.h"
#include "bip32.h"
#include "curves.h"

//// coint_type_bitcoin is the coin_type for Bitcoin
// static const uint32_t coint_type_bitcoin = 0;

//// coint_type_bitcoin_testnet is the coin_type for Skycoin
// static const uint32_t coint_type_bitcoin_testnet = 1;

// coint_type_skycoin is the coin_type for Skycoin
static const uint32_t coint_type_skycoin = 8000;

//// external_chain_index is the index of the external chain
// static const uint32_t external_chain_index = 0;

//// change_chain_index is the index of the change chain
// static const uint32_t change_chain_index = 1;

extern uint32_t first_hardened_child;
int parse_path(const char *path, uint32_t *out_indexes,
               size_t *out_indexes_size);

// m / purpose' / coin_type' / account' / change / address_index
int validate_path(const uint32_t *indexes, size_t indexes_size) {
  if (indexes_size != 5) {
    return -1;
  }
  // Purpose is a constant set to 44' (or 0x8000002C) following the BIP43
  // recommendation.
  if (indexes[0] != 0x8000002C) {
    return -2;
  }
  // coin_type is set to 8000'
  if (indexes[1] != first_hardened_child + coint_type_skycoin) {
    return -3;
  }
  // account is in an a hardened chield (')
  if (!(indexes[2] & first_hardened_child)) {
    return -4;
  }
  // change is 0 or 1 (Constant 0 is used for external chain and constant 1 for
  // internal chain)
  if (indexes[3] != 0 && indexes[3] != 1) {
    return -5;
  }
  // address_index is not in a hardened chield (')
  if (indexes[4] & first_hardened_child) {
    return -6;
  }
  return 0;
}

int hdnode_ckd_address_from_path(const uint8_t *seed, size_t seed_len,
                                 const char *path, uint8_t *out_addrs,
                                 size_t *out_addrs_size) {
  uint32_t out_indexes[256] = {0};
  size_t out_indexes_size = 0;
  int ret = parse_path(path, out_indexes, &out_indexes_size);
  if (ret) {
    return ret;
  }
  ret = validate_path(out_indexes, out_indexes_size);
  if (ret != 0) {
    return ret;
  }
  HDNode node;
  ret = hdnode_from_seed(seed, seed_len, SECP256K1_NAME, &node);
  if (ret != 1) {
    return ret;
  }
  ret = hdnode_private_ckd_from_path(path, &node);
  if (ret != 1) {
    return ret;
  }
  hdnode_get_address_raw(&node, out_addrs, out_addrs_size);
  return 0;
}
