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

#include <string.h>

#include "bip32.h"
#include "bip44.h"
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
int parse_path(const char* path, uint32_t* out_indexes, size_t* out_indexes_size);

// m / purpose' / coin_type' / account' / change / address_index
static int validate_bip44(uint32_t purpose, uint32_t coin_type, uint32_t account, uint32_t change, uint32_t address_index)
{
    // Purpose is a constant set to 44' (or 0x8000002C) following the BIP43
    // recommendation.
    if (purpose != 0x8000002C) {
        return -2;
    }
    // coin_type is set to 8000'
    if (coin_type != first_hardened_child + coint_type_skycoin) {
        return -3;
    }
    // account is in an a hardened chield (')
    if (!(account & first_hardened_child)) {
        return -4;
    }
    // change is 0 or 1 (Constant 0 is used for external chain and constant 1 for
    // internal chain)
    if (change != 0 && change != 1) {
        return -5;
    }
    // address_index is not in a hardened chield (')
    if (address_index & first_hardened_child) {
        return -6;
    }
    return 0;
}

static int hdnode_for_branch_path(const uint8_t* seed, size_t seed_len, uint32_t purpose, uint32_t coin_type, uint32_t account, uint32_t change, uint32_t address_index, HDNode* node)
{
    int ret = validate_bip44(purpose, coin_type, account, change, address_index);
    if (ret != 0) {
        return ret;
    }
    ret = hdnode_from_seed(seed, seed_len, SECP256K1_NAME, node);
    if (ret != 1) {
        return ret;
    }
    ret = hdnode_private_ckd(node, purpose);
    if (ret != 1) {
        return ret;
    }
    ret = hdnode_private_ckd(node, coin_type);
    if (ret != 1) {
        return ret;
    }
    ret = hdnode_private_ckd(node, account);
    if (ret != 1) {
        return ret;
    }
    ret = hdnode_private_ckd(node, change);
    if (ret != 1) {
        return ret;
    }
    ret = hdnode_private_ckd(node, address_index);
    if (ret != 1) {
        return ret;
    }
    return 1;
}

int hdnode_address_for_branch(const uint8_t* seed, size_t seed_len, uint32_t purpose, uint32_t coin_type, uint32_t account, uint32_t change, uint32_t address_index, char* out_addrs, size_t* out_addrs_size)
{
    HDNode node;
    int ret = hdnode_for_branch_path(seed, seed_len, purpose, coin_type, account,
        change, address_index, &node);
    if (ret != 1) {
        return ret;
    }
    hdnode_get_address(&node, out_addrs, out_addrs_size);
    return 1;
}

int hdnode_keypair_for_branch(const uint8_t* seed, size_t seed_len, uint32_t purpose, uint32_t coin_type, uint32_t account, uint32_t change, uint32_t address_index, uint8_t* seckey, uint8_t* pubkey)
{
    HDNode node;
    int ret = hdnode_for_branch_path(seed, seed_len, purpose, coin_type, account,
        change, address_index, &node);
    if (ret != 1) {
        return ret;
    }
    memcpy(seckey, node.private_key, sizeof(node.private_key));
    memcpy(pubkey, node.public_key, sizeof(node.public_key));
    return 1;
}

// m / purpose' / coin_type' / account' / change / address_index
int validate_path(const uint32_t* indexes, size_t indexes_size)
{
    if (indexes_size != 5) {
        return -1;
    }
    return validate_bip44(indexes[0], indexes[1], indexes[2], indexes[3], indexes[4]);
}

int hdnode_ckd_address_from_path(const uint8_t* seed, size_t seed_len, const char* path, uint8_t* out_addrs, size_t* out_addrs_size)
{
    uint32_t path_nodes[256] = {0};
    size_t path_nodes_size = 0;
    int ret = parse_path(path, path_nodes, &path_nodes_size);
    if (ret) {
        return ret;
    }
    ret = validate_path(path_nodes, path_nodes_size);
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
