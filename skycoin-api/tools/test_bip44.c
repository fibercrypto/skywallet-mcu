#include "tools/test_bip32.h"

#include <check.h>
#include <stdio.h>
#include <string.h>

#include <skycoin_crypto.h>

#include "base58.h"
#include "bip39.h"
#include "bip44.h"
#include "curves.h"
#include "test_bip44.h"

START_TEST(TestSimpleExample)
{
    char seed_str[] = {"000102030405060708090a0b0c0d0e0f"};
    uint8_t seed[1000] = {0};
    const size_t seed_len =
        sizeof(seed) < strlen(seed_str) / 2 ? sizeof(seed) : strlen(seed_str) / 2;
    int ret = tobuff(seed_str, seed, seed_len);
    ck_assert_int_eq(true, ret);
    char path_invalid_len[] = {"m/0'/1/2'"};
    uint8_t addr[100];
    size_t addr_size = sizeof(addr);
    ret = hdnode_ckd_address_from_path(seed, seed_len, path_invalid_len, addr,
        &addr_size);
    ck_assert_int_eq(-1, ret);
    char path_invalid_purpose[] = {"m/0'/0'/2'/0/0"};
    addr_size = sizeof(addr);
    ret = hdnode_ckd_address_from_path(seed, seed_len, path_invalid_purpose, addr,
        &addr_size);
    ck_assert_int_eq(-2, ret);
    char path_invalid_coin_type[] = {"m/44'/0'/2'/0/0"};
    addr_size = sizeof(addr);
    ret = hdnode_ckd_address_from_path(seed, seed_len, path_invalid_coin_type,
        addr, &addr_size);
    ck_assert_int_eq(-3, ret);
    char path_invalid_account[] = {"m/44'/8000'/2/0/0"};
    addr_size = sizeof(addr);
    ret = hdnode_ckd_address_from_path(seed, seed_len, path_invalid_account, addr,
        &addr_size);
    ck_assert_int_eq(-4, ret);
    char path_invalid_invalid_change[] = {"m/44'/8000'/2'/1'/0"};
    addr_size = sizeof(addr);
    ret = hdnode_ckd_address_from_path(
        seed, seed_len, path_invalid_invalid_change, addr, &addr_size);
    ck_assert_int_eq(-5, ret);
    char path_invalid_invalid_change2[] = {"m/44'/8000'/2'/2/0"};
    addr_size = sizeof(addr);
    ret = hdnode_ckd_address_from_path(
        seed, seed_len, path_invalid_invalid_change2, addr, &addr_size);
    ck_assert_int_eq(-5, ret);
    char path_invalid_invalid_index[] = {"m/44'/8000'/2'/1/0'"};
    addr_size = sizeof(addr);
    ret = hdnode_ckd_address_from_path(seed, seed_len, path_invalid_invalid_index,
        addr, &addr_size);
    ck_assert_int_eq(-6, ret);
    char path[] = {"m/44'/8000'/0'/0/1"};
    addr_size = sizeof(addr);
    ret = hdnode_ckd_address_from_path(seed, seed_len, path, addr, &addr_size);
    ck_assert_int_eq(0, ret);
}
END_TEST

START_TEST(TestSimpleExample1)
{
    typedef struct {
        uint8_t addr[20];
        size_t addr_index;
        char* mnemonic;
    } TestData;
    // TODO test_cases generated with skycoin cli
    TestData test_cases[] = {
        {
            .mnemonic = "random gloom dash lens inner city recycle shuffle shell "
                        "panic verb exchange",
            .addr = {111, 75, 53, 169, 16, 240, 26, 29, 240, 141,
                58, 98, 93, 2, 250, 95, 128, 213, 113, 32},
            .addr_index = 0,
        },
        {
            .mnemonic = "program robust plug afraid subway lesson slight rose hunt depart milk traffic",
            .addr = {230, 222, 198, 100, 93, 45, 63, 251, 180, 66, 108, 117, 37, 45, 0, 80, 155, 8, 167, 227},
            .addr_index = 4,
        },
        {
            .mnemonic = "random gloom dash lens inner city recycle shuffle shell "
                        "panic verb exchange",
            .addr = {194, 136, 251, 7, 58, 141, 24, 178, 231, 76,
                151, 44, 115, 151, 103, 87, 152, 204, 45, 175},
            .addr_index = 1,
        },
        {
            .mnemonic = "program robust plug afraid subway lesson slight rose hunt depart milk traffic",
            .addr = {228, 93, 171, 106, 55, 62, 187, 11, 47, 26, 163, 103, 142, 107, 62, 102, 64, 28, 139, 195},
            .addr_index = 0,
        },
        {
            .mnemonic = "random gloom dash lens inner city recycle shuffle shell "
                        "panic verb exchange",
            .addr = {196, 92, 203, 138, 6, 103, 104, 190, 160, 73, 249, 72, 46, 94, 87, 130, 201, 126, 84, 26},
            .addr_index = 3,
        }};
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(*test_cases); ++i) {
        uint8_t seed[512 / 8] = {0};
        mnemonic_to_seed(test_cases[i].mnemonic, "", seed, NULL);
        char path[100] = {0};
        sprintf(path, "m/44'/8000'/0'/0/%lu", test_cases[i].addr_index);
        uint8_t addr[100] = {0};
        size_t addr_size = sizeof(addr);
        int ret = hdnode_ckd_address_from_path(seed, sizeof(seed), path, addr,
            &addr_size);
        ck_assert_int_eq(0, ret);
        ck_assert_mem_eq(test_cases[i].addr, addr, sizeof(test_cases[i].addr));
    }
}
END_TEST

void load_bip44_testcase(Suite* s)
{
    TCase* tc = tcase_create("skycoin_crypto_bip44");
    tcase_add_test(tc, TestSimpleExample);
    tcase_add_test(tc, TestSimpleExample1);
    suite_add_tcase(s, tc);
}
