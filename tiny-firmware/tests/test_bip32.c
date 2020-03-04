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

#include "test_bip32.h"

START_TEST(test_dumy)
{
    ck_assert_int_eq(1, 1);
}
END_TEST

TCase* add_bip32_tests(TCase* tc)
{
    tcase_add_test(tc, test_dumy);
    return tc;
}
