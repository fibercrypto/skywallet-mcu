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

#include "test_pin.h"

char* TEST_PIN1 = "123";
char* TEST_PIN2 = "246";

ErrCode_t pin_reader_ok(PinMatrixRequestType pinReqType, const char* text, char* out_pin)
{
    (void)text;
    (void)pinReqType;
    strcpy(out_pin, TEST_PIN1);
    return ErrOk;
}

ErrCode_t pin_reader_alt(PinMatrixRequestType pinReqType, const char* text, char* pin_out)
{
    (void)text;
    (void)pinReqType;
    strcpy(pin_out, TEST_PIN2);
    return ErrOk;
}

ErrCode_t pin_reader_wrong(PinMatrixRequestType pinReqType, const char* text, char* pin_out)
{
    (void)text;
    switch (pinReqType) {
    case PinMatrixRequestType_PinMatrixRequestType_NewFirst:
        strcpy(pin_out, TEST_PIN1);
        break;
    case PinMatrixRequestType_PinMatrixRequestType_NewSecond:
        strcpy(pin_out, "456");
        break;
    default:
        break;
    }
    strcpy(pin_out, "789");
    return ErrPinMismatch;
}
