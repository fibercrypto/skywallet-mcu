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

#ifndef __TINYFIRMWARE_FIRMWARE_FSMIMPL_H__
#define __TINYFIRMWARE_FIRMWARE_FSMIMPL_H__

#include "tiny-firmware/firmware/error.h"
#include "tiny-firmware/protob/c/messages.pb.h"

#define MNEMONIC_WORD_COUNT_12 12
#define MNEMONIC_WORD_COUNT_24 24

// message methods
#define GET_MSG_POINTER(TYPE, VarName)                                       \
    TYPE* VarName = (TYPE*)(void*)msg_resp;                                  \
    _Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE " is too large"); \
    memset(VarName, 0, sizeof(TYPE));

#define RESP_INIT(TYPE) GET_MSG_POINTER(TYPE, resp);

#define CHECK_INITIALIZED                                             \
    if (!storage_isInitialized()) {                                   \
        fsm_sendFailure(FailureType_Failure_NotInitialized, NULL, 0); \
        return;                                                       \
    }

#define CHECK_INITIALIZED_RET_ERR_CODE \
    if (!storage_isInitialized()) {    \
        return ErrInitialized;         \
    }

#define CHECK_NOT_INITIALIZED                                                                                           \
    if (storage_isInitialized()) {                                                                                      \
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Device is already initialized. Use Wipe first."), 0); \
        return;                                                                                                         \
    }

#define CHECK_NOT_INITIALIZED_RET_ERR_CODE \
    if (storage_isInitialized()) {         \
        return ErrNotInitialized;          \
    }

#define CHECK_PIN            \
    if (!protectPin(true)) { \
        layoutHome();        \
        return;              \
    }

#define CHECK_PIN_RET_ERR_CODE \
    if (!protectPin(true)) {   \
        return ErrPinRequired; \
    }

#define CHECK_PIN_UNCACHED    \
    if (!protectPin(false)) { \
        layoutHome();         \
        return;               \
    }

#define CHECK_PIN_UNCACHED_RET_ERR_CODE \
    if (!protectPin(false)) {           \
        return ErrPinRequired;          \
    }

#define CHECK_PARAM(cond, errormsg)                                    \
    if (!(cond)) {                                                     \
        fsm_sendFailure(FailureType_Failure_DataError, (errormsg), 0); \
        layoutHome();                                                  \
        return;                                                        \
    }

#define CHECK_PARAM_RET_ERR_CODE(cond, errormsg) \
    if (!(cond)) {                               \
        return ErrInvalidArg;                    \
    }

#define CHECK_PRECONDITION(cond, errormsg)                             \
    if (!(cond)) {                                                     \
        fsm_sendFailure(FailureType_Failure_DataError, (errormsg), 0); \
        layoutHome();                                                  \
        return;                                                        \
    }

#define CHECK_PRECONDITION_RET_ERR_CODE(cond, errormsg) \
    if (!(cond)) {                                      \
        return ErrPreconditionFailed;                   \
    }

#define CHECK_BUTTON_PROTECT                                                  \
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) { \
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, 0);        \
        layoutHome();                                                         \
        return;                                                               \
    }

#define CHECK_BUTTON_PROTECT_RET_ERR_CODE                                     \
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) { \
        layoutHome();                                                         \
        return ErrActionCancelled;                                            \
    }

#define CHECK_MNEMONIC                                                                 \
    if (storage_hasMnemonic() == false) {                                              \
        fsm_sendFailure(FailureType_Failure_AddressGeneration, "Mnemonic not set", 0); \
        layoutHome();                                                                  \
        return;                                                                        \
    }

#define CHECK_MNEMONIC_RET_ERR_CODE       \
    if (storage_hasMnemonic() == false) { \
        return ErrMnemonicRequired;       \
    }

#define CHECK_INPUTS(msg)                                                                              \
    if ((msg)->nbIn > 8) {                                                                             \
        fsm_sendFailure(FailureType_Failure_InvalidSignature, _("Cannot have more than 8 inputs"), 0); \
        layoutHome();                                                                                  \
        return;                                                                                        \
    }

#define CHECK_OUTPUTS(msg)                                                                              \
    if ((msg)->nbOut > 8) {                                                                             \
        fsm_sendFailure(FailureType_Failure_InvalidSignature, _("Cannot have more than 8 outputs"), 0); \
        layoutHome();                                                                                   \
        return;                                                                                         \
    }

#define CHECK_MNEMONIC_CHECKSUM                                                                        \
    if (!mnemonic_check(msg->mnemonic)) {                                                              \
        fsm_sendFailure(FailureType_Failure_DataError, _("Mnemonic with wrong checksum provided"), 0); \
        layoutHome();                                                                                  \
        return;                                                                                        \
    }

#define CHECK_MNEMONIC_CHECKSUM_RET_ERR_CODE \
    if (!mnemonic_check(msg->mnemonic)) {    \
        return ErrInvalidValue;              \
    }

bool checkInitialized(void);

bool checkNotInitialized(void);

bool checkPin(void);

bool checkPinUncached(void);

bool checkParam(bool cond, const char* errormsg);

bool checkPrecondition(bool cond, const char* errormsg);

bool checkButtonProtect(void);

ErrCode_t checkButtonProtectRetErrCode(void);

bool checkMnemonic(void);

bool checkInputs(TransactionSign* msg);

bool checkOutputs(TransactionSign* msg);

bool checkMnemonicChecksum(SetMnemonic* msg);

ErrCode_t signTransactionMessageFromHDW(uint8_t* message_digest, Bip44AddrIndex bip44, char* signed_message);

ErrCode_t
fsm_getKeyPairAtIndex(uint32_t nbAddress, uint8_t* pubkey, uint8_t* seckey, ResponseSkycoinAddress* respSkycoinAddress, uint32_t start_index);

ErrCode_t addressFromHdw(SkycoinAddress* msg, ResponseSkycoinAddress* resp);

ErrCode_t keyPairFromHdw(SkycoinSignMessage* msg, uint8_t* seckey, uint8_t* pubkey);

ErrCode_t addressFromHdwWithTransactionOutput(SkycoinTransactionOutput output, char* addr, size_t* addr_size);

ErrCode_t msgGenerateMnemonicImpl(GenerateMnemonic* msg, void (*random_buffer_func)(uint8_t* buf, size_t len));

ErrCode_t msgEntropyAckImpl(EntropyAck* msg);

ErrCode_t msgSignTransactionMessageImpl(uint8_t* message_digest, uint32_t index, char* signed_message, bool with_passphrase);

ErrCode_t msgApplySettingsImpl(ApplySettings* msg);

ErrCode_t msgGetFeaturesImpl(Features* resp);

ErrCode_t msgPingImpl(Ping* msg);

ErrCode_t msgChangePinImpl(ChangePin* msg, const char* (*)(PinMatrixRequestType, const char*));

ErrCode_t msgWipeDeviceImpl(WipeDevice* msg);

ErrCode_t msgSetMnemonicImpl(SetMnemonic* msg);

ErrCode_t msgGetEntropyImpl(GetRawEntropy* msg, Entropy* resp, void (*random_buffer_func)(uint8_t* buf, size_t len));

ErrCode_t msgLoadDeviceImpl(LoadDevice* msg);

ErrCode_t msgBackupDeviceImpl(BackupDevice* msg, ErrCode_t (*)(void));

ErrCode_t msgRecoveryDeviceImpl(RecoveryDevice* msg, ErrCode_t (*)(void));

ErrCode_t msgSignTxImpl(SignTx* msg, TxRequest* resp);

ErrCode_t msgTxAckImpl(TxAck* msg, TxRequest* resp);

ErrCode_t reqConfirmTransaction(uint64_t coins, uint64_t hours, char* address);

#endif // __TINYFIRMWARE_FIRMWARE_FSMIMPL_H__
