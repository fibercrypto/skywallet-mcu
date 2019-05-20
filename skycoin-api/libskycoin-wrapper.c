#include "libskycoin.h"

#include <stdint.h>
#include <string.h>
#include <time.h>

#include "skyerrors.h"

#include "sha2.h"
#include "skycoin_crypto.h"
#include "ripemd160.h"
#include "base58.h"
#include "skycoin_check_signature.h"

GoUint32 SKY_cipher_SumSHA256(GoSlice p0, cipher__SHA256* p1) {
    compute_sha256sum(p0.data, (uint8_t*)p1, sizeof(p1));
    return SKY_OK;
}

GoUint32 SKY_cipher_SHA256FromHex(GoString p0, cipher__SHA256* p1) {
    if (p0.n != sizeof(cipher__SHA256) * 2) {
        return SKY_ErrInvalidHexLength;
    }
    tobuff(p0.p, p1, p0.n/2);
    return SKY_OK;
}

GoUint32 SKY_cipher_AddSHA256(cipher__SHA256* p0, cipher__SHA256* p1, cipher__SHA256* p2) {
    add_sha256((const uint8_t*)p0, sizeof(cipher__SHA256)/sizeof(uint8_t),
               (const uint8_t*)p1, sizeof(cipher__SHA256)/sizeof(uint8_t),
               (uint8_t*)p2);
    return SKY_OK;
}

GoUint32 SKY_cipher_GenerateKeyPair(cipher__PubKey* p0, cipher__SecKey* p1) {
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    srand(time(0));
    int seed = rand();
    compute_sha256sum((const uint8_t*)&seed, digest, sizeof(seed));
    generate_deterministic_key_pair(digest, sizeof(digest), (uint8_t*)p1, (uint8_t*)p0);
    return SKY_OK;
}

GoUint32 SKY_cipher_GenerateDeterministicKeyPair(GoSlice p0, cipher__PubKey* p1, cipher__SecKey* p2) {
    generate_deterministic_key_pair(p0.data, p0.len, (uint8_t *)p2, (uint8_t*)p1);
    return SKY_OK;
}

GoUint32 SKY_cipher_AddressFromPubKey(cipher__PubKey* p0, cipher__Address* p1) {
    size_t size_address = 0;
    generate_base58_address_from_pubkey(
                (const uint8_t*)p0, (char *)p1->Key, &size_address);
    p1->Version = 0;
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_Verify(cipher__Address* p0, cipher__PubKey* p1) {
    if (p0->Version != 0x00) {
        return SKY_ErrAddressInvalidVersion;
    }
    uint8_t hash[RIPEMD160_DIGEST_LENGTH] = {0};
    ripemd160((const uint8_t*)p1, sizeof(cipher__PubKey), hash);
    if (memcmp((const char*)(p0->Key), (const char*)hash, sizeof(p0->Key))) {
        return SKY_ErrAddressInvalidPubKey;
    }
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_Checksum(cipher__Address* p0, cipher__Checksum* p1) {
    uint8_t r1[sizeof(p0->Key) + sizeof(p0->Version)] = {0};
    memcpy(r1, p0->Key, sizeof(p0->Key));
    memcpy(&r1[sizeof(p0->Key)], &(p0->Version), sizeof(p0->Version));
    cipher__SHA256 r2 = {0};
    GoSlice gr1 = {.data = r1, .len = sizeof(r1)};
    SKY_cipher_SumSHA256(gr1, &r2);
    memcpy(p1, r2, sizeof(cipher__Checksum));
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_Bytes(cipher__Address* p0, coin__UxArray* p1) {
    uint8_t b[20 + 1 + 4] = {0};
    memcpy(b, p0->Key, sizeof(p0->Key));
    memcpy(&b[20], &(p0->Version), sizeof(p0->Version));
    cipher__Checksum chs = {0};
    SKY_cipher_Address_Checksum(p0, &chs);
    memcpy(&b[21], chs, sizeof(chs));
    memcpy(p1->data, b, sizeof(b));
    p1->len = sizeof(b);
    return SKY_OK;
}

GoUint32 SKY_base58_Encode(GoSlice p0, GoString_* p1) {
    b58enc(p0.data, (size_t *)&(p0.len), p1->p, p1->n);
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_String(cipher__Address* p0, GoString_* p1) {
    char str[1024] = {0};
    coin__UxArray bytes = {.data = str, .len = sizeof(str)};
    SKY_cipher_Address_Bytes(p0, &bytes);
    GoSlice sl = {.data=bytes.data, .len=bytes.len};
    SKY_base58_Encode(sl, p1);
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_Null(cipher__Address* p0, GoUint8* p1) {
    cipher__Address a;
    memset(&a, 0, sizeof(cipher__Address));
    *p1 = memcmp(p0->Key, a.Key, sizeof(p0->Key)) == 0 && p0->Version == a.Version;
    return SKY_OK;
}

GoUint32 SKY_cipher_PubKey_Verify(cipher__PubKey* p0) {
    // FIXME This should be implemented
    (void)p0;
    return SKY_OK;
}

GoUint32 SKY_cipher_AddressFromBytes(GoSlice p0, cipher__Address* p1) {
    memcpy(p1->Key, (uint8_t*)(p0.data), 20);
    memcpy(&(p1->Version), (uint8_t*)p0.data + 20, 1);
    cipher__Checksum chs = {0};
    SKY_cipher_Address_Checksum(p1, &chs);
    if (memcmp(chs, (uint8_t*)(p0.data) + 21, sizeof(chs))) {
        return SKY_ErrAddressInvalidChecksum;
    }
    if (p1->Version != 0) {
        return SKY_ErrAddressInvalidVersion;
    }
    return SKY_OK;
}

GoUint32 SKY_cipher_NewPubKey(GoSlice p0, cipher__PubKey* p1) {
    if (sizeof(p1) != p0.len) {
        return SKY_ErrInvalidLengthPubKey;
    }
    memcpy(p1, p0.data, p0.len);
    int err = SKY_cipher_PubKey_Verify(p1);
    return err;
}

GoUint32 SKY_cipher_DecodeBase58Address(GoString p0, cipher__Address* p1) {
    bool ret = b58tobin((void*)p0.p, (size_t*)&(p0.n), (const char*)&(p1->Key));
    return ret ? SKY_OK : !SKY_OK;
}

GoUint32 SKY_base58_Hex2Base58(GoSlice p0, GoString_* p1) {
    tobuff(p0.data, (uint8_t*)p1, p0.len/2);
    return SKY_OK;
}

GoUint32 SKY_cipher_HashRipemd160(GoSlice p0, cipher__Ripemd160* p1) {
    ripemd160(p0.data, p0.len, (uint8_t*)p1);
    return SKY_OK;
}

GoUint32 SKY_cipher_SHA256_Hex(cipher__SHA256* p0, GoString_* p1) {
    tohex((char*)p1->p, (const uint8_t*)p0, sizeof(cipher__SHA256));
    return SKY_OK;
}

GoUint32 SKY_cipher_SHA256_Set(cipher__SHA256* p0, GoSlice p1) {
    memcpy(p0, p1.data, p1.len);
    return SKY_OK;
}

GoUint32 SKY_cipher_SHA256_Null(cipher__SHA256* p0, GoUint8* p1) {
    cipher__SHA256 s;
    memset(&s, 0, sizeof(cipher__SHA256));
    *p1 = memcmp(p0, &s, sizeof(cipher__SHA256)) == 0;
    return SKY_OK;
}

GoUint32 SKY_cipher_PubKeyFromHex(GoString p0, cipher__PubKey* p1) {
    uint8_t *buf = (uint8_t*)calloc(p0.n/2, sizeof(uint8_t));
    tobuff(p0.p, buf, p0.n/2);
    GoSlice data = {.data = buf, .len = p0.n/2};
    GoUint32 ret = SKY_cipher_NewPubKey(data, p1);
    free(buf);
    return ret;
}

GoUint32 SKY_cipher_PubKey_Hex(cipher__PubKey* p0, GoString_* p1) {
    tohex((char*)p0, (const uint8_t*)p1->p, sizeof(cipher__SHA256));
    return SKY_OK;
}

GoUint32 SKY_cipher_NewSig(GoSlice p0, cipher__Sig* p1) {
    if (p0.len != sizeof(cipher__Sig)) {
        return SKY_ErrInvalidLengthSig;
    }
    memcpy(p1, p0.data, p0.len);
    return SKY_OK;
}

GoUint32 SKY_cipher_SigFromHex(GoString p0, cipher__Sig* p1) {
    uint8_t *buf = (uint8_t*)calloc(p0.n/2, sizeof(uint8_t));
    tobuff(p0.p, buf, p0.n/2);
    GoSlice s_buf = {.data = buf, .len = p0.n/2};
    GoUint32 ret = SKY_cipher_NewSig(s_buf, p1);
    free(buf);
    return ret;
}

GoUint32 SKY_cipher_Sig_Hex(cipher__Sig* p0, GoString_* p1) {
    uint8_t *buf = (uint8_t*)calloc(p1->n/2, sizeof(uint8_t));
    tobuff(p1->p, buf, p1->n/2);
    GoSlice s_buf = {.data = buf, .len = p1->n/2};
    GoUint32 ret = SKY_cipher_NewSig(s_buf, p0);
    free(buf);
    return ret;
}

GoUint32 SKY_cipher_NewSecKey(GoSlice p0, cipher__SecKey* p1) {
    if (p0.len != sizeof(cipher__SecKey)) {
        return SKY_ErrInvalidLengthSecKey;
    }
    memcpy(p1, p0.data, sizeof(cipher__SecKey));
    // TODO
    //if err := p1->verify(false); err != nil {
    //    return SecKey{}, err
    //}
    return SKY_OK;
}

GoUint32 SKY_cipher_PubKeyFromSecKey(cipher__SecKey* p0, cipher__PubKey* p1) {
    generate_pubkey_from_seckey((uint8_t *)p0, (uint8_t *)p1);
    return SKY_OK;
}

GoUint32 SKY_cipher_ECDH(cipher__PubKey* p0, cipher__SecKey* p1, coin__UxArray* p2) {
    ecdh((const uint8_t *)p1, (const uint8_t *)p0, p2->data);
    return SKY_OK;
}

GoUint32 SKY_cipher_PubKeyFromSig(cipher__Sig* p0, cipher__SHA256* p1, cipher__PubKey* p2) {
    int ret = recover_pubkey_from_signed_message(
                (const char*)p1, (const uint8_t*)p0, (uint8_t *)p2);
    if (ret) {
        return SKY_OK;
    } else {
        return !SKY_OK;
    }
}
