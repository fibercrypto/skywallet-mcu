#include "libskycoin.h"

#include <stdint.h>
#include <string.h>

#include "skyerrors.h"

#include "sha2.h"
#include "ripemd160.h"
#include "base58.h"

GoUint32 SKY_cipher_SumSHA256(GoSlice p0, cipher__SHA256* p1) {
    compute_sha256sum(p0.data, p1, sizeof(p1));
    return SKY_OK;
}

GoUint32 SKY_cipher_SHA256FromHex(GoString p0, cipher__SHA256* p1) {
    uint8_t *buf = (uint8_t*)calloc(p0.n/2, sizeof(uint8_t));
    tobuff(p0.p, buf, p0.n/2);
    compute_sha256sum(buf, p1, p0.n/2);
    free(buf);
}

GoUint32 SKY_cipher_AddSHA256(cipher__SHA256* p0, cipher__SHA256* p1, cipher__SHA256* p2) {
    add_sha256(p0, sizeof(cipher__SHA256)/sizeof(uint8_t), 
               p1, sizeof(cipher__SHA256)/sizeof(uint8_t), 
               p2, sizeof(cipher__SHA256)/sizeof(uint8_t));
}

GoUint32 SKY_cipher_GenerateKeyPair(cipher__PubKey* p0, cipher__SecKey* p1) {
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    int seed = rand();
    uint8_t seedd[SHA256_DIGEST_LENGTH] = {0};
    memcpy(&seedd, &seed, sizeof(seed));
    compute_sha256sum((const uint8_t*)seedd, digest, sizeof(seed));
    generate_deterministic_key_pair(digest, sizeof(digest), p1, p0);
    return SKY_OK;
}

GoUint32 SKY_cipher_GenerateDeterministicKeyPair(GoSlice p0, cipher__PubKey* p1, cipher__SecKey* p2) {
    generate_deterministic_key_pair(p0.data, p0.len, p1, p2);
    return SKY_OK;
}

GoUint32 SKY_cipher_AddressFromPubKey(cipher__PubKey* p0, cipher__Address* p1) {
    size_t size_address = 0;
    generate_base58_address_from_pubkey(p0, p1->Key, &size_address);
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_Verify(cipher__Address* p0, cipher__PubKey* p1) {
    if (p0->Version != 0x00) {
        return SKY_ErrAddressInvalidVersion;
    }
    uint8_t hash[RIPEMD160_DIGEST_LENGTH] = {0};
    ripemd160((int*)p1, sizeof(cipher__PubKey), hash);
    if (strncmp(p0->Key, hash, sizeof(p0->Key))) {
        return SKY_ErrAddressInvalidPubKey;
    }
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_Checksum(cipher__Address* p0, cipher__Checksum* p1) {
    uint8_t r1[sizeof(p0->Key) + sizeof(p0->Version)] = {0};
    memcpy(r1, p0->Key, sizeof(p0->Key));
    memcpy(&r1[sizeof(p0->Key)], p0->Version, sizeof(p0->Version));
    uint8_t r2[SHA256_DIGEST_LENGTH] = {0};
    GoSlice gr1 = {.data = r1, .len = sizeof(r1)};
    SKY_cipher_SumSHA256(gr1, r2);
    memcpy(p1, r2, sizeof(cipher__Checksum));
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_Bytes(cipher__Address* p0, coin__UxArray* p1) {
    uint8_t b[20 + 1 + 4] = {0};
    memcpy(b, p0->Key, sizeof(p0->Key));
    memcpy(&b[20], &(p0->Version), sizeof(p0->Version));
    cipher__Checksum chs = {0};
    SKY_cipher_Address_Checksum(p0, chs);
    memcpy(&b[21], chs, sizeof(chs));
    memcpy(p1, &b[21], sizeof(b));
    return SKY_OK;
}

GoUint32 SKY_base58_Encode(GoSlice p0, GoString_* p1) {
    b58enc(p0.data, p0.len, p1->p, p1->n);
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
    return SKY_OK;
}

GoUint32 SKY_cipher_AddressFromBytes(GoSlice p0, cipher__Address* p1) {
    memcpy(p1->Key, p0.data, 20);
    memcpy(&(p1->Version), &(p0.data[20]), 1);
    cipher__Checksum chs = {0};
    SKY_cipher_Address_Checksum(p1, chs);
    if (memcmp(chs, &(p0.data[21]), sizeof(chs))) {
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
    bool ret = b58tobin(p0.p, p0.n, &(p1->Key));
    return ret ? SKY_OK : !SKY_OK;
}

GoUint32 SKY_base58_Hex2Base58(GoSlice p0, GoString_* p1) {
    tobuff(p0.data, p1, p0.len/2);
    return SKY_OK;
}

GoUint32 SKY_cipher_HashRipemd160(GoSlice p0, cipher__Ripemd160* p1) {
    ripemd160(p0.data, p0.len, p1);
    return SKY_OK;
}

GoUint32 SKY_cipher_SHA256_Hex(cipher__SHA256* p0, GoString_* p1) {
    tohex(p0, p1->p, sizeof(cipher__SHA256));
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
