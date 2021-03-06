#include <stdint.h>
#include <string.h>
#include <time.h>

#include "libskycoin.h"
#include "skyerrors.h"

#include "skycoin_crypto.h"
#include "tools/base58.h"
#include "tools/ripemd160.h"
#include "tools/sha2.h"

GoUint32 SKY_cipher_SumSHA256(GoSlice p0, cipher__SHA256* p1)
{
    sha256sum(p0.data, *p1, p0.len);
    return SKY_OK;
}

GoUint32 SKY_cipher_SHA256FromHex(GoString p0, cipher__SHA256* p1)
{
    if (!tobuff(p0.p, (uint8_t*)p1, p0.n / 2)) {
        return SKY_ERROR;
    }
    if (p0.n != sizeof(cipher__SHA256) * 2) {
        return SKY_ErrInvalidHexLength;
    }
    return SKY_OK;
}

GoUint32 SKY_cipher_AddSHA256(cipher__SHA256* p0, cipher__SHA256* p1, cipher__SHA256* p2)
{
    sha256sum_two((const uint8_t*)p0, sizeof(cipher__SHA256) / sizeof(uint8_t),
        (const uint8_t*)p1, sizeof(cipher__SHA256) / sizeof(uint8_t),
        (uint8_t*)p2);
    return SKY_OK;
}

GoUint32 SKY_cipher_GenerateKeyPair(cipher__PubKey* p0, cipher__SecKey* p1)
{
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    static int always_wrowing = 0;
    // always_wrowing ensure that srand receive a different value for each call,
    // even if more than one SKY_cipher_GenerateKeyPair call is done almost at
    // the same time, currently SKY_cipher_GenerateKeyPair is not called so many
    // times to be required an integer overflow check in always_wrowing
    srand(time(0) + ++always_wrowing);
    int seed = rand();
    uint8_t nextSeed[SHA256_DIGEST_LENGTH] = {0};
    sha256sum((const uint8_t*)&seed, digest, sizeof(seed));
    deterministic_key_pair_iterator(digest, sizeof(digest), nextSeed, (uint8_t*)p1, (uint8_t*)p0);
    return SKY_OK;
}

GoUint32 SKY_cipher_GenerateDeterministicKeyPair(GoSlice p0, cipher__PubKey* p1, cipher__SecKey* p2)
{
    uint8_t nextSeed[SHA256_DIGEST_LENGTH] = {0};
    deterministic_key_pair_iterator(p0.data, p0.len, nextSeed, (uint8_t*)p2, (uint8_t*)p1);
    return SKY_OK;
}

GoUint32 SKY_cipher_AddressFromPubKey(cipher__PubKey* p0, cipher__Address* p1)
{
    char buff[256] = {0};
    size_t size_address = sizeof(buff);
    skycoin_address_from_pubkey(
        (const uint8_t*)p0, buff, &size_address);
    GoString add = {.p = buff, .n = sizeof(buff)};
    return SKY_cipher_DecodeBase58Address(add, p1);
}

GoUint32 SKY_cipher_Address_Verify(cipher__Address* p0, cipher__PubKey* p1)
{
    if (p0->Version != 0x00) {
        return SKY_ErrAddressInvalidVersion;
    }
    GoSlice gs1 = {.data = (void*)p1, .len = sizeof(cipher__PubKey)};
    cipher__Ripemd160 rp;
    GoUint32 ret = SKY_cipher_HashRipemd160(gs1, &rp);
    if (ret != SKY_OK) {
        return ret;
    }
    if (memcmp((const char*)(p0->Key), (const char*)rp, sizeof(p0->Key))) {
        return SKY_ErrAddressInvalidPubKey;
    }
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_Checksum(cipher__Address* p0, cipher__Checksum* p1)
{
    uint8_t r1[sizeof(p0->Key) + sizeof(p0->Version)] = {0};
    memcpy(r1, p0->Key, sizeof(p0->Key));
    memcpy(&r1[sizeof(p0->Key)], &(p0->Version), sizeof(p0->Version));
    cipher__SHA256 r2 = {0};
    GoSlice gr1 = {.data = r1, .len = sizeof(r1)};
    SKY_cipher_SumSHA256(gr1, &r2);
    memcpy(*p1, r2, sizeof(cipher__Checksum));
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_Bytes(cipher__Address* p0, GoSlice_* p1)
{
    uint8_t b[20 + 1 + 4] = {0};
    memcpy(b, p0->Key, sizeof(p0->Key));
    memcpy(&b[20], &(p0->Version), sizeof(p0->Version));
    cipher__Checksum chs = {0};
    GoUint32 err = SKY_cipher_Address_Checksum(p0, &chs);
    if (err != SKY_OK) {
        return err;
    }
    memcpy(&b[21], chs, sizeof(chs));
    memcpy(p1->data, b, sizeof(b));
    p1->len = sizeof(b);
    return SKY_OK;
}

GoUint32 SKY_base58_Encode(GoSlice p0, GoString_* p1)
{
    return b58enc((char*)p1->p, (size_t*)&(p1->n), p0.data, p0.len) ? SKY_OK : SKY_ERROR;
}

GoUint32 SKY_base58_Decode(GoString p0, GoSlice_* p1)
{
    size_t sz = p0.n;
    if (!b58tobin((void*)p0.p, &sz, p1->data)) {
        return SKY_ERROR;
    }
    p1->len = sz;
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_String(cipher__Address* p0, GoString_* p1)
{
    char str[25] = {0};
    GoSlice_ bytes = {.data = str, .len = sizeof(str)};
    GoUint32 ret = SKY_cipher_Address_Bytes(p0, &bytes);
    if (ret != SKY_OK) {
        return ret;
    }
    GoSlice sl = {.data = bytes.data, .len = bytes.len};
    ret = SKY_base58_Encode(sl, p1);
    if (ret != SKY_OK) {
        return ret;
    }
    return SKY_OK;
}

GoUint32 SKY_cipher_Address_Null(cipher__Address* p0, GoUint8* p1)
{
    cipher__Address a;
    memset(&a, 0, sizeof(cipher__Address));
    *p1 = memcmp(p0->Key, a.Key, sizeof(p0->Key)) == 0 && p0->Version == a.Version;
    return SKY_OK;
}

GoUint32 SKY_cipher_PubKey_Verify(cipher__PubKey* p0)
{
    if (!verify_pub_key((const uint8_t*)p0)) {
        return SKY_ErrInvalidPubKey;
    }
    return SKY_OK;
}

GoUint32 SKY_cipher_AddressFromBytes(GoSlice p0, cipher__Address* p1)
{
    if (p0.len != 20 + 1 + 4) {
        return SKY_ErrAddressInvalidLength;
    }
    memcpy(p1->Key, (uint8_t*)(p0.data), sizeof(p1->Key));
    memcpy(&(p1->Version), &((uint8_t*)(p0.data))[20], sizeof(p1->Version));
    cipher__Checksum chs = {0};
    int ret = SKY_cipher_Address_Checksum(p1, &chs);
    if (ret != SKY_OK) {
        return ret;
    }
    if (memcmp(chs, &((uint8_t*)(p0.data))[21], sizeof(chs))) {
        return SKY_ErrAddressInvalidChecksum;
    }
    if (p1->Version != 0) {
        return SKY_ErrAddressInvalidVersion;
    }
    return SKY_OK;
}

GoUint32 SKY_cipher_NewPubKey(GoSlice p0, cipher__PubKey* p1)
{
    if (sizeof(*p1) != p0.len) {
        return SKY_ErrInvalidLengthPubKey;
    }
    memcpy(p1, p0.data, p0.len);
    return SKY_cipher_PubKey_Verify(p1);
}

GoUint32 SKY_cipher_DecodeBase58Address(GoString p0, cipher__Address* p1)
{
    uint8_t decoded[250] = {0};
    size_t bz = sizeof(decoded);
    if (!b58tobin(decoded, &bz, p0.p)) {
        return SKY_ERROR;
    }
    GoSlice sl = {.data = &decoded[sizeof(decoded) - bz], .len = bz, .cap = bz};
    return SKY_cipher_AddressFromBytes(sl, p1);
}

GoUint32 SKY_base58_Hex2Base58(GoSlice p0, GoString_* p1)
{
    return SKY_base58_Encode(p0, p1);
}

GoUint32 SKY_cipher_HashRipemd160(GoSlice p0, cipher__Ripemd160* p1)
{
    cipher__SHA256 s1 = {0};
    SKY_cipher_SumSHA256(p0, &s1);
    cipher__SHA256 s2 = {0};
    GoSlice gs2 = {.data = (void*)s1, .len = sizeof(cipher__SHA256)};
    SKY_cipher_SumSHA256(gs2, &s2);
    ripemd160((const uint8_t*)s2, sizeof(cipher__SHA256), *p1);
    return SKY_OK;
}

GoUint32 SKY_cipher_SHA256_Hex(cipher__SHA256* p0, GoString_* p1)
{
    p1->n = sizeof(cipher__SHA256) * 2;
    p1->p = (const char*)calloc(p1->n + 1, sizeof(uint8_t));
    memset((char*)(p1->p), 0, p1->n + 1);
    tohex((char*)p1->p, (const uint8_t*)p0, sizeof(cipher__SHA256));
    return SKY_OK;
}

GoUint32 SKY_cipher_SHA256_Set(cipher__SHA256* p0, GoSlice p1)
{
    if (sizeof(cipher__SHA256) != p1.len) {
        return SKY_ErrInvalidLengthSHA256;
    }
    memcpy(p0, p1.data, p1.len);
    return SKY_OK;
}

GoUint32 SKY_cipher_SHA256_Null(cipher__SHA256* p0, GoUint8* p1)
{
    cipher__SHA256 s;
    memset(&s, 0, sizeof(cipher__SHA256));
    *p1 = memcmp(p0, &s, sizeof(cipher__SHA256)) == 0;
    return SKY_OK;
}

GoUint32 SKY_cipher_PubKeyFromHex(GoString p0, cipher__PubKey* p1)
{
    uint8_t* buf = (uint8_t*)calloc(p0.n / 2, sizeof(uint8_t));
    if (!tobuff(p0.p, buf, p0.n / 2)) {
        return SKY_ErrInvalidPubKey;
    }
    GoSlice data = {.data = buf, .len = p0.n / 2};
    GoUint32 ret = SKY_cipher_NewPubKey(data, p1);
    free(buf);
    return ret;
}

GoUint32 SKY_cipher_PubKey_Hex(cipher__PubKey* p0, GoString_* p1)
{
    p1->p = (const char*)calloc(sizeof(cipher__PubKey) * 2, sizeof(char));
    tohex((char*)p1->p, (const uint8_t*)p0, sizeof(cipher__PubKey));
    p1->n = sizeof(cipher__PubKey) * 2;
    return SKY_OK;
}

GoUint32 SKY_cipher_NewSig(GoSlice p0, cipher__Sig* p1)
{
    if (p0.len != sizeof(cipher__Sig)) {
        return SKY_ErrInvalidLengthSig;
    }
    memcpy(p1, p0.data, p0.len);
    return SKY_OK;
}

GoUint32 SKY_cipher_Sig_Hex(cipher__Sig* p0, GoString_* p1)
{
    tohex((char*)(p1->p), (uint8_t*)p0, sizeof(cipher__Sig));
    p1->n = sizeof(cipher__Sig) * 2;
    return SKY_OK;
}

GoUint32 SKY_cipher_SigFromHex(GoString p0, cipher__Sig* p1)
{
    uint8_t* buf = (uint8_t*)calloc(p0.n / 2, sizeof(uint8_t));
    GoUint32 ret;
    if (!tobuff(p0.p, buf, p0.n / 2)) {
        ret = SKY_ErrInvalidSig;
        goto free_mem;
    }
    GoSlice s_buf = {.data = buf, .len = p0.n / 2};
    ret = SKY_cipher_NewSig(s_buf, p1);
free_mem:
    free(buf);
    return ret;
}

GoUint32 SKY_cipher_NewSecKey(GoSlice p0, cipher__SecKey* p1)
{
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

GoUint32 SKY_cipher_PubKeyFromSecKey(cipher__SecKey* p0, cipher__PubKey* p1)
{
    cipher__SecKey dumy = {0};
    if (!memcmp(&dumy, p0, sizeof(cipher__SecKey))) {
        return SKY_ErrPubKeyFromNullSecKey;
    }
    skycoin_pubkey_from_seckey((uint8_t*)p0, (uint8_t*)p1);
    return SKY_OK;
}

GoUint32 SKY_cipher_ECDH(cipher__PubKey* p0, cipher__SecKey* p1, GoSlice_* p2)
{
    return ecdh((const uint8_t*)p1, (const uint8_t*)p0, p2->data) ? SKY_ERROR : SKY_OK;
}

GoUint32 SKY_cipher_PubKeyFromSig(cipher__Sig* p0, cipher__SHA256* p1, cipher__PubKey* p2)
{
    int ret = skycoin_ecdsa_sign_digest(
        (const char*)p0, (const uint8_t*)p1, (uint8_t*)p2);
    if (ret) {
        return SKY_OK;
    } else {
        return !SKY_OK;
    }
}
