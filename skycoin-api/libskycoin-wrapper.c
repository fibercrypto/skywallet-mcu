#include "libskycoin.h"

#include <stdint.h>
#include <string.h>

#include "skyerrors.h"

#include "sha2.h"
#include "ripemd160.h"

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
    size_t size_address = 0;;
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
