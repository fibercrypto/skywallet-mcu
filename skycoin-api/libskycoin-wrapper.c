#include "libskycoin.h"

#include <stdint.h>

GoUint32 SKY_cipher_SumSHA256(GoSlice p0, cipher__SHA256* p1) {
    compute_sha256sum(p0.data, p1, sizeof(p1));
    return 0;
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
    return 0;
}

GoUint32 SKY_cipher_GenerateDeterministicKeyPair(GoSlice p0, cipher__PubKey* p1, cipher__SecKey* p2) {
    generate_deterministic_key_pair(p0.data, p0.len, p1, p2);
    return 0;
}

GoUint32 SKY_cipher_AddressFromPubKey(cipher__PubKey* p0, cipher__Address* p1) {
    size_t size_address = 0;;
    generate_base58_address_from_pubkey(p0, p1->Key, &size_address);
    return 0;
}
