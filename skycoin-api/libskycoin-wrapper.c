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

extern GoUint32 SKY_cipher_AddSHA256(cipher__SHA256* p0, cipher__SHA256* p1, cipher__SHA256* p2) {
    add_sha256(p0, sizeof(cipher__SHA256)/sizeof(uint8_t), 
               p1, sizeof(cipher__SHA256)/sizeof(uint8_t), 
               p2, sizeof(cipher__SHA256)/sizeof(uint8_t));
}
