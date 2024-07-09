#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sysendian.h"
#include "ar2id/argon2.h"
#include "ar2id/blake2/blake2.h"
#include "ar2id/sha512.h"

static const size_t INPUT_BYTES = 80;  // Length of a block header in bytes

void sha512_hash(const uint8_t *input, size_t input_len, uint8_t *output)
{
    sha512_context ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, input, input_len);
    sha512_final(&ctx, output);
}

void argon2iddpc_call(const unsigned char *input, unsigned char *output)
{
    uint8_t salt_sha512_first[64];
    uint8_t salt_sha512_second[64];
    uint8_t hash1[32];
    uint8_t hash2[32];

    // First SHA-512 hash
    sha512_hash(input, INPUT_BYTES, salt_sha512_first);

    // Second SHA-512 hash
    sha512_hash(salt_sha512_first, 64, salt_sha512_second);

    // Calling the first round of Argon2id
    int rc = argon2id_hash_raw(2, 4096, 2, input, INPUT_BYTES, salt_sha512_second, 64, hash1, 32);
    if (rc != ARGON2_OK) {
        printf("Error: Failed to compute Argon2id hash for the first round\n");
        exit(1);
    }

    // Using the result of the first round as salt for the second round
    rc = argon2id_hash_raw(2, 32768, 2, input, INPUT_BYTES, hash1, 32, hash2, 32);
    if (rc != ARGON2_OK) {
        printf("Error: Failed to compute Argon2id hash for the second round\n");
        exit(1);
    }

    memcpy(output, hash2, 32);
}

void argon2iddpc_hash(const unsigned char *input, unsigned char *output, unsigned int len)
{
    argon2iddpc_call(input, output);
}