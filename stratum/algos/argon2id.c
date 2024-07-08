#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sysendian.h"
#include "ar2id/argon2.h"
#include "ar2id/blake2/blake2.h"
#include "ar2id/sha512.h"

#define SHA512_HASH_SIZE 64

static const size_t INPUT_BYTES = 80;  // Length of a block header in bytes

void argon2iddpc_call(const void *input, void *output)
{
    uint8_t salt_sha512_first[SHA512_HASH_SIZE];
    uint8_t salt_sha512_second[SHA512_HASH_SIZE];
    uint8_t hash1[32];
    uint8_t hash2[32];

    // First SHA-512 hash
    SHA512Hash((uint8_t *)input, salt_sha512_first);

    // Second SHA-512 hash
    SHA512Hash(salt_sha512_first, salt_sha512_second);

    const void *pwd = input;
    size_t pwdlen = INPUT_BYTES;
    const void *salt = salt_sha512_second;
    size_t saltlen = SHA512_HASH_SIZE;

    // Calling the first round of Argon2id
    int rc = argon2id_hash_raw(2, 4096, 2, pwd, pwdlen, salt, saltlen, hash1, 32);
    if (rc != ARGON2_OK) {
        printf("Error: Failed to compute Argon2id hash for the first round\n");
        exit(1);
    }

    // Using the result of the first round as salt for the second round
    salt = hash1;
    saltlen = 32;

    // Calling the second round of Argon2id
    rc = argon2id_hash_raw(2, 32768, 2, pwd, pwdlen, salt, saltlen, hash2, 32);
    if (rc != ARGON2_OK) {
        printf("Error: Failed to compute Argon2id hash for the second round\n");
        exit(1);
    }

    return hash2;
}

void argon2iddpc_hash(const unsigned char *input, unsigned char *output, unsigned int len)
{
    argon2iddpc_call(input, output);
}