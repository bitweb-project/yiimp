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
    SHA512Hash((const unsigned char *)input, INPUT_BYTES, salt_sha512_first);

    uint8_t salt_sha512_second[SHA512_HASH_SIZE];
    SHA512Hash(salt_sha512_first, SHA512_HASH_SIZE, salt_sha512_second);

    const void *pwd = input;
    size_t pwdlen = INPUT_BYTES;
    const void *salt = salt_sha512_second;
    size_t saltlen = SHA512_HASH_SIZE;

    uint8_t hash1[32];
    int rc = argon2id_hash_raw(2, 4096, 2, pwd, pwdlen, salt, saltlen, hash1, 32);

    salt = hash1;
    saltlen = 32;

    uint8_t hash2[32];
    rc = argon2id_hash_raw(2, 32768, 2, pwd, pwdlen, salt, saltlen, hash2, 32);

    memcpy(output, hash2, 32);
}

void argon2iddpc_hash(const unsigned char *input, unsigned char *output, unsigned int len)
{
    argon2iddpc_call(input, output);
}