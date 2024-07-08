#ifndef ARGON2ID_H
#define ARGON2ID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void argon2iddpc_hash(const char* input, char* output, unsigned int len);

#ifdef __cplusplus
}
#endif

#endif