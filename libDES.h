#ifndef STDLIB_H
#include <stdlib.h>
#endif
#ifndef STDIO_H
#include <stdio.h>
#endif
#ifndef STRING_H
#include <string.h>
#endif
#ifndef STDINT_H
#include <stdint.h>
#endif
#ifndef STDINT_H
#include <stdarg.h>
#endif
#ifndef UTILS_C
#include "utils.h"
#endif
#ifndef PERMUTATIONS_C
#include "permutations.h"
#endif

uint64_t ld_encrypt(uint64_t block, uint64_t key);
uint64_t ld_decrypt(uint64_t block, uint64_t key);
uint64_t ld_encrypt3(uint64_t block, uint64_t *keys);

uint64_t ld_decrypt3(uint64_t block, uint64_t *keys);
uint64_t ld_encryptn(uint64_t block, uint32_t n, uint64_t *keys);
uint64_t ld_decryptn(uint64_t block, uint32_t n, uint64_t *keys);

void ld_encryptm(char *message, char *cipher_text, uint8_t mode, ...);
void ld_decryptm(char *cipher_text, char *message, uint8_t mode, ...);

uint32_t _ld_feistel(uint32_t right, uint64_t round_key);
uint64_t _ld_des(uint64_t block, uint64_t key, uint8_t mode);

#include "libDES.c"
