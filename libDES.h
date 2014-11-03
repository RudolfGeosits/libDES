//#define DEBUG
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
#ifndef STDARG_H
#include <stdarg.h>
#endif
#ifndef UTILS_C
#include "utils.c"
#endif
#ifndef PERMUTATIONS_C
#include "permutations.c"
#endif

uint64_t ld_encrypt(uint64_t block, uint64_t key);
/*
# Call to Internal _ld_des(block, key, DES_ENCRYPT)
*/

uint64_t ld_decrypt(uint64_t block, uint64_t key);
/*
# Call to Internal _ld_des(block, key, DES_DECRYPT)
*/

uint64_t ld_encrypt3(uint64_t block, uint64_t key1, uint64_t key2, uint64_t key3);
/*
# 3DES Encryption Ek3(Dk2(Ek1(BLOCK)))
*/

uint64_t ld_decrypt3(uint64_t block, uint64_t key1, uint64_t key2, uint64_t key3);
/*
# 3DES Decryption Dk1(Ek2(Dk3(BLOCK)))   
*/

uint64_t ld_decryptn(uint64_t block, uint32_t n, ...);
/*
# N-DES Decryption ...Dk1(Ek2(Dk3(BLOCK)))   
# Use 3+ DES
*/

uint32_t _ld_feistel(uint32_t right, uint64_t round_key);
/*
# Calculate the feistel round function in the encryption or 
# decryption routine
*/

uint64_t _ld_des(uint64_t block, uint64_t key, uint8_t mode);
/*
# Basic Encryption and Decryption method for DES
*/

#include "libDES.c"
