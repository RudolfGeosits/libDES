//#define LD_DEBUG
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

uint64_t ld_encrypt3(uint64_t block, uint64_t *keys);
/*
# 3DES Encryption Ek3(Dk2(Ek1(BLOCK)))
*/

uint64_t ld_decrypt3(uint64_t block, uint64_t *keys);
/*
# 3DES Decryption Dk1(Ek2(Dk3(BLOCK)))   
*/

uint64_t ld_encryptn(uint64_t block, uint32_t n, uint64_t *keys);
/*
# N-DES Encryption ...Ek3(Dk2(Ek1(BLOCK)))
# Use 1..n DES where n is an odd number
*/

uint64_t ld_decryptn(uint64_t block, uint32_t n, uint64_t *keys);
/*
# N-DES Decryption ...Dk1(Ek2(Dk3(BLOCK)))   
# Use 1..n DES where n is an odd number
*/

void ld_encryptm(char *message, char *cipher_text, uint8_t mode, ...);
/*
# Encrypt a message with modes LD_DES, LD_3DES, or LD_NDES
# Variable arguments will be, respectively:
#   ld_encryptm(P, C, LD_DES, KEY) where KEY is 64 bits
#   ld_encryptm(P, C, LD_3DES, KEYS) where KEYS is an array of 3 or more 64 bit keys
#   ld_encryptm(P, C, LD_NDES, N, KEYS) where N is the amount of DES oscillation  
#                                       and KEYS is an array of N or more 64 bit keys
*/

void ld_decryptm(char *cipher_text, char *message, uint8_t mode, ...);
/*
# Decrypt a message with modes LD_DES, LD_3DES, or LD_NDES
# Variable arguments will be, respectively:
#   ld_decryptm(P, C, LD_DES, KEY) where KEY is 64 bits
#   ld_decryptm(P, C, LD_3DES, KEYS) where KEYS is an array of 3 or more 64 bit keys
#   ld_decryptm(P, C, LD_NDES, N, KEYS) where N is the amount of DES oscillation  
#                                       and KEYS is an array of N or more 64 bit keys
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
