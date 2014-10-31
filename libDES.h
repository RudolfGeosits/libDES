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
#ifndef UTILS_C
#include "utils.c"
#endif
#ifndef PERMUTATIONS_C
#include "permutations.c"
#endif

uint32_t feistel(uint32_t right, uint64_t round_key);
/*
#
*/

uint64_t des_encrypt(uint64_t block, uint64_t key);
/*
#
*/

uint64_t des_decrypt(uint64_t block, uint64_t key);
/*
#
*/

#include "libDES.c"
