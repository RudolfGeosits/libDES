/*       
libDES - 3+ DES Encryption and Decryption Library                     
Copyright (C) 2014 Rudolf Geosits (rgeosits@live.esu.edu)
 
This program is free software: you can redistribute it and/or modify 
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or   
(at your option) any later version.                               

This program is distributed in the hope that it will be useful,    
but WITHOUT ANY WARRANTY; without even the implied warranty of      
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the       
GNU General Public License for more details.
                                                                  
You should have received a copy of the GNU General Public License 
along with this program.  If not, see <http://www.gnu.org/licenses
*/

#include "permutations.h"

//##########+++ Initial Permutation (IP) +++##########
void initial_permutation(uint64_t *block)
{
  static const uint8_t ip_template[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
  };

  uint64_t mask = 0x8000000000000000, tmp_block = *block;
  uint8_t i;
  *block = 0;

  //# bit a[X] becomes bit Y
  for(i = 0;i < 64;i++){
    tmp_block & (mask >> ip_template[i]-1) ? *block |= (mask >> i) : 0;
  }
}

//##########+++ Final Permutation (IP^-1) +++##########
void final_permutation(uint64_t *block)
{
  static const unsigned char fp_template[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
  };

  uint64_t mask = 0x8000000000000000, tmp_block = *block;
  uint8_t i;
  *block = 0;

  //# bit a[X] becomes bit Y
  for(i = 0;i < 64;i++){
    tmp_block & (mask >> fp_template[i]-1) ? *block |= (mask >> i) : 0;
  }
}


//##########+++ Expansion Permutation (E) +++##########
uint64_t expansion_permutation(uint32_t block)
{
  static const unsigned char e_template[48] = {
    32,  1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
  };

  uint64_t e_mask = 0x800000000000, new_block = 0;
  uint32_t block_mask = 0x80000000, i;

  //# bit a[X] becomes bit Y
  for(i = 0;i < 48;i++){
    block&(block_mask >> e_template[i]-1) ? new_block |= e_mask>>i : 0;
  }

  #ifdef LD_DEBUG
  printf("\n\t[EXPANSION of Ri]\nRi   =  ");
  print_binary(block, 48);
  printf("E(Ri) = ");
  print_binary(new_block, 48);
  #endif

  return new_block;
}

//##########+++ Left shift for key segment encryption +++########## 
void left_shift_key_segment(uint32_t *key_seg, unsigned char round)
{
  static const unsigned char shift_table[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
  };

  uint32_t mask = 0x8000000;
  uint8_t i, CF = 0;

  for(i = 0;i < shift_table[round];i++){
    *key_seg & mask ? CF = 1 : (CF = 0);
    *key_seg = ((*key_seg << 1) & 0x0FFFFFFE) | CF;
  }
}

//##########+++ Right shift for key segment decryption +++########## 
void right_shift_key_segment(uint32_t *key_seg, unsigned char round)
{
  static const unsigned char shift_table[16] = {
    1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1, 1
  };

  uint32_t i, CF = 0, mask = 1;

  for(i = 0;i < shift_table[round];i++){
    *key_seg & mask ? CF = 0x8000000 : (CF = 0);
    *key_seg = ((*key_seg >> 1) & 0x07FFFFFF) | CF;
  }
}

//##########+++ Permuted Choice 1 (PC1) +++########## 
uint64_t permuted_choice_1(uint64_t key)
{
  static const unsigned char pc_1[56] = {
    57, 49, 41, 33, 25, 17,  9,
    1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
  };

  uint64_t pc1_mask = 0x80000000000000, new_key = 0,
           key_mask = 0x8000000000000000;
  uint8_t i;
  
  //# bit a[X] becomes bit Y
  for(i = 0;i < 56;i++){
    key & (key_mask >> pc_1[i]-1) ? new_key |= (pc1_mask >> i) : 0;
  }

  return new_key;
}

//##########+++ Permuted Choice 2 (PC2) +++########## 
uint64_t permuted_choice_2(uint32_t C, uint32_t D)
{
  static const unsigned char pc_2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 
    15,  6, 21, 10, 23, 19, 12,  4,
    26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
  };
  
  uint64_t pc2_mask = 0x800000000000, round_key = 0,
           CD_mask  = 0x80000000000000, CD = 0;
  uint8_t i;

  //# Concatenate Key segments into one unit
  CD = ((CD | C) << 28) | D;

  
  //# bit a[X] becomes bit Y
  for(i = 0;i < 48;i++){
    CD & (CD_mask >> pc_2[i]-1) ? round_key |= (pc2_mask >> i) : 0;
  }


  #ifdef LD_DEBUG
  printf("\n\t[PERMUTED CHOICE 2]\nC'D' = ");
  print_binary(CD, 56); printf("Round Key  =   ");
  print_binary(round_key, 48);
  #endif

  return round_key;
}

//##########+++ S-box calculation +++########## 
uint32_t s_boxes(uint64_t input)
{
  uint64_t mask = 0x3F;
  uint32_t result = 0;
  uint8_t i, j = 42, k = 28;

  for( i = 0; i < 8; (i++),(j -= 6),(k -= 4) ){
    //# Raw 6 bit value to interpolate
    uint8_t sextet = (input >> j) & mask;
    uint8_t row = 0, col = 0;

    //# Interpolate row and column values (0bRCCCCR)
    sextet & 0x20 ? row |= 0b10 : 0; // row msb
    sextet & 0x01 ? row |= 0b01 : 0; // row lsb
    
    col = (sextet >> 1) & 0x0F; // col bits

    //# Append the S box result to the 32 bit return value
    //# Most Significant Nibble First by shifting left
    result |= ((uint32_t)0 | Si[i][row][col]) << k;
  }

  #ifdef LD_DEBUG
  printf("\n\t[S-BOX Interpolation]\n");
  print_binary(result, 32);
  #endif

  return result;
}

//##########+++ Permutation Function +++########## 
uint32_t permutation(uint32_t block)
{
  static const char perm[32] = {
    16,  7, 20, 21, 29, 12, 28, 17, 
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
  };

  uint32_t mask = 0x80000000, result = 0;
  uint8_t i;

  //# bit a[X] becomes bit Y
  for(i = 0;i < 32;i++){
    block & (mask >> perm[i]-1) ? result |= (mask >> i) : 0;
  }  

  #ifdef LD_DEBUG
  puts("\n\t[PERMUTATION]");
  print_binary(result, 32);
  #endif

  return result;
}
