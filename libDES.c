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

//#define LD_DEBUG
#define _LIBDES_ENCRYPT 0
#define _LIBDES_DECRYPT 1
#define LD_DES 0
#define LD_3DES 1
#define LD_NDES 2

//##########+++ DES Encryption/Decryption +++##########
uint64_t _ld_des(uint64_t block, uint64_t key, uint8_t mode)
{
  static const uint8_t ROUNDS = 16;
  uint32_t round = 0, i;

  initial_permutation( &block );  //# Initial Permutation on plaintext
  key = permuted_choice_1( key ); //# Initial Permutation on key

  uint32_t left = block >> 32, right = block & 0x00000000FFFFFFFF,
           C = key >> 28, D = key & 0x000000000FFFFFFF,
           new_left = 0, new_right = 0;
  uint64_t round_key = 0, result = 0;

  for(round = 0;round < ROUNDS;round++){
    #ifdef LD_DEBUG
    printf("*** Round %d   Prepare Round Key ***\nC  = ", round + 1);
    print_binary(C, 28);
    printf("D  = ");
    print_binary(D, 28);
    #endif
    
    if( mode == _LIBDES_ENCRYPT ){
      left_shift_key_segment( &C, round );
      left_shift_key_segment( &D, round );
    }

    #ifdef LD_DEBUG
    puts("\n\t[LEFT SHIFT(S)]");
    printf("C' = "); print_binary(C, 28);
    printf("D' = "); print_binary(D, 28);
    #endif

    round_key = permuted_choice_2( C, D );
    
    //# Ri+1 = Li XOR F(Ri)
    new_right = left ^ _ld_feistel(right, round_key);
    
    //# Li+1 = Ri
    new_left = right;

    //# Finalize for next round, unless 16
    if( round != 16 ){
      left = new_left;
      right = new_right;
    
      //# If DECRYPTION, rotate right instead
      if( mode == _LIBDES_DECRYPT ){
	right_shift_key_segment( &C, round );
	right_shift_key_segment( &D, round );	
      }
    }

    #ifdef LD_DEBUG
    puts("\n\t[Li XOR F(Ri)]");
    print_binary(new_right, 32);
    printf("\n [NEW LEFT = ]  ");
    print_binary(new_left, 32);
    printf(" [NEW RIGHT = ] ");
    print_binary(new_right, 32);
    puts("\n");
    #endif
  }

  //# final permutation on R16|L16 (swap and FP)
  result = ((((uint64_t)0) | right) << 32) | left;
  final_permutation( &result );
  return result;
}

//##########+++ Feistel Structure Round +++###########
uint32_t _ld_feistel(uint32_t right, uint64_t round_key)
{
  uint64_t expanded_right = 0, e_xor_k = 0;
  uint8_t i;

  //# Expand Ri
  expanded_right = expansion_permutation(right);
    
  //# E(Ri) XOR key_round(i)
  e_xor_k = expanded_right ^ round_key; //# 48 bits
  
  #ifdef LD_DEBUG
  puts("\n\t[E(Ri) XOR Ki]");
  print_binary(round_key, 48);
  print_binary(expanded_right, 48);
  for(i = 0;i < 48;i++){printf("-");}; puts("");
  print_binary( e_xor_k, 48 );
  #endif  

  //# Apply S-Boxes, then calculate Permutation Function
  return permutation( s_boxes(e_xor_k) );
}

//##########+++ DES Encrypt +++###########
uint64_t ld_encrypt(uint64_t block, uint64_t key)
{
  return _ld_des(block, key, _LIBDES_ENCRYPT);
}

//##########+++ DES Decrypt +++###########
uint64_t ld_decrypt(uint64_t block, uint64_t key)
{
  return _ld_des(block, key, _LIBDES_DECRYPT);
}
//##########+++ 3DES Encrypt +++##########
uint64_t ld_encrypt3(uint64_t block, uint64_t *keys)
{
  return _ld_des(
	  _ld_des(
           _ld_des( block, keys[0], _LIBDES_ENCRYPT), 
                     keys[1], _LIBDES_DECRYPT), 
                      keys[2], _LIBDES_ENCRYPT);
}

//##########+++ 3DES Decrypt +++##########
uint64_t ld_decrypt3(uint64_t block, uint64_t *keys)
{
  return _ld_des(
	  _ld_des(
           _ld_des( block, keys[2], _LIBDES_DECRYPT), 
                     keys[1], _LIBDES_ENCRYPT), 
                      keys[0], _LIBDES_DECRYPT);
}

//##########+++ N-DES Encrypt +++##########
uint64_t ld_encryptn(uint64_t block, uint32_t n, uint64_t *keys)
{
  uint32_t i, cur_mode = _LIBDES_ENCRYPT;

  if( (n % 2) == 0 ){
    fprintf(stderr, "ld_encryptn: n must be odd, exiting now.\n\n");
    exit(1);
  }

  for(i = 0;i < n;i++){
    block = _ld_des(block, keys[i], cur_mode);
    cur_mode = !cur_mode;
  }

  return block;
}

//##########+++ N-DES Decrypt +++##########
uint64_t ld_decryptn(uint64_t block, uint32_t n, uint64_t *keys)
{
  uint32_t i, cur_mode = _LIBDES_DECRYPT;

  if( (n % 2) == 0 ){
    fprintf(stderr, "ld_encryptn: n must be odd, exiting now.\n\n");
    exit(1);
  }  

  for(i = n;i > 0;i--){
    block = _ld_des(block, keys[i-1], cur_mode);
    cur_mode = !cur_mode;
  }

  return block;
}

//##########+++ Message Encrypt +++##########
void ld_encryptm(char *message, char *cipher_text, uint8_t mode, ...)
{
  uint32_t str_size, num_blocks, i;
  va_list keyargs;
      
  str_size = strlen(message);
  num_blocks = ( (str_size/8) + 1); //# Extra one for last segment
  uint64_t blocks[ num_blocks ];
  memset(blocks, 0, sizeof(blocks));

  //# Convert chrstr into blocks
  _ld_str_to_blocks(message, blocks);

  //# For each block, process with the respective encryption mode
  for(i = 0;i < num_blocks;i++){
    if( mode == LD_DES ){
      //# Expect one argument, one key
      va_start(keyargs, mode);
      
      blocks[i] = _ld_des( blocks[i], va_arg(keyargs, uint64_t), _LIBDES_ENCRYPT );
    }
    else if( mode == LD_3DES ){
      //# Expect one argument, key array
      mode = 1;
      va_start(keyargs, mode);
      
      uint64_t *keys = va_arg(keyargs, uint64_t*);
      blocks[i] = ld_encrypt3( blocks[i], keys );
    }
    else if( mode == LD_NDES ){
      //# Expect two arguments, N and key array
      va_start(keyargs, mode);
      
      uint8_t n = va_arg( keyargs, int );
      uint64_t *keys = va_arg( keyargs, uint64_t* );

      blocks[i] = ld_encryptn( blocks[i], n, keys );
    }
  }

  //# Convert blocks into chrstr
  _ld_blocks_to_str(blocks, cipher_text, num_blocks);

  va_end(keyargs);
}

//##########+++ Message Decrypt +++##########
void ld_decryptm(char *message, char *plain_text, uint8_t mode, ...)
{  
  uint32_t str_size, num_blocks, i;
  va_list keyargs;
      
  str_size = strlen(message);
  num_blocks = ( (str_size/8) + 1); //# Extra one for last segment
  uint64_t blocks[ num_blocks ];
  memset(blocks, 0, sizeof(blocks));

  //# Convert chrstr into blocks
  _ld_str_to_blocks(message, blocks);

  //# For each block, process with the respective encryption mode
  for(i = 0;i < num_blocks;i++){
    if( mode == LD_DES ){
      //# Expect one argument, one key
      va_start(keyargs, mode);

      blocks[i] = _ld_des( blocks[i], va_arg(keyargs, uint64_t), _LIBDES_DECRYPT );
    }
    else if( mode == LD_3DES ){
      //# Expect one argument, key array
      mode = 1;
      va_start(keyargs, mode);
      
      uint64_t *keys = va_arg(keyargs, uint64_t*);
      blocks[i] = ld_decrypt3( blocks[i], keys );
    }
    else if( mode == LD_NDES ){
      //# Expect two arguments, N and key array
      va_start(keyargs, mode);

      uint8_t n = va_arg( keyargs, int );
      uint64_t *keys = va_arg( keyargs, uint64_t* );

      blocks[i] = ld_decryptn( blocks[i], n, keys );
    }
  }

  //# Convert blocks into chrstr
  _ld_blocks_to_str(blocks, plain_text, num_blocks);

  va_end(keyargs);
}
