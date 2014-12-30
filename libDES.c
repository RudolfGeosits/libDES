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

/* interface enums */
typedef enum { LD_DES, LD_3DES, LD_NDES } ld_type;

/* local enums */
typedef enum { _LIBDES_ENCRYPT, _LIBDES_DECRYPT } _ld_method;

/* Initialization Vector for CBC mode when turned on */
uint8_t  _LD_CBC_MODE = 0;
uint64_t _ld_IV;

/* DES Encryption/Decryption Algorithm
**
** returns 64 bit block according to mode specified
*/
uint64_t _ld_des(uint64_t block, uint64_t key, uint8_t mode)
{
  static const uint8_t ROUNDS = 16;
  uint32_t round = 0;
  uint8_t i;

  initial_permutation(&block);  /* Initial Permutation on plaintext */
  key = permuted_choice_1(key); /* Initial Permutation on key */

  uint32_t left = block >> 32, right = block & 0x00000000FFFFFFFF;
  uint32_t C = key >> 28, D = key & 0x000000000FFFFFFF;
  uint32_t new_left = 0, new_right = 0;
  uint64_t round_key = 0, result = 0;

  for ( round = 0; round < ROUNDS; round++ ) {
    #ifdef LD_DEBUG
    printf( "*** Round %d   Prepare Round Key ***\nC  = ", round + 1 );
    ld_print_binary( C, 28 );
    printf( " D  = " );
    ld_print_binary( D, 28 );
    #endif
    
    if ( mode == _LIBDES_ENCRYPT ) {
      left_shift_key_segment( &C, round );
      left_shift_key_segment( &D, round );
    }

    #ifdef LD_DEBUG
    puts( "\n\t[LEFT SHIFT(S)]" );
    printf( "C' = " ); ld_print_binary( C, 28 );
    printf( "D' = " ); ld_print_binary( D, 28 );
    #endif

    round_key = permuted_choice_2( C, D );
    
    new_right =            /* Ri+1 = Li XOR F(Ri) */
      left ^ _ld_feistel( right, round_key );
    
    new_left = right;      /* Li+1 = Ri */

    if ( round != 16 ) {   /* Finalize for next round */
      left = new_left;
      right = new_right;
    
      if ( mode == _LIBDES_DECRYPT ) {   /* rotate right for decrypt */
        right_shift_key_segment( &C, round );
        right_shift_key_segment( &D, round );   
      }
    }

    #ifdef LD_DEBUG
    puts( "\n\t[Li XOR F(Ri)]" );
    ld_print_binary( new_right, 32 );
    printf( "\n [NEW LEFT = ]  " );
    ld_print_binary( new_left, 32 );
    printf( " [NEW RIGHT = ] " );
    ld_print_binary( new_right, 32 );
    puts( "\n" );
    #endif
  }

  //# final permutation on R16|L16 (swap and FP)
  result = ((((uint64_t)0) | right) << 32) | left;
  
  final_permutation( &result );
  return result;
}


/* Feistel structure round
**
** returns a 32 bit block which is the encrypted side of the current 
** block
*/
uint32_t _ld_feistel(uint32_t right, uint64_t round_key)
{
  uint64_t expanded_right = 0;
  uint64_t e_xor_k = 0;
  uint8_t i;

  //# Expand Ri
  expanded_right = expansion_permutation( right );
    
  //# E(Ri) XOR key_round(i)
  e_xor_k = expanded_right ^ round_key; //# 48 bits
  
  #ifdef LD_DEBUG
  puts( "\n\t[E(Ri) XOR Ki]" );
  ld_print_binary( round_key, 48 );
  ld_print_binary( expanded_right, 48 );
  for ( i = 0; i < 48; i++ ) { printf("-"); }; puts("");
  ld_print_binary( e_xor_k, 48 );
  #endif  

  //# Apply S-Boxes, then calculate Permutation Function
  return permutation( s_boxes(e_xor_k) );
}


/* DES Encrypt (one block, one key)
**
** returns a 64 bit block encrypted by DES
*/
uint64_t ld_encrypt(uint64_t block, uint64_t key)
{
  return _ld_des( block, key, _LIBDES_ENCRYPT );
}


/* DES Decrypt (one block, one key)
**
** returns a 64 bit block decrypted by DES
*/
uint64_t ld_decrypt(uint64_t block, uint64_t key)
{
  return _ld_des( block, key, _LIBDES_DECRYPT );
}


/* 3DES Encrypt (one block, three keys)
**
** returns a 64 bit block encrypted by 3DES
*/
uint64_t ld_encrypt3(uint64_t block, uint64_t *keys)
{
  return _ld_des(
      _ld_des(
           _ld_des( block, 
                    keys[0], _LIBDES_ENCRYPT ), 
           keys[1], _LIBDES_DECRYPT ), 
      keys[2], _LIBDES_ENCRYPT );
}


/* DES Decrypt (one block, three keys)
**
** returns a 64 bit block decrypted by 3DES
*/
uint64_t ld_decrypt3(uint64_t block, uint64_t *keys)
{
  return _ld_des(
      _ld_des(
           _ld_des( block, 
                    keys[2], _LIBDES_DECRYPT ), 
           keys[1], _LIBDES_ENCRYPT ), 
      keys[0], _LIBDES_DECRYPT );
}


/* N-DES Encrypt (one block, n keys)
**
** returns a 64 bit block encrypted by NDES
*/
uint64_t ld_encryptn(uint64_t block, uint32_t n, uint64_t *keys)
{
  _ld_method cur_mode = _LIBDES_ENCRYPT; 
  uint8_t i;

  if ( (n % 2) == 0 ) {
    fprintf(stderr, "ld_encryptn: n must be odd, exiting now.\n\n");
    exit( 1 );
  }

  for ( i = 0; i < n; i++ ) {
    block = _ld_des( block, keys[i], cur_mode );
    cur_mode = !cur_mode;   /* Toggle encryption/decryption */
  }

  return block;
}


/* N-DES Decrypt (one block, n keys)
**
** returns a 64 bit block decrypted by NDES
*/
uint64_t ld_decryptn(uint64_t block, uint32_t n, uint64_t *keys)
{
  _ld_method cur_mode = _LIBDES_DECRYPT;
  uint8_t i;

  if ( (n % 2) == 0 ) {
    fprintf(stderr, "ld_encryptn: n must be odd, exiting now.\n\n");
    exit( 1 );
  }  

  for ( i = n; i > 0; i-- ) {
    block = _ld_des(block, keys[i-1], cur_mode);
    cur_mode = !cur_mode;   /* Toggle decryption/encryption */
  }

  return block;
}


/* N-DES Encrypt Message with any mode
**
** ld_encryptm(*PLAINTEXT, *CIPHERTEXT, MODE, ...)
**    PLAINTEXT gets encrypted block by block by the MODE 
**    parameter (LD_DES, LD_3DES, or LD_NDES)
**    CIPHERTEXT will point to the encrypted message
** Exs.
**   ld_encryptm(msg, cmsg, DES, key)
**   ld_encryptm(msg, cmsg, 3DES, keys) where keys is uint64_t arr[3] 
**   ld_encryptm(msg, cmsg, NDES, 9, keys) whr keys is uint64_t arr[9]
*/
void ld_encryptm(char *message, char *cipher_text, uint8_t mode, ...)
{
  uint32_t str_size;
  uint32_t num_blocks;
  va_list  args;
  uint8_t  i;

  str_size = strlen( message );        /* Rely on terminating \0 */
  num_blocks = ( (str_size/8) + 1 );   /* +1 for pssible partial blk */
  uint64_t blocks[ num_blocks ];       /* Allocate needed blocks */

  _ld_str_to_blocks( message, str_size, blocks );


  for ( i = 0; i < num_blocks; i++ ) { /* Encrypt each block */
    
    if ( mode == LD_DES ) {
      va_start( args, mode );          /* Expect one key arg */
      blocks[i] = 
        _ld_des( blocks[i], va_arg(args, uint64_t), _LIBDES_ENCRYPT );
    }
    else if ( mode == LD_3DES ) {
      mode = 1;                        /* Expect a key array */
      va_start( args, mode );
      
      uint64_t *keys = va_arg( args, uint64_t* );
      blocks[i] = ld_encrypt3( blocks[i], keys );
    }
    else if ( mode == LD_NDES ) {
      va_start( args, mode );          /* Expect num and key array */
      
      uint64_t iv = _ld_IV;
      uint8_t n = va_arg( args, int );
      uint64_t *keys = va_arg( args, uint64_t* );

      if ( _LD_CBC_MODE ) {
        iv = blocks[i] = ld_encryptn(blocks[i] ^ iv, n, keys);
      }
      else {
        blocks[i] = ld_encryptn( blocks[i], n, keys );
      }
    
    }
  }

 
  _ld_blocks_to_str( blocks, cipher_text, num_blocks );
  va_end( args );
}



/* N-DES Decrypt Message with any mode
**
** ld_decryptm(*CIPHERTEXT, *PLAINTEXT, MODE, ...)
**    CIPHERTEXT gets decrypted block by block by the MODE 
**    parameter (LD_DES, LD_3DES, or LD_NDES)
**    PLAINTEXT will point to the decrypted message
** Exs.
**   ld_decryptm(cmsg, msg, DES, key)
**   ld_decryptm(cmsg, msg, 3DES, keys) where keys is uint64_t arr[3] 
**   ld_decryptm(cmsg, msg, NDES, 9, keys) whr keys is uint64_t arr[9]
*/
void ld_decryptm(char *message, char *plain_text, uint8_t mode, ...)
{  
  uint32_t str_size;
  uint32_t num_blocks;
  va_list args;
  uint8_t i;

  for ( i = 0; i < 50; i++ ) {
    if ( message[i] == 0 && message[i+1] == 0 ) {
      str_size = i;
      break;
    }
  }
    
  num_blocks = ( (str_size/8) + 1);   /* +1 fr possble partial block */
  uint64_t blocks[ num_blocks ];      /* Allocated needed blocks */

  _ld_str_to_blocks( message, str_size, blocks );


  for ( i = 0; i < num_blocks; i++ ) {/* Decrypt each block */
    if ( mode == LD_DES ) {
      va_start( args, mode );         /* Expect one key arg */

      blocks[i] = 
        _ld_des( blocks[i], va_arg(args, uint64_t), _LIBDES_DECRYPT );
    }
    else if ( mode == LD_3DES ) {
      mode = 1;                       /* Expect one key array */
      va_start( args, mode );    
      
      uint64_t *keys = va_arg( args, uint64_t* );
      blocks[i] = ld_decrypt3( blocks[i], keys );
    }
    else if ( mode == LD_NDES ) {
      va_start( args, mode );         /* Expect num and key array */

      uint64_t iv = _ld_IV, new_iv = blocks[i];
      uint8_t n = va_arg( args, int );
      uint64_t *keys = va_arg( args, uint64_t* );

      if (_LD_CBC_MODE) {
        blocks[i] = iv ^ ld_decryptn( blocks[i], n, keys );
        iv = new_iv;
      }
      else {
        blocks[i] = ld_decryptn( blocks[i], n, keys );
      }
    }
  }


  _ld_blocks_to_str( blocks, plain_text, num_blocks );
  va_end( args );
}

/* Send Initialization Vector to remote machine
**
** Sets the IV for CBC mode created by this machine
**  Send and Recv IV to turn CBC mode on
*/
void ld_send_iv(int32_t fd)
{
  _ld_IV = 0;

  srand( time(NULL) );
  uint64_t iv = 0 | ( ((iv | rand()) << 32) | rand() );

  send( fd, &iv, sizeof iv, 0 );

  _ld_IV = iv;
  _LD_CBC_MODE = 1;
}

/* Recieve Initialization Vector to remote machine
**
** Sets the IV for CBC mode created by remote
**  Send and Recv IV to turn CBC mode on
*/
void ld_recv_iv(int32_t fd)
{
  _ld_IV = 0;

  recv( fd, &_ld_IV, sizeof _ld_IV, 0 );

  _LD_CBC_MODE = 1;
}
