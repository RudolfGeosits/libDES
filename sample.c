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
#include "libDES.h"

char message[] = "Hello block cipher world!\n";
char cipher_msg[50], plain_msg[50];

uint64_t plain_block = 0x0123456789ABCDEF,
  cipher_block = 0, deciphered_block = 0,
  keys[] = { 0x3b3898371520f75e,
             0x09872384734743e2,
             0xef4432847347445e,
             0x87089237549fff83,
             0x9398478293489233, };

int main (int argc, char **argv)
{
  memset(plain_msg,  0, sizeof plain_msg); /* Clear Message Buffers */
  memset(cipher_msg, 0, sizeof cipher_msg);

  //###+++ String N-DES Encryption Example +++###
  //# mode can be: LD_DES, LD_3DES, or LD_NDES

  ld_encryptm(message, cipher_msg, LD_NDES, 5, keys);
  printf("\nMessage Encrypt %s \t%s\n", message, cipher_msg);

  //          ciphertxt   plaintxt    mode    N  list of keys
  ld_decryptm(cipher_msg, plain_msg, LD_NDES, 5, keys);
  printf("\nMessage Decrypt %s\n \t%s\n", cipher_msg, plain_msg);




  //###+++ Simple DES Encryption Example +++###
  /*
  cipher_block = ld_encrypt(plain_block, keys[0]);

  printf("\nDES Encryption Result: %llX\n", 
     (unsigned long long)cipher_block);
  ld_print_binary( cipher_block, 64 );  

  deciphered_block = ld_decrypt(cipher_block, keys[0]);

  printf("\nDES Encryption Result: %llX\n", 
     (unsigned long long)deciphered_block);
  ld_print_binary( deciphered_block, 64 );  
  */



  //###+++ 3DES Encryption Example +++###
  /*
  cipher_block = ld_encrypt3(plain_block, keys);

  printf("\n3DES Encryption Result: %llX\n", 
     (unsigned long long)cipher_block);
  ld_print_binary( cipher_block, 64 );  

  deciphered_block = ld_decrypt3(cipher_block, keys);

  printf("\nDES Encryption Result: %llX\n", 
     (unsigned long long)deciphered_block);
  ld_print_binary( deciphered_block, 64 );  
  */


  //###+++ N-DES Encryption Example +++###
  /*
  cipher_block = ld_encryptn( plain_block, 5, keys );
  
  printf("\nN-DES Encryption Result: %llX\n", 
     (unsigned long long)cipher_block);
  ld_print_binary( cipher_block, 64 );

  //                       N-DES     block  odd n  list of keys
  deciphered_block = ld_decryptn( cipher_block, 5, keys );
  
  printf("\nN-DES Decryption Result: %llX\n", 
     (unsigned long long)deciphered_block);
  ld_print_binary( deciphered_block, 64 );
  */

  return 0;
}
