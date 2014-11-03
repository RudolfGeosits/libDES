/*
libDES - 3+ DES Encryption and Decryption Library
Copyright (C) 2014  Rudolf Geosits

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

//#define DEBUG
#include "libDES.h"

char message[] = "Hello World.\n";
char *cipher_message = NULL;

uint64_t plain_block = 0x0123456789ABCDEF,
  cipher_block = 0, deciphered_block = 0,
  keys[] = { 0x3b3898371520f75e,
	     0x09872384734743e2,    
	     0xef4432847347445e,
	     0x87089237549fff83, };

int main(int argc, char **argv)
{
  //###+++ String N-DES Encryption  +++###
  //printf("\nMessage Encryption Result: %s\n", cipher_message);

  //###+++ DES Encryption +++###

  //###+++ 3DES Encryption +++###

  //###+++ N-DES Encryption +++###
                //#   N-DES     block      n  keys
  cipher_block = ld_encryptn( plain_block, 3, keys );
  
  printf("\nN-DES Encryption Result: %llX\n", 
	 (unsigned long long)cipher_block);
  ld_print_binary( cipher_block, 64 );

  deciphered_block = ld_decryptn( cipher_block, 3, keys );
  
  printf("\nN-DES Decryption Result: %llX\n", 
	 (unsigned long long)deciphered_block);
  ld_print_binary( deciphered_block, 64 );

  return 0;
}
