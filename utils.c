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

/* Turn 64 bit blocks into a cstr
**  Example:
** _ld_blocks_to_str(BLOCK_ARRAY, STR, NUM_OF_BLOCKS)
**  Places result into STR
*/ 
void _ld_blocks_to_str(uint64_t *blocks, char *message, uint8_t num_blocks)
{
  uint8_t i = 0, j = 0;

  for ( ; i < num_blocks; i++, j += 8 ) {
    memcpy(message + j, &blocks[i], sizeof(uint64_t));
  }
}


/* Turn a cstr into 64 bit blocks
**  Example:
** _ld_str_to_blocks(STR, BLOCK_ARRAY) 
**  Places result into BLOCK_ARRAY
*/
void _ld_str_to_blocks(char *message, uint64_t *blocks)
{
  uint8_t i = 0, j = 0;

  for ( ; j < strlen(message); i++, j += 8 ) {
    memcpy(&blocks[i], message + j, sizeof(uint64_t));
  }
}


/* Print a number out in binary form
**  Example:
** ld_print_binary(NUM, PRINT_SIZE)
**  Prints NUM represented as PRINT_SIZE bits 
*/
void ld_print_binary(uint64_t num, uint32_t print_size)
{
  const uint64_t mask = 0x8000000000000000 >> ( 64-print_size );
  uint8_t shf = 0;

  for ( ; print_size > 0; print_size--, shf++ ) {
    num & (mask >> shf) ? printf("1") : printf("0");
  }

  puts("");
}
