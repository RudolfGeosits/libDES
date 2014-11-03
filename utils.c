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

#include "utils.h"

//##########+++ Print Binary Representation +++##########
void ld_print_binary(uint64_t num, uint32_t print_size)
{
  uint64_t mask = 0x8000000000000000 >> (64-print_size);

  uint8_t i;
  for(i = print_size;i > 0;i--){
    (num & mask) ? printf("1") : printf("0");
    mask >>= 1;
  }

  puts("");
}
