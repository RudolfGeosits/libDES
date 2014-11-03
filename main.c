//#define DEBUG
#include "libDES.h"

int main(int argc, char** argv)
{
  uint64_t plain_block = 0x0123456789ABCDEF,
    key1 = 0x3b3898371520f75e,
    key2 = 0x09872384734743e2,    
    key3 = 0xef4432847347445e,
    key4 = 0x87089237549fff83,
    cipher_block = 0, deciphered_block = 0;

  cipher_block = ld_encryptn( plain_block, 3, key1, key2, key3, key4 );
  printf("\nEncryption Result 1: %llX\n", (unsigned long long)cipher_block);
  print_binary( cipher_block, 64 );

  deciphered_block = ld_decryptn( cipher_block, 3, key1, key2, key3, key4 );
  printf("\nDecryption Result 1: %llX\n", (unsigned long long)deciphered_block);
  print_binary( deciphered_block, 64 );

  return 0;
}
