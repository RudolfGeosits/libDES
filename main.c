#include "libDES.h"

int main(int argc, char** argv)
{
  uint64_t plain_block = 0x0123456789ABCDEF,
    key = 0x3b3898371520f75e,
    cipher_block = 0, deciphered_block = 0;

  cipher_block = des_encrypt( plain_block, key );
  printf("\nEncryptionResult:%llX\n", (unsigned long long)cipher_block);
  print_binary( cipher_block, 64 );

  deciphered_block = des_decrypt( cipher_block, key );
  printf("\nDecryptionResult:%llX\n", (unsigned long long)deciphered_block);
  print_binary( deciphered_block, 64 );

  //uint32_tblock=plain_block;
  //print_binary(block,32);
  //right_shift_key_segment(&block,1);
  //print_binary(block,32);

  return 0;
}
