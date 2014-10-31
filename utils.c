#include "utils.h"

//##########+++ Print Binary Representation +++##########
void print_binary(uint64_t num, uint32_t print_size)
{
  uint64_t mask = 0x8000000000000000 >> (64-print_size);

  uint8_t i;
  for(i = print_size;i > 0;i--){
    (num & mask) ? printf("1") : printf("0");
    mask >>= 1;
  }

  puts("");
}
