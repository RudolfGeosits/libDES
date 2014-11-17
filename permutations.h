void initial_permutation(uint64_t *block);

uint64_t expansion_permutation(uint32_t block);

void final_permutation(uint64_t *block);

void left_shift_key_segment(uint32_t *key_seg, uint8_t round);
void right_shift_key_segment(uint32_t *key_seg, uint8_t round);

uint64_t permuted_choice_1(uint64_t key);
uint64_t permuted_choice_2(uint32_t C, uint32_t D);

uint32_t s_boxes(uint64_t input);

uint32_t permutation(uint32_t block);

#include "permutations.c"
