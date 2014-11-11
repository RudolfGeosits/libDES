void initial_permutation(uint64_t *block);
/*
# Initial Permutation is done before any rounds are
# calculated using the IP box.
*/

uint64_t expansion_permutation(uint32_t block);
/*
# Expansion Permutation Expands (for each round of encryption)
# the initial Ri as the start of the F function
*/

void final_permutation(uint64_t *block);
/*
# Final permutation is the inverse of initial permutation
# applied after all rounds have been calculated
*/

void left_shift_key_segment(uint32_t *key_seg, unsigned char round);
/*
# cyclical left rotate on 28 bit key segment for key generation
*/

uint64_t permuted_choice_1(uint64_t key);
/*
# Permutated choice one is applied to the key before any 
# subkeys are calculated for DES rounds
*/

uint64_t permuted_choice_2(uint32_t C, uint32_t D);
/*
# Permutated choice two is applied to the key before XOR 
# with left side durring function F
*/

uint32_t s_boxes(uint64_t input);
/*
# s boxes will calculate the result used in permutation
# then returned by Feistel function
*/

uint32_t permutation(uint32_t block);
/*
# The permutation (P) function is applied after the S box
# Interpolation and returns from the F function
*/

#include "permutations.c"
