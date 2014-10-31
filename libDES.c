//#define DEBUG

//##########+++ DES Decryption +++##########
uint64_t des_decrypt(uint64_t block, uint64_t key)
{
  static const unsigned char ROUNDS = 16;
  uint32_t round = 0, i;

  initial_permutation( &block );  //# Initial Permutation on plaintext
  key = permuted_choice_1( key ); //# Initial Permutation on key

  uint32_t left = block >> 32, right = block & 0x00000000FFFFFFFF,
           C = key >> 28, D = key & 0x000000000FFFFFFF,
           new_left = 0, new_right = 0;
  uint64_t round_key = 0, result = 0;

  for(round = 0;round < ROUNDS;round++){
    #ifdef DEBUG
    printf("*** Round %d   Prepare Round Key ***\nC  = ", round + 1);
    print_binary(C, 28);
    printf("D  = ");
    print_binary(D, 28);
    #endif
    
    left_shift_key_segment( &C, round );
    left_shift_key_segment( &D, round );
    
    #ifdef DEBUG
    puts("\n\t[LEFT SHIFT(S)]");
    printf("C' = "); print_binary(C, 28);
    printf("D' = "); print_binary(D, 28);
    #endif

    round_key = permuted_choice_2( C, D );
    
    //# Ri+1 = Li XOR F(Ri)
    new_right = left ^ feistel(right, round_key);
    
    //# Li+1 = Ri
    new_left = right;

    //# Finalize for next round, unless 16
    if( round != 16 ){
      left = new_left;
      right = new_right;
    }

    #ifdef DEBUG
    puts("\n\t[Li XOR F(Ri)]");
    print_binary(new_right, 32);
    printf("\n [NEW LEFT = ]  ");
    print_binary(new_left, 32);
    printf(" [NEW RIGHT = ] ");
    print_binary(new_right, 32);
    puts("\n");
    #endif
  }

  //# final permutation on R16|L16
  result = ((((uint64_t)0) | right) << 32) | left;
  final_permutation( &result );
  return result;
}

//##########+++ DES Encryption +++##########
uint64_t des_encrypt(uint64_t block, uint64_t key)
{
  static const unsigned char ROUNDS = 16;
  uint32_t round = 0, i;

  initial_permutation( &block );  //# Initial Permutation on plaintext
  key = permuted_choice_1( key ); //# Initial Permutation on key

  uint32_t left = block >> 32, right = block & 0x00000000FFFFFFFF,
           C = key >> 28, D = key & 0x000000000FFFFFFF,
           new_left = 0, new_right = 0;
  uint64_t round_key = 0, result = 0;

  for(round = 0;round < ROUNDS;round++){
    #ifdef DEBUG
    printf("*** Round %d   Prepare Round Key ***\nC  = ", round + 1);
    print_binary(C, 28);
    printf("D  = ");
    print_binary(D, 28);
    #endif
    
    left_shift_key_segment( &C, round );
    left_shift_key_segment( &D, round );
    
    #ifdef DEBUG
    puts("\n\t[LEFT SHIFT(S)]");
    printf("C' = "); print_binary(C, 28);
    printf("D' = "); print_binary(D, 28);
    #endif

    round_key = permuted_choice_2( C, D );
    
    //# Ri+1 = Li XOR F(Ri)
    new_right = left ^ feistel(right, round_key);
    
    //# Li+1 = Ri
    new_left = right;

    //# Finalize for next round, unless 16
    if( round != 16 ){
      left = new_left;
      right = new_right;
    }

    #ifdef DEBUG
    puts("\n\t[Li XOR F(Ri)]");
    print_binary(new_right, 32);
    printf("\n [NEW LEFT = ]  ");
    print_binary(new_left, 32);
    printf(" [NEW RIGHT = ] ");
    print_binary(new_right, 32);
    puts("\n");
    #endif
  }

  //# final permutation on R16|L16
  result = ((((uint64_t)0) | right) << 32) | left;
  final_permutation( &result );
  return result;
}

//##########+++ Feistel Structure Round +++###########
uint32_t feistel(uint32_t right, uint64_t round_key)
{
  uint64_t expanded_right = 0, e_xor_k = 0;
  uint8_t i;

  //# Expand Ri
  expanded_right = expansion_permutation(right);
    
  //# E(Ri) XOR key_round(i)
  e_xor_k = expanded_right ^ round_key; //# 48 bits
  
  #ifdef DEBUG
  puts("\n\t[E(Ri) XOR Ki]");
  print_binary(round_key, 48);
  print_binary(expanded_right, 48);
  for(i = 0;i < 48;i++){printf("-");}; puts("");
  print_binary( e_xor_k, 48 );
  #endif  

  //# Apply S-Boxes, then calculate Permutation Function
  return permutation( s_boxes(e_xor_k) );
}
