/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// TODO: Any other files you need to include should go here

#include "rijndael.h"

// Adding the Rijndael substitution box and inverse substitution box here for easy access
// This was created by Rijndael to be resistant to linear and differential cryptanalysis.
// Cited here https://en.wikipedia.org/wiki/Rijndael_S-box#Rijndael_S-box

static const unsigned char sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


//  Create the inverse sbox by inverting the sbox

static const unsigned char inv_sbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

size_t block_size_to_bytes(aes_block_size_t block_size) {
  switch (block_size) {
  case AES_BLOCK_128:
    return 16;
  case AES_BLOCK_256:
    return 32;
  case AES_BLOCK_512:
    return 64;
  default:
    fprintf(stderr, "Invalid block size %d\n", block_size);
    exit(1);
  }
}

unsigned char block_access(unsigned char *block, size_t row, size_t col, aes_block_size_t block_size) {
  int row_len;
  switch (block_size) {
    case AES_BLOCK_128:
      row_len = 4;
      break;
    case AES_BLOCK_256:
      row_len = 8;
      break;
    case AES_BLOCK_512:
      row_len = 16;
      break;
    default:
      fprintf(stderr, "Invalid block size for block_access: %d\n", block_size);
      exit(1);
  }

  return block[(row * row_len) + col];
}

char *message(char n) {
  char *output = (char *)malloc(7);
  strcpy(output, "hello");
  output[5] = n;
  output[6] = 0;
  return output;
}

/*
 * Operations used when encrypting a block
 */

 // In the subbytes step we take all the bytes in our block and replace it with the corresponding byte in the s-box
void sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  // Using the provided block_size_to_bytes, to figure out how many bytes are in our block (16, 32, or 64)
  size_t total_bytes = block_size_to_bytes(block_size);

  // We will loop through all the bytes in our block, and replace it with the corresponding byte in the s-box
  for(size_t i = 0; i < total_bytes; i++){
    block[i] = sbox[block[i]];
  }
}


//  We aew going to immplement the shift rows function by shifting the rows of our block to the left by a certain amount. The first row is not shifted, the second row is shifted by 1, the third row is shifted by 2, and the fourth row is shifted by 3. This is done to create diffusion in our block, which makes it more resistant to cryptanalysis.

void shift_rows(unsigned char *block, aes_block_size_t block_size) {
  // Focusing on the 128 bit first

  if(block_size == AES_BLOCK_128){
    unsigned char temp, temp2;

    // First row is not shifted.
    // Second row is shifted by 1 to the left across columns.
    temp = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = temp;

    // Third row is shifted by 2 to the left.
    temp = block[2];
    temp2 = block[6];
    block[2] = block[10];
    block[6] = block[14];
    block[10] = temp;
    block[14] = temp2;

    // Fourth row is shifted by 3 to the left (same as 1 right).
    temp = block[3];
    block[3] = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = temp;
  }
}

// This is the mix columns step, which is a linear transformation that mixes the columns of the block //together.The mix columns step is a matrix multiplication of the block with a fixed matrix, which can be implemented using bitwise operations and XORs.

// Multiplies by 2 in Galois Field (shifts left, XORs with 0x1B if the highest bit is set)
#define xtime(x) ((x & 0x80) ? ((x << 1) ^ 0x1B) : (x << 1))


void mix_columns(unsigned char *block, aes_block_size_t block_size) {
  // Using the provided block_size_to_bytes, to figure out how many bytes are in our block (16, 32, or 64)
  size_t total_bytes = block_size_to_bytes(block_size);
  // We will loop through each column of our block, and perform the matrix multiplication for that column
  for (size_t i = 0; i < total_bytes; i += 4) {
    // now we will take the 4 bytes in our column
    unsigned char a0 = block[i + 0];
    unsigned char a1 = block[i + 1];
    unsigned char a2 = block[i + 2];
    unsigned char a3 = block[i + 3];

    // We need to learn the Galois field multiplication to do the matrix multiplication. In AES, we are working in GF(2^8), which means that we can represent our bytes as polynomials, and we can perform multiplication by using bitwise operations and XORs. To multiply by 2, we can use the xtime macro defined above.
    // To multiply by 1, we just take the original value: x
    // To multiply by 3, we multiply by 2 and XOR the original value: (xtime(x) ^ x)
    // Reference for the matrix multiplication: https://en.wikipedia.org/wiki/Rijndael_MixColumns#MixColumns_step
    
    // New_a0 = (2 * a0) + (3 * a1) + a2 + a3
    block[i + 0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
    
    // New_a1 = a0 + (2 * a1) + (3 * a2) + a3
    block[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
    
    // New_a2 = a0 + a1 + (2 * a2) + (3 * a3)
    block[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
    
    // New_a3 = (3 * a0) + a1 + a2 + (2 * a3)
    block[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
  }
}

/*
 * Operations used when decrypting a block
 */

 // We will do the exact same as the sub_bytes step, but instead of using the s-box, we will use the inverse s-box
void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  // Using the provided block_size_to_bytes, to figure out how many bytes are in our block (16, 32, or 64)
  size_t total_bytes = block_size_to_bytes(block_size);

  // We will loop through all the bytes in our block, and replace it with the corresponding byte in the inverse s-box
  for(size_t i = 0; i < total_bytes; i++){
    block[i] = inv_sbox[block[i]];
  }
}

// This will be the opposite of the shift rows function, so we will shift the rows to the right instead of to the left
void invert_shift_rows(unsigned char *block, aes_block_size_t block_size) {
  // Focusing on the 128 bit first

  if(block_size == AES_BLOCK_128){
    unsigned char temp, temp2;

    // First row is not shifted.
    // Second row is shifted by 1 to the right across columns.
    temp = block[13];
    block[13] = block[9];
    block[9] = block[5];
    block[5] = block[1];
    block[1] = temp;

    // Third row is shifted by 2 to the right.
    temp = block[2];
    temp2 = block[6];
    block[2] = block[10];
    block[6] = block[14];
    block[10] = temp;
    block[14] = temp2;

    // Fourth row is shifted by 3 to the right (same as 1 left).
    temp = block[3];
    block[3] = block[7];
    block[7] = block[11];
    block[11] = block[15];
    block[15] = temp;
  }
}

void invert_mix_columns(unsigned char *block, aes_block_size_t block_size) {
  size_t total_bytes = block_size_to_bytes(block_size);

  for (size_t i = 0; i < total_bytes; i += 4) {
    // now we will take the 4 bytes in our column
    unsigned char a0 = block[i + 0];
    unsigned char a1 = block[i + 1];
    unsigned char a2 = block[i + 2];
    unsigned char a3 = block[i + 3];

    // Inverse MixColumns matrix uses multipliers 14, 11, 13 and 9 in GF(2^8).
    // We build these from xtime (taht multiplies by 2):
    // 9x = (8x) ^ x, 11x = (8x) ^ (2x) ^ x, 13x = (8x) ^ (4x) ^ x, 14x = (8x) ^ (4x) ^ (2x)
    unsigned char a0_2 = xtime(a0);
    unsigned char a1_2 = xtime(a1);
    unsigned char a2_2 = xtime(a2);
    unsigned char a3_2 = xtime(a3);

    unsigned char a0_4 = xtime(a0_2);
    unsigned char a1_4 = xtime(a1_2);
    unsigned char a2_4 = xtime(a2_2);
    unsigned char a3_4 = xtime(a3_2);

    unsigned char a0_8 = xtime(a0_4);
    unsigned char a1_8 = xtime(a1_4);
    unsigned char a2_8 = xtime(a2_4);
    unsigned char a3_8 = xtime(a3_4);

    unsigned char a0_9  = a0_8 ^ a0;
    unsigned char a1_9  = a1_8 ^ a1;
    unsigned char a2_9  = a2_8 ^ a2;
    unsigned char a3_9  = a3_8 ^ a3;

    unsigned char a0_11 = a0_8 ^ a0_2 ^ a0;
    unsigned char a1_11 = a1_8 ^ a1_2 ^ a1;
    unsigned char a2_11 = a2_8 ^ a2_2 ^ a2;
    unsigned char a3_11 = a3_8 ^ a3_2 ^ a3;

    unsigned char a0_13 = a0_8 ^ a0_4 ^ a0;
    unsigned char a1_13 = a1_8 ^ a1_4 ^ a1;
    unsigned char a2_13 = a2_8 ^ a2_4 ^ a2;
    unsigned char a3_13 = a3_8 ^ a3_4 ^ a3;

    unsigned char a0_14 = a0_8 ^ a0_4 ^ a0_2;
    unsigned char a1_14 = a1_8 ^ a1_4 ^ a1_2;
    unsigned char a2_14 = a2_8 ^ a2_4 ^ a2_2;
    unsigned char a3_14 = a3_8 ^ a3_4 ^ a3_2;

    // New_a0 = (14 * a0) + (11 * a1) + (13 * a2) + (9 * a3)
    block[i + 0] = a0_14 ^ a1_11 ^ a2_13 ^ a3_9;

    // New_a1 = (9 * a0) + (14 * a1) + (11 * a2) + (13 * a3)
    block[i + 1] = a0_9 ^ a1_14 ^ a2_11 ^ a3_13;

    // New_a2 = (13 * a0) + (9 * a1) + (14 * a2) + (11 * a3)
    block[i + 2] = a0_13 ^ a1_9 ^ a2_14 ^ a3_11;

    // New_a3 = (11 * a0) + (13 * a1) + (9 * a2) + (14 * a3)
    block[i + 3] = a0_11 ^ a1_13 ^ a2_9 ^ a3_14;
  }
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, 
                   unsigned char *round_key,
                   aes_block_size_t block_size) {
  size_t total_bytes = block_size_to_bytes(block_size);

  // In this step we will XOR each byte of our block with the corresponding byte of our round key.
  for (size_t i = 0; i < total_bytes; i++) {
    block[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key, aes_block_size_t block_size) {
  // TODO: Implement me!
  return 0;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * block_size_to_bytes(block_size));
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * block_size_to_bytes(block_size));
  return output;
}
