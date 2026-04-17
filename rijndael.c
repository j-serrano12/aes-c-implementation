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
  // based on the provided block_size_to_bytes, we can figure out how many columns are in our block (4, 8, or 16), and we will use that to determine how much to shift each row by. the buffer is used to store the values of the row before we shift them, so that we can shift them correctly without overwriting values that we still need to shift.
  size_t columns = block_size_to_bytes(block_size) / 4;
  unsigned char row_buffer[16];

  // here we will loop through each row of our block, and shift it to the left by the appropriate amount. 
  // Row 0 is unchanged. Rows 1 is rotated left by 1, row 2 is rotated left by 2, and row 3 is rotated left by 3.
  for (size_t row = 1; row < 4; row++) {
    size_t shift = row % columns;
    // We will first copy the values of the row into our buffer, and then we will copy them back into the block in the shifted positions.
    for (size_t col = 0; col < columns; col++) {
      row_buffer[col] = block[row + (4 * col)];
    }

    for (size_t col = 0; col < columns; col++) {
      block[row + (4 * col)] = row_buffer[(col + shift) % columns];
    }
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
  // based on the provided block_size_to_bytes, we can figure out how many columns are in our block (4, 8, or 16), and we will use that to determine how much to shift each row by.
  size_t columns = block_size_to_bytes(block_size) / 4;
  unsigned char row_buffer[16];

  // just as in shift_rows, we will loop through each row of our block, and shift it to the right by the appropriate amount.
  for (size_t row = 1; row < 4; row++) {
    size_t shift = row % columns;

    for (size_t col = 0; col < columns; col++) {
      row_buffer[col] = block[row + (4 * col)];
    }

    for (size_t col = 0; col < columns; col++) {
      block[row + (4 * col)] = row_buffer[(col + columns - shift) % columns];
    }
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
// I am basing this on the following youtube video, which explains the key expansion algorithm in detail: https://www.youtube.com/watch?v=0RxLUf4fxs8
unsigned char *expand_key(unsigned char *cipher_key, aes_block_size_t block_size) {
  //here we will first determine the number of bytes in our key, the number of words in our key, the number of words in our block, and the number of rounds we need to perform based on the key size and block size.
  const size_t key_bytes = block_size_to_bytes(block_size);
  const size_t nk = key_bytes / 4;  // key words
  const size_t nb = key_bytes / 4;  // block words
  const size_t nr = ((nk > nb) ? nk : nb) + 6;
  const size_t expanded_len = (nr + 1) * key_bytes;
// We will allocate memory for our expanded key, which will be (nr + 1) * key_bytes bytes long, since we need to generate nr round keys plus the original key.
  unsigned char *expanded_key = (unsigned char *)malloc(expanded_len);
  if (expanded_key == NULL) {
    return NULL;
  }
  // We will first copy our original key into the first key_bytes bytes of our expanded key, since the first round key is just the original key.
  memcpy(expanded_key, cipher_key, key_bytes);

  // here we will generate the rest of our expanded key, by looping until we have generated enough bytes for all our round keys. We will generate 4 bytes at a time, since each word is 4 bytes long.
  size_t bytes_generated = key_bytes;
  // rcon is the round constant, which is used in the key expansion algorithm. It starts at 0x01, and is multiplied by 2 in the Galois field for each round. We will use the xtime macro defined above to multiply it by 2.
  unsigned char rcon = 0x01;
  unsigned char temp[4];
  // We will generate 4 bytes at a time.
  while (bytes_generated < expanded_len) {
    // We will take the last 4 bytes of the expanded key, and store it in a temporary array.
    temp[0] = expanded_key[bytes_generated - 4];
    temp[1] = expanded_key[bytes_generated - 3];
    temp[2] = expanded_key[bytes_generated - 2];
    temp[3] = expanded_key[bytes_generated - 1];

    size_t word_index = bytes_generated / 4;
    // here we will perform the key expansion algorithm on our temporary array, which will be used to generate the next 4 bytes of our expanded key. The key expansion algorithm has two main steps: the RotWord step, which rotates the bytes in the word to the left, and the SubWord step, which applies the s-box to each byte in the word. 
    if ((word_index % nk) == 0) {
      unsigned char rotated = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = rotated;

      temp[0] = sbox[temp[0]];
      temp[1] = sbox[temp[1]];
      temp[2] = sbox[temp[2]];
      temp[3] = sbox[temp[3]];

      temp[0] ^= rcon;
      rcon = xtime(rcon);
    } else if (nk > 6 && ((word_index % nk) == 4)) {
      // here we will perform the SubWord step on our temporary array, which is just applying the s-box to each byte in the word. This step is only performed if our key has more than 6 words (256-bit key)
      temp[0] = sbox[temp[0]];
      temp[1] = sbox[temp[1]];
      temp[2] = sbox[temp[2]];
      temp[3] = sbox[temp[3]];
    }

    // finally, we will XOR the temporary array with the word that is nk words before the current word, and store the result in our expanded key. This will generate the next 4 bytes of our expanded key.
    expanded_key[bytes_generated] = expanded_key[bytes_generated - key_bytes] ^ temp[0];
    bytes_generated++;
    expanded_key[bytes_generated] = expanded_key[bytes_generated - key_bytes] ^ temp[1];
    bytes_generated++;
    expanded_key[bytes_generated] = expanded_key[bytes_generated - key_bytes] ^ temp[2];
    bytes_generated++;
    expanded_key[bytes_generated] = expanded_key[bytes_generated - key_bytes] ^ temp[3];
    bytes_generated++;
  }
  // now we have generated all the round keys, and we can return our expanded key.
  return expanded_key;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  // first we will determine the number of bytes in our block, the number of words in our key, the number of words in our block, and the number of rounds we need to perform based on the key size and block size.
  const size_t total_bytes = block_size_to_bytes(block_size);
  const size_t nk = total_bytes / 4;
  const size_t nb = total_bytes / 4;
  const size_t nr = ((nk > nb) ? nk : nb) + 6;

  // now we will allocate memory for our output, which will be the same size as our block. We will return this output at the end of the function, after we have encrypted our plaintext.
  unsigned char *output = (unsigned char *)malloc(total_bytes);
  if (output == NULL) {
    return NULL;
  }
  // now we will expand our key, which will give us all the round keys that we need to perform our encryption. We will use the expand_key function that we defined above to do this. The expanded key will be (nr + 1) * total_bytes bytes long, since we need to generate nr round keys plus the original key.
  unsigned char *expanded_key = expand_key(key, block_size);
  if (expanded_key == NULL) {
    free(output);
    return NULL;
  }
  // here we will perform the initial round of our encryption, which is just adding the round key to our plaintext. We will use the add_round_key function that we defined above to do this. The first round key is just the original key, which is the first total_bytes bytes of our expanded key.
  memcpy(output, plaintext, total_bytes);
  add_round_key(output, expanded_key, block_size);
  // now we will perform the main rounds of our encryption, which consist of the sub_bytes, shift_rows, mix_columns, and add_round_key steps. We will loop through each round, and perform these steps in order. The round keys for these rounds are stored in our expanded key, starting from the second total_bytes bytes (since the first total_bytes bytes is the original key).
  for (size_t round = 1; round < nr; round++) {
    sub_bytes(output, block_size);
    shift_rows(output, block_size);
    mix_columns(output, block_size);
    add_round_key(output, expanded_key + (round * total_bytes), block_size);
  }
  // finally, we will perform the last round of our encryption, which is just the sub_bytes, shift_rows, and add_round_key steps (no mix_columns in the last round). The round key for this round is stored in the last total_bytes bytes of our expanded key.
  sub_bytes(output, block_size);
  shift_rows(output, block_size);
  add_round_key(output, expanded_key + (nr * total_bytes), block_size);
  // we then free the memory that we allocated for our expanded key, since we no longer need it, and we return our output, which is the encrypted block.
  free(expanded_key);
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
