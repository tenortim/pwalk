// //////////////////////////////////////////////////////////
// sha3.h
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once


// define fixed size integer types
#ifdef _MSC_VER
// Windows
typedef unsigned __int8  uint8_t;
typedef unsigned __int64 uint64_t;
#else
// GCC
#include <stdint.h>
#endif
#include <stddef.h>

/// compute SHA3 hash
/** Usage:
    SHA3 *sha3 = SHA3_init(Bits256);
    char *myHash  = SHA3_str(sha3, "Hello World");     // C string
    char *myHash2 = SHA3_block(sha3, "How are you", 11); // arbitrary data, 11 bytes
    ...
    free(myHash);
    free(myHash2);
    SHA3_free(sha3);

    // or in a streaming fashion:

    SHA3 *sha3 = SHA3_init(Bits256);
    while (more data available)
      SHA3_add(sha3, pointer to fresh data, number of new bytes);
    char *myHash3 = SHA3_getHash_str(sha3);
    ...
    free(myHash3);
    SHA3_free(sha3);
  */

/// algorithm variants
enum SHA3_Bits { Bits224 = 224, Bits256 = 256, Bits384 = 384, Bits512 = 512 };
/// 1600 bits, stored as 25x64 bit, BlockSize is no more than 1152 bits (Keccak224)
enum { SHA3_StateSize    = 1600 / (8 * 8),
       SHA3_MaxBlockSize =  200 - 2 * (224 / 8) };

typedef struct {
  /// hash
  uint64_t m_hash[SHA3_StateSize];
  /// size of processed data in bytes
  uint64_t m_numBytes;
  /// block size (less or equal to MaxBlockSize)
  size_t   m_blockSize;
  /// valid bytes in m_buffer
  size_t   m_bufferSize;
  /// bytes not processed yet
  uint8_t  m_buffer[SHA3_MaxBlockSize];
  /// variant
  enum SHA3_Bits m_bits;
} SHA3;

SHA3 * SHA3_init(enum SHA3_Bits bits);
void SHA3_reset(SHA3 *self);
void SHA3_free(SHA3 *self);
/// compute SHA3 of a memory block
char *SHA3_block(SHA3 *self, const void* data, size_t numBytes);
/// compute SHA3 of a string, excluding final zero
char *SHA3_str(SHA3 *self, const char *text);
/// add arbitrary number of bytes
void SHA3_add(SHA3 *self, const void* data, size_t numBytes);
/// return latest hash as hex characters
char *SHA3_getHash_str(SHA3 *self);
