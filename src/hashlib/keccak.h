// //////////////////////////////////////////////////////////
// keccak.h
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

/// compute Keccak hash (designated SHA3)
/** Usage:
    Keccak *keccak = Keccak_init(Keccak256);
    char *myHash  = Keccak_str(keccak, "Hello World");     // C string
    char *myHash2 = Keccak_block(keccak, "How are you", 11); // arbitrary data, 11 bytes
    ...
    free(myHash);
    free(myHash2);
    Keccak_free(keccak);

    // or in a streaming fashion:

    Keccak *keccak = Keccak_init(Keccak256);
    while (more data available)
      Keccak_add(keccak, pointer to fresh data, number of new bytes);
    char *myHash3 = Keccak_getHash_str(keccak);
    ...
    free(myHash3);
    Keccak_free(keccak);
  */

/// algorithm variants
enum Keccak_Bits { Keccak224 = 224, Keccak256 = 256, Keccak384 = 384, Keccak512 = 512 };
/// 1600 bits, stored as 25x64 bit, BlockSize is no more than 1152 bits (Keccak224)
enum { Keccak_StateSize    = 1600 / (8 * 8),
       Keccak_MaxBlockSize =  200 - 2 * (224 / 8) };

typedef struct {
  /// hash
  uint64_t m_hash[Keccak_StateSize];
  /// size of processed data in bytes
  uint64_t m_numBytes;
  /// block size (less or equal to MaxBlockSize)
  size_t   m_blockSize;
  /// valid bytes in m_buffer
  size_t   m_bufferSize;
  /// bytes not processed yet
  uint8_t  m_buffer[Keccak_MaxBlockSize];
  /// variant
  enum Keccak_Bits m_bits;
} Keccak;

Keccak * Keccak_init(enum Keccak_Bits bits);
void Keccak_reset(Keccak *self);
void Keccak_free(Keccak *self);
/// compute Keccak of a memory block
char *Keccak_block(Keccak *self, const void* data, size_t numBytes);
/// compute Keccak of a string, excluding final zero
char *Keccak_str(Keccak *self, const char *text);
/// add arbitrary number of bytes
void Keccak_add(Keccak *self, const void* data, size_t numBytes);
/// return latest hash as hex characters
char *Keccak_getHash_str(Keccak *self);
