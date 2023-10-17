// //////////////////////////////////////////////////////////
// sha256.h
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once


// define fixed size integer types
#ifdef _MSC_VER
// Windows
typedef unsigned __int8  uint8_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#else
// GCC
#include <stdint.h>
#endif
#include <stddef.h>

/// compute SHA256 hash
/** Usage:
    SHA256 *sha256 = SHA256_init();
    char *myHash  = SHA256_str(sha256, "Hello World");     // C string
    char *myHash2 = SHA256_block(sha256, "How are you", 11); // arbitrary data, 11 bytes
    ...
    free(myHash);
    free(myHash2);
    SHA256_free(sha256);

    // or in a streaming fashion:

    SHA256 *sha256 = SHA256_init();
    while (more data available)
      SHA256_add(sha256, pointer to fresh data, number of new bytes);
    char *myHash3 = SHA256_getHash_str(sha256);
    ...
    free(myHash3);
    SHA256_free(sha256);
  */

/// split into 64 byte blocks (=> 512 bits), hash is 32 bytes long
enum { SHA256_BlockSize = 512 / 8, SHA256_HashBytes = 32 };
enum { SHA256_HashValues = SHA256_HashBytes / 4 };

typedef struct {
  /// size of processed data in bytes
  uint64_t m_numBytes;
  /// valid bytes in m_buffer
  size_t   m_bufferSize;
  /// bytes not processed yet
  uint8_t  m_buffer[SHA256_BlockSize];
  /// hash, stored as integers
  uint32_t m_hash[SHA256_HashValues];
} SHA256;

SHA256 * SHA256_init();
void SHA256_reset(SHA256 *self);
void SHA256_free(SHA256 *self);
/// compute SHA256 of a memory block
char *SHA256_block(SHA256 *self, const void* data, size_t numBytes);
/// compute SHA256 of a string, excluding final zero
char *SHA256_str(SHA256 *self, const char *text);
/// add arbitrary number of bytes
void SHA256_add(SHA256 *self, const void* data, size_t numBytes);
/// return latest hash as 64 hex characters
char *SHA256_getHash_str(SHA256 *self);
/// return latest hash as bytes
void SHA256_getHash_bytes(SHA256 *self, unsigned char buffer[SHA256_HashBytes]);
