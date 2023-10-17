// //////////////////////////////////////////////////////////
// sha1.h
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

/// compute SHA1 hash
/** Usage:
    SHA1 *sha1 = SHA1_init();
    char *myHash  = SHA1_str(sha1, "Hello World");     // C string
    char *myHash2 = SHA1_block(sha1, "How are you", 11); // arbitrary data, 11 bytes
    ...
    free(myHash);
    free(myHash2);
    SHA1_free(sha1)

    // or in a streaming fashion:

    SHA1 *sha1 = SHA1_init();
    while (more data available)
      SHA1_add(sha1, pointer to fresh data, number of new bytes);
    char *myHash3 = SHA1_getHash_str(sha1);
    ...
    free(myHash3);
    SHA1_free(sha1);
  */

/// split into 64 byte blocks (=> 512 bits), hash is 20 bytes long
enum { SHA1_BlockSize = 512 / 8, SHA1_HashBytes = 20 };
enum { SHA1_HashValues = SHA1_HashBytes / 4 };

typedef struct {
  /// size of processed data in bytes
  uint64_t m_numBytes;
  /// valid bytes in m_buffer
  size_t   m_bufferSize;
  /// bytes not processed yet
  uint8_t  m_buffer[SHA1_BlockSize];
  /// hash, stored as integers
  uint32_t m_hash[SHA1_HashValues];
} SHA1;

SHA1 * SHA1_init();
void SHA1_reset(SHA1 *self);
void SHA1_free(SHA1 *self);
/// compute SHA1 of a memory block
char *SHA1_block(SHA1 *self, const void* data, size_t numBytes);
/// compute SHA1 of a string, excluding final zero
char *SHA1_str(SHA1 *self, const char *text);
/// add arbitrary number of bytes
void SHA1_add(SHA1 *self, const void* data, size_t numBytes);
/// return latest hash as 32 hex characters
char *SHA1_getHash_str(SHA1 *self);
/// return latest hash as bytes
void SHA1_getHash_bytes(SHA1 *self, unsigned char buffer[SHA1_HashBytes]);
