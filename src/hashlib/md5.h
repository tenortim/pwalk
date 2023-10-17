// //////////////////////////////////////////////////////////
// md5.h
// Copyright (c) 2014 Stephan Brumme. All rights reserved.
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

/// compute MD5 hash
/** Usage:
    MD5 *md5 = MD5_init();
    char *myHash  = MD5_str(md5, "Hello World");     // C string
    char *myHash2 = MD5_block(md5, "How are you", 11); // arbitrary data, 11 bytes
    ...
    free(myHash);
    free(myHash2);
    MD5_free(md5);

    // or in a streaming fashion:

    MD5 *md5 = MD5_init();
    while (more data available)
      MD5_add(md5, pointer to fresh data, number of new bytes);
    char *myHash3 = MD5_getHash_str(md5);
    ...
    free(myHash3);
    MD5_free(md5);
  */

/// split into 64 byte blocks (=> 512 bits), hash is 16 bytes long
enum { MD5_BlockSize = 512 / 8, MD5_HashBytes = 16 };
enum { MD5_HashValues = MD5_HashBytes / 4 };

typedef struct {
  /// size of processed data in bytes
  uint64_t m_numBytes;
  /// valid bytes in m_buffer
  size_t   m_bufferSize;
  /// bytes not processed yet
  uint8_t  m_buffer[MD5_BlockSize];
  /// hash, stored as integers
  uint32_t m_hash[MD5_HashValues];
} MD5;

MD5 * MD5_init();
void MD5_reset(MD5 *self);
void MD5_free(MD5 *self);
/// compute MD5 of a memory block
char *MD5_block(MD5 *self, const void* data, size_t numBytes);
/// compute MD5 of a string, excluding final zero
char *MD5_str(MD5 *self, const char *text);
/// add arbitrary number of bytes
void MD5_add(MD5 *self, const void* data, size_t numBytes);
/// return latest hash as 32 hex characters
char *MD5_getHash_str(MD5 *self);
/// return latest hash as bytes
void MD5_getHash_bytes(MD5 *self, unsigned char buffer[MD5_HashBytes]);
