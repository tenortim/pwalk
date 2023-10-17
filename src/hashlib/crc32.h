// //////////////////////////////////////////////////////////
// crc32.h
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once

// define fixed size integer types
#ifdef _MSC_VER
// Windows
typedef unsigned __int8  uint8_t;
typedef unsigned __int32 uint32_t;
#else
// GCC
#include <stdint.h>
#endif
#include <stddef.h>

/// compute CRC32 hash, based on Intel's Slicing-by-8 algorithm
/** Usage:
    CRC32 *crc32 = CRC32_init();
    char *myHash  = CRC32_str(crc32, "Hello World");     // C string
    char *myHash2 = CRC32_block(crc32, "How are you", 11); // arbitrary data, 11 bytes
    ...
    free(myHash);
    free(myHash2);
    CRC32_free(crc32);

    // or in a streaming fashion:

    CRC32 *crc32 = CRC32_init();
    while (more data available)
      CRC32_add(crc32, pointer to fresh data, number of new bytes);
    char *myHash3 = CRC32_getHash_str(crc32);
    ...
    free(myHash3);
    CRC32_free(crc32)

    Note:
    You can find code for the faster Slicing-by-16 algorithm on my website, too:
    http://create.stephan-brumme.com/crc32/
    Its unrolled version is about twice as fast but its look-up table doubled in size as well.
  */

typedef struct {
    uint32_t m_hash;
} CRC32;

/// hash is 4 bytes long
enum { CRC32_HashBytes = 4 };

CRC32 * CRC32_init();
void CRC32_reset(CRC32 *self);
void CRC32_free(CRC32 *self);
/// compute CRC32 of a memory block
char *CRC32_block(CRC32 *self, const void* data, size_t numBytes);
/// compute CRC32 of a string, excluding final zero
char *CRC32_str(CRC32 *self, const char *text);
/// add arbitrary number of bytes
void CRC32_add(CRC32 *self, const void* data, size_t numBytes);
/// return latest hash as 8 hex characters
char *CRC32_getHash_str(CRC32 *self);
/// return latest hash as bytes
void CRC32_getHash_bytes(CRC32 *self, unsigned char buffer[CRC32_HashBytes]);
