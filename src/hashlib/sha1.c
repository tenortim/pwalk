// //////////////////////////////////////////////////////////
// sha1.cpp
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#include "sha1.h"

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <endian.h>
#endif
#include <stdlib.h>
#include <string.h>


SHA1 *SHA1_init()
{
  SHA1 *sha1 = malloc(sizeof(SHA1));
  if (sha1 == NULL) {
    return NULL;
  }
  SHA1_reset(sha1);
  return sha1;
}

/// restart
void SHA1_reset(SHA1 *self)
{
  self->m_numBytes   = 0;
  self->m_bufferSize = 0;

  // according to RFC 1321
  self->m_hash[0] = 0x67452301;
  self->m_hash[1] = 0xefcdab89;
  self->m_hash[2] = 0x98badcfe;
  self->m_hash[3] = 0x10325476;
  self->m_hash[4] = 0xc3d2e1f0;
}

/// free backing struct
void SHA1_free(SHA1 *self)
{
  free(self);
}


// mix functions for processBlock()
static inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d)
{
  return d ^ (b & (c ^ d)); // original: f = (b & c) | ((~b) & d);
}

static inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d)
{
  return b ^ c ^ d;
}

static inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d)
{
  return (b & c) | (b & d) | (c & d);
}

static inline uint32_t rotate(uint32_t a, uint32_t c)
{
  return (a << c) | (a >> (32 - c));
}

static inline uint32_t swap(uint32_t x)
{
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap32(x);
#endif
#ifdef MSC_VER
  return _byteswap_ulong(x);
#endif

  return (x >> 24) |
        ((x >>  8) & 0x0000FF00) |
        ((x <<  8) & 0x00FF0000) |
         (x << 24);
}


/// process 64 bytes
static void processBlock(SHA1 *self, const void* data)
{
  // get last hash
  uint32_t a = self->m_hash[0];
  uint32_t b = self->m_hash[1];
  uint32_t c = self->m_hash[2];
  uint32_t d = self->m_hash[3];
  uint32_t e = self->m_hash[4];

  // data represented as 16x 32-bit words
  const uint32_t* input = (uint32_t*) data;
  // convert to big endian
  uint32_t words[80];
  for (int i = 0; i < 16; i++)
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
    words[i] = input[i];
#else
    words[i] = swap(input[i]);
#endif

  // extend to 80 words
  for (int i = 16; i < 80; i++)
    words[i] = rotate(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1);

  // first round
  for (int i = 0; i < 4; i++)
  {
    int offset = 5*i;
    e += rotate(a,5) + f1(b,c,d) + words[offset  ] + 0x5a827999; b = rotate(b,30);
    d += rotate(e,5) + f1(a,b,c) + words[offset+1] + 0x5a827999; a = rotate(a,30);
    c += rotate(d,5) + f1(e,a,b) + words[offset+2] + 0x5a827999; e = rotate(e,30);
    b += rotate(c,5) + f1(d,e,a) + words[offset+3] + 0x5a827999; d = rotate(d,30);
    a += rotate(b,5) + f1(c,d,e) + words[offset+4] + 0x5a827999; c = rotate(c,30);
  }

  // second round
  for (int i = 4; i < 8; i++)
  {
    int offset = 5*i;
    e += rotate(a,5) + f2(b,c,d) + words[offset  ] + 0x6ed9eba1; b = rotate(b,30);
    d += rotate(e,5) + f2(a,b,c) + words[offset+1] + 0x6ed9eba1; a = rotate(a,30);
    c += rotate(d,5) + f2(e,a,b) + words[offset+2] + 0x6ed9eba1; e = rotate(e,30);
    b += rotate(c,5) + f2(d,e,a) + words[offset+3] + 0x6ed9eba1; d = rotate(d,30);
    a += rotate(b,5) + f2(c,d,e) + words[offset+4] + 0x6ed9eba1; c = rotate(c,30);
  }

  // third round
  for (int i = 8; i < 12; i++)
  {
    int offset = 5*i;
    e += rotate(a,5) + f3(b,c,d) + words[offset  ] + 0x8f1bbcdc; b = rotate(b,30);
    d += rotate(e,5) + f3(a,b,c) + words[offset+1] + 0x8f1bbcdc; a = rotate(a,30);
    c += rotate(d,5) + f3(e,a,b) + words[offset+2] + 0x8f1bbcdc; e = rotate(e,30);
    b += rotate(c,5) + f3(d,e,a) + words[offset+3] + 0x8f1bbcdc; d = rotate(d,30);
    a += rotate(b,5) + f3(c,d,e) + words[offset+4] + 0x8f1bbcdc; c = rotate(c,30);
  }

  // fourth round
  for (int i = 12; i < 16; i++)
  {
    int offset = 5*i;
    e += rotate(a,5) + f2(b,c,d) + words[offset  ] + 0xca62c1d6; b = rotate(b,30);
    d += rotate(e,5) + f2(a,b,c) + words[offset+1] + 0xca62c1d6; a = rotate(a,30);
    c += rotate(d,5) + f2(e,a,b) + words[offset+2] + 0xca62c1d6; e = rotate(e,30);
    b += rotate(c,5) + f2(d,e,a) + words[offset+3] + 0xca62c1d6; d = rotate(d,30);
    a += rotate(b,5) + f2(c,d,e) + words[offset+4] + 0xca62c1d6; c = rotate(c,30);
  }

  // update hash
  self->m_hash[0] += a;
  self->m_hash[1] += b;
  self->m_hash[2] += c;
  self->m_hash[3] += d;
  self->m_hash[4] += e;
}


/// add arbitrary number of bytes
void SHA1_add(SHA1 *self, const void* data, size_t numBytes)
{
  const uint8_t* current = (const uint8_t*) data;

  if (self->m_bufferSize > 0)
  {
    while (numBytes > 0 && self->m_bufferSize < SHA1_BlockSize)
    {
      self->m_buffer[self->m_bufferSize++] = *current++;
      numBytes--;
    }
  }

  // full buffer
  if (self->m_bufferSize == SHA1_BlockSize)
  {
    processBlock(self, (void*)self->m_buffer);
    self->m_numBytes  += SHA1_BlockSize;
    self->m_bufferSize = 0;
  }

  // no more data ?
  if (numBytes == 0)
    return;

  // process full blocks
  while (numBytes >= SHA1_BlockSize)
  {
    processBlock(self, current);
    current          += SHA1_BlockSize;
    self->m_numBytes += SHA1_BlockSize;
    numBytes         -= SHA1_BlockSize;
  }

  // keep remaining bytes in buffer
  while (numBytes > 0)
  {
    self->m_buffer[self->m_bufferSize++] = *current++;
    numBytes--;
  }
}


/// process final block, less than 64 bytes
static void processBuffer(SHA1 *self)
{
  // the input bytes are considered as bits strings, where the first bit is the most significant bit of the byte

  // - append "1" bit to message
  // - append "0" bits until message length in bit mod 512 is 448
  // - append length as 64 bit integer

  // number of bits
  size_t paddedLength = self->m_bufferSize * 8;

  // plus one bit set to 1 (always appended)
  paddedLength++;

  // number of bits must be (numBits % 512) = 448
  size_t lower11Bits = paddedLength & 511;
  if (lower11Bits <= 448)
    paddedLength +=       448 - lower11Bits;
  else
    paddedLength += 512 + 448 - lower11Bits;
  // convert from bits to bytes
  paddedLength /= 8;

  // only needed if additional data flows over into a second block
  unsigned char extra[SHA1_BlockSize];

  // append a "1" bit, 128 => binary 10000000
  if (self->m_bufferSize < SHA1_BlockSize)
    self->m_buffer[self->m_bufferSize] = 128;
  else
    extra[0] = 128;

  size_t i;
  for (i = self->m_bufferSize + 1; i < SHA1_BlockSize; i++)
    self->m_buffer[i] = 0;
  for (; i < paddedLength; i++)
    extra[i - SHA1_BlockSize] = 0;

  // add message length in bits as 64 bit number
  uint64_t msgBits = 8 * (self->m_numBytes + self->m_bufferSize);
  // find right position
  unsigned char* addLength;
  if (paddedLength < SHA1_BlockSize)
    addLength = self->m_buffer + paddedLength;
  else
    addLength = extra + paddedLength - SHA1_BlockSize;

  // must be big endian
  *addLength++ = (unsigned char)((msgBits >> 56) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 48) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 40) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 32) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 24) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >> 16) & 0xFF);
  *addLength++ = (unsigned char)((msgBits >>  8) & 0xFF);
  *addLength   = (unsigned char)( msgBits        & 0xFF);

  // process blocks
  processBlock(self, self->m_buffer);
  // flowed over into a second block ?
  if (paddedLength > SHA1_BlockSize)
    processBlock(self, extra);
}


/// return latest hash as 40 hex characters
char * SHA1_getHash_str(SHA1 *self)
{
  // compute hash (as raw bytes)
  unsigned char rawHash[SHA1_HashBytes];
  SHA1_getHash_bytes(self, rawHash);

  // convert to hex string
  char result[(2 * SHA1_HashBytes) + 1];
  char *p;
  p = result;
  for (int i = 0; i < SHA1_HashBytes; i++)
  {
    static const char dec2hex[16+1] = "0123456789abcdef";
    *p++ = dec2hex[(rawHash[i] >> 4) & 15];
    *p++ = dec2hex[ rawHash[i]       & 15];
  }
  *p = '\0';

  return strdup(result);
}


/// return latest hash as bytes
void SHA1_getHash_bytes(SHA1 *self, unsigned char buffer[SHA1_HashBytes])
{
  // save old hash if buffer is partially filled
  uint32_t oldHash[SHA1_HashValues];
  for (int i = 0; i < SHA1_HashValues; i++)
    oldHash[i] = self->m_hash[i];

  // process remaining bytes
  processBuffer(self);

  unsigned char* current = buffer;
  for (int i = 0; i < SHA1_HashValues; i++)
  {
    *current++ = (self->m_hash[i] >> 24) & 0xFF;
    *current++ = (self->m_hash[i] >> 16) & 0xFF;
    *current++ = (self->m_hash[i] >>  8) & 0xFF;
    *current++ =  self->m_hash[i]        & 0xFF;

    // restore old hash
    self->m_hash[i] = oldHash[i];
  }
}


/// compute SHA1 of a memory block
char *SHA1_block(SHA1 *self, const void* data, size_t numBytes)
{
  SHA1_reset(self);
  SHA1_add(self, data, numBytes);
  return SHA1_getHash_str(self);
}


/// compute SHA1 of a string, excluding final zero
char *SHA1_str(SHA1 *self, const char * text)
{
  SHA1_reset(self);
  SHA1_add(self, text, strlen(text));
  return SHA1_getHash_str(self);
}
