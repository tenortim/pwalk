// //////////////////////////////////////////////////////////
// sha256.cpp
// Copyright (c) 2014,2015,2021 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#include "sha256.h"

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <endian.h>
#endif
#include <stdlib.h>
#include <string.h>


//#define SHA2_224_SEED_VECTOR


SHA256 *SHA256_init()
{
  SHA256 *sha256 = malloc(sizeof(SHA256));
  if (sha256 == NULL) {
    return NULL;
  }
  SHA256_reset(sha256);
  return sha256;
}

/// restart
void SHA256_reset(SHA256 *self)
{
  self->m_numBytes   = 0;
  self->m_bufferSize = 0;

  // according to RFC 1321
  // "These words were obtained by taking the first thirty-two bits of the
  //  fractional parts of the square roots of the first eight prime numbers"
  self->m_hash[0] = 0x6a09e667;
  self->m_hash[1] = 0xbb67ae85;
  self->m_hash[2] = 0x3c6ef372;
  self->m_hash[3] = 0xa54ff53a;
  self->m_hash[4] = 0x510e527f;
  self->m_hash[5] = 0x9b05688c;
  self->m_hash[6] = 0x1f83d9ab;
  self->m_hash[7] = 0x5be0cd19;

#ifdef SHA2_224_SEED_VECTOR
  // if you want SHA2-224 instead then use these seeds
  // and throw away the last 32 bits of getHash
  self->m_hash[0] = 0xc1059ed8;
  self->m_hash[1] = 0x367cd507;
  self->m_hash[2] = 0x3070dd17;
  self->m_hash[3] = 0xf70e5939;
  self->m_hash[4] = 0xffc00b31;
  self->m_hash[5] = 0x68581511;
  self->m_hash[6] = 0x64f98fa7;
  self->m_hash[7] = 0xbefa4fa4;
#endif
}

/// free backing struct
void SHA256_free(SHA256 *self)
{
  free(self);
}


static inline uint32_t rotate(uint32_t a, uint32_t c)
{
  return (a >> c) | (a << (32 - c));
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

// mix functions for processBlock()
static inline uint32_t f1(uint32_t e, uint32_t f, uint32_t g)
{
  uint32_t term1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
  uint32_t term2 = (e & f) ^ (~e & g); //(g ^ (e & (f ^ g)))
  return term1 + term2;
}

static inline uint32_t f2(uint32_t a, uint32_t b, uint32_t c)
{
  uint32_t term1 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
  uint32_t term2 = ((a | b) & c) | (a & b); //(a & (b ^ c)) ^ (b & c);
  return term1 + term2;
}


/// process 64 bytes
static void processBlock(SHA256 *self, const void* data)
{
  // get last hash
  uint32_t a = self->m_hash[0];
  uint32_t b = self->m_hash[1];
  uint32_t c = self->m_hash[2];
  uint32_t d = self->m_hash[3];
  uint32_t e = self->m_hash[4];
  uint32_t f = self->m_hash[5];
  uint32_t g = self->m_hash[6];
  uint32_t h = self->m_hash[7];

  // data represented as 16x 32-bit words
  const uint32_t* input = (uint32_t*) data;
  // convert to big endian
  uint32_t words[64];
  int i;
  for (i = 0; i < 16; i++)
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
    words[i] =      input[i];
#else
    words[i] = swap(input[i]);
#endif

  uint32_t x,y; // temporaries

  // first round
  x = h + f1(e,f,g) + 0x428a2f98 + words[ 0]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0x71374491 + words[ 1]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0xb5c0fbcf + words[ 2]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0xe9b5dba5 + words[ 3]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x3956c25b + words[ 4]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0x59f111f1 + words[ 5]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x923f82a4 + words[ 6]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0xab1c5ed5 + words[ 7]; y = f2(b,c,d); e += x; a = x + y;

  // secound round
  x = h + f1(e,f,g) + 0xd807aa98 + words[ 8]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0x12835b01 + words[ 9]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0x243185be + words[10]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0x550c7dc3 + words[11]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x72be5d74 + words[12]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0x80deb1fe + words[13]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x9bdc06a7 + words[14]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0xc19bf174 + words[15]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 24 words
  for (; i < 24; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // third round
  x = h + f1(e,f,g) + 0xe49b69c1 + words[16]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0xefbe4786 + words[17]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0x0fc19dc6 + words[18]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0x240ca1cc + words[19]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x2de92c6f + words[20]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0x4a7484aa + words[21]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x5cb0a9dc + words[22]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0x76f988da + words[23]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 32 words
  for (; i < 32; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // fourth round
  x = h + f1(e,f,g) + 0x983e5152 + words[24]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0xa831c66d + words[25]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0xb00327c8 + words[26]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0xbf597fc7 + words[27]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0xc6e00bf3 + words[28]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0xd5a79147 + words[29]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x06ca6351 + words[30]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0x14292967 + words[31]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 40 words
  for (; i < 40; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // fifth round
  x = h + f1(e,f,g) + 0x27b70a85 + words[32]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0x2e1b2138 + words[33]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0x4d2c6dfc + words[34]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0x53380d13 + words[35]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x650a7354 + words[36]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0x766a0abb + words[37]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x81c2c92e + words[38]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0x92722c85 + words[39]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 48 words
  for (; i < 48; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // sixth round
  x = h + f1(e,f,g) + 0xa2bfe8a1 + words[40]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0xa81a664b + words[41]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0xc24b8b70 + words[42]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0xc76c51a3 + words[43]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0xd192e819 + words[44]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0xd6990624 + words[45]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0xf40e3585 + words[46]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0x106aa070 + words[47]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 56 words
  for (; i < 56; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // seventh round
  x = h + f1(e,f,g) + 0x19a4c116 + words[48]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0x1e376c08 + words[49]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0x2748774c + words[50]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0x34b0bcb5 + words[51]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x391c0cb3 + words[52]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0x4ed8aa4a + words[53]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0x5b9cca4f + words[54]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0x682e6ff3 + words[55]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 64 words
  for (; i < 64; i++)
    words[i] = words[i-16] +
               (rotate(words[i-15],  7) ^ rotate(words[i-15], 18) ^ (words[i-15] >>  3)) +
               words[i-7] +
               (rotate(words[i- 2], 17) ^ rotate(words[i- 2], 19) ^ (words[i- 2] >> 10));

  // eigth round
  x = h + f1(e,f,g) + 0x748f82ee + words[56]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + 0x78a5636f + words[57]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + 0x84c87814 + words[58]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + 0x8cc70208 + words[59]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + 0x90befffa + words[60]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + 0xa4506ceb + words[61]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + 0xbef9a3f7 + words[62]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + 0xc67178f2 + words[63]; y = f2(b,c,d); e += x; a = x + y;

  // update hash
  self->m_hash[0] += a;
  self->m_hash[1] += b;
  self->m_hash[2] += c;
  self->m_hash[3] += d;
  self->m_hash[4] += e;
  self->m_hash[5] += f;
  self->m_hash[6] += g;
  self->m_hash[7] += h;
}


/// add arbitrary number of bytes
void SHA256_add(SHA256 *self, const void* data, size_t numBytes)
{
  const uint8_t* current = (const uint8_t*) data;

  if (self->m_bufferSize > 0)
  {
    while (numBytes > 0 && self->m_bufferSize < SHA256_BlockSize)
    {
      self->m_buffer[self->m_bufferSize++] = *current++;
      numBytes--;
    }
  }

  // full buffer
  if (self->m_bufferSize == SHA256_BlockSize)
  {
    processBlock(self, self->m_buffer);
    self->m_numBytes  += SHA256_BlockSize;
    self->m_bufferSize = 0;
  }

  // no more data ?
  if (numBytes == 0)
    return;

  // process full blocks
  while (numBytes >= SHA256_BlockSize)
  {
    processBlock(self, current);
    current    += SHA256_BlockSize;
    self->m_numBytes += SHA256_BlockSize;
    numBytes   -= SHA256_BlockSize;
  }

  // keep remaining bytes in buffer
  while (numBytes > 0)
  {
    self->m_buffer[self->m_bufferSize++] = *current++;
    numBytes--;
  }
}


/// process final block, less than 64 bytes
static void processBuffer(SHA256 *self)
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
  unsigned char extra[SHA256_BlockSize];

  // append a "1" bit, 128 => binary 10000000
  if (self->m_bufferSize < SHA256_BlockSize)
    self->m_buffer[self->m_bufferSize] = 128;
  else
    extra[0] = 128;

  size_t i;
  for (i = self->m_bufferSize + 1; i < SHA256_BlockSize; i++)
    self->m_buffer[i] = 0;
  for (; i < paddedLength; i++)
    extra[i - SHA256_BlockSize] = 0;

  // add message length in bits as 64 bit number
  uint64_t msgBits = 8 * (self->m_numBytes + self->m_bufferSize);
  // find right position
  unsigned char* addLength;
  if (paddedLength < SHA256_BlockSize)
    addLength = self->m_buffer + paddedLength;
  else
    addLength = extra + paddedLength - SHA256_BlockSize;

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
  if (paddedLength > SHA256_BlockSize)
    processBlock(self, extra);
}


/// return latest hash as 64 hex characters
char * SHA256_getHash_str(SHA256 *self)
{
  // compute hash (as raw bytes)
  unsigned char rawHash[SHA256_HashBytes];
  SHA256_getHash_bytes(self, rawHash);

  // convert to hex string
  char result[(2 * SHA256_HashBytes) + 1];
  char *p;
  p = result;
  for (int i = 0; i < SHA256_HashBytes; i++)
  {
    static const char dec2hex[16+1] = "0123456789abcdef";
    *p++ = dec2hex[(rawHash[i] >> 4) & 15];
    *p++ = dec2hex[ rawHash[i]       & 15];
  }
  *p = '\0';

  return strdup(result);
}


/// return latest hash as bytes
void SHA256_getHash_bytes(SHA256 *self,unsigned char buffer[SHA256_HashBytes])
{
  // save old hash if buffer is partially filled
  uint32_t oldHash[SHA256_HashValues];
  for (int i = 0; i < SHA256_HashValues; i++)
    oldHash[i] = self->m_hash[i];

  // process remaining bytes
  processBuffer(self);

  unsigned char* current = buffer;
  for (int i = 0; i < SHA256_HashValues; i++)
  {
    *current++ = (self->m_hash[i] >> 24) & 0xFF;
    *current++ = (self->m_hash[i] >> 16) & 0xFF;
    *current++ = (self->m_hash[i] >>  8) & 0xFF;
    *current++ =  self->m_hash[i]        & 0xFF;

    // restore old hash
    self->m_hash[i] = oldHash[i];
  }
}


/// compute SHA256 of a memory block
char *SHA256_block(SHA256 *self, const void* data, size_t numBytes)
{
  SHA256_reset(self);
  SHA256_add(self, data, numBytes);
  return SHA256_getHash_str(self);
}


/// compute SHA256 of a string, excluding final zero
char *SHA256_str(SHA256 *self, const char * text)
{
  SHA256_reset(self);
  SHA256_add(self, text, strlen(text));
  return SHA256_getHash_str(self);
}
