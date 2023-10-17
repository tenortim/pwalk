// //////////////////////////////////////////////////////////
// keccak.cpp
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#include "keccak.h"

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <endian.h>
#endif

#include <stdlib.h>
#include <string.h>


Keccak *Keccak_init(enum Keccak_Bits bits)
{
  Keccak *keccak = malloc(sizeof(Keccak));
  if (keccak == NULL) {
    return NULL;
  }
  keccak->m_blockSize = (200 - 2 * (bits / 8));
  // validate bits
  // No 'C' equivalent of explicit to prevent int->enum conversion
  switch(bits) {
    case Keccak224:
    case Keccak256:
    case Keccak384:
    case Keccak512:
      // valid size
      break;
    default:
      // no easy way to indicate error other than failing the initialization
      return NULL;
  }
  keccak->m_bits = bits;
  Keccak_reset(keccak);
  return keccak;
}

/// restart
void Keccak_reset(Keccak *self)
{
  for (size_t i = 0; i < Keccak_StateSize; i++)
    self->m_hash[i] = 0;

  self->m_numBytes   = 0;
  self->m_bufferSize = 0;
}

/// free backing struct
void Keccak_free(Keccak *self)
{
  free(self);
}


/// constants and local helper functions
static const unsigned int KeccakRounds = 24;
// can't use const variable as array size in C
static const uint64_t XorMasks[24] =
{
  0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
  0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
  0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
  0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
  0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/// rotate left and wrap around to the right
static inline uint64_t rotateLeft(uint64_t x, uint8_t numBits)
{
  return (x << numBits) | (x >> (64 - numBits));
}

/// convert litte vs big endian
static inline uint64_t swap(uint64_t x)
{
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap64(x);
#endif
#ifdef _MSC_VER
  return _byteswap_uint64(x);
#endif

  return  (x >> 56) |
         ((x >> 40) & 0x000000000000FF00ULL) |
         ((x >> 24) & 0x0000000000FF0000ULL) |
         ((x >>  8) & 0x00000000FF000000ULL) |
         ((x <<  8) & 0x000000FF00000000ULL) |
         ((x << 24) & 0x0000FF0000000000ULL) |
         ((x << 40) & 0x00FF000000000000ULL) |
          (x << 56);
}

/// return x % 5 for 0 <= x <= 9
static unsigned int mod5(unsigned int x)
{
  if (x < 5)
    return x;

  return x - 5;
}


/// process a full block
static void processBlock(Keccak *self, const void* data)
{
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
#define LITTLEENDIAN(x) swap(x)
#else
#define LITTLEENDIAN(x) (x)
#endif

  const uint64_t* data64 = (const uint64_t*) data;
  // mix data into state
  for (unsigned int i = 0; i < self->m_blockSize / 8; i++)
    self->m_hash[i] ^= LITTLEENDIAN(data64[i]);

  // re-compute state
  for (unsigned int round = 0; round < KeccakRounds; round++)
  {
    // Theta
    uint64_t coefficients[5];
    for (unsigned int i = 0; i < 5; i++)
      coefficients[i] = self->m_hash[i] ^ self->m_hash[i + 5] ^ self->m_hash[i + 10] ^ self->m_hash[i + 15] ^ self->m_hash[i + 20];

    for (unsigned int i = 0; i < 5; i++)
    {
      uint64_t one = coefficients[mod5(i + 4)] ^ rotateLeft(coefficients[mod5(i + 1)], 1);
      self->m_hash[i     ] ^= one;
      self->m_hash[i +  5] ^= one;
      self->m_hash[i + 10] ^= one;
      self->m_hash[i + 15] ^= one;
      self->m_hash[i + 20] ^= one;
    }

    // temporary
    uint64_t one;

    // Rho Pi
    uint64_t last = self->m_hash[1];
    one = self->m_hash[10]; self->m_hash[10] = rotateLeft(last,  1); last = one;
    one = self->m_hash[ 7]; self->m_hash[ 7] = rotateLeft(last,  3); last = one;
    one = self->m_hash[11]; self->m_hash[11] = rotateLeft(last,  6); last = one;
    one = self->m_hash[17]; self->m_hash[17] = rotateLeft(last, 10); last = one;
    one = self->m_hash[18]; self->m_hash[18] = rotateLeft(last, 15); last = one;
    one = self->m_hash[ 3]; self->m_hash[ 3] = rotateLeft(last, 21); last = one;
    one = self->m_hash[ 5]; self->m_hash[ 5] = rotateLeft(last, 28); last = one;
    one = self->m_hash[16]; self->m_hash[16] = rotateLeft(last, 36); last = one;
    one = self->m_hash[ 8]; self->m_hash[ 8] = rotateLeft(last, 45); last = one;
    one = self->m_hash[21]; self->m_hash[21] = rotateLeft(last, 55); last = one;
    one = self->m_hash[24]; self->m_hash[24] = rotateLeft(last,  2); last = one;
    one = self->m_hash[ 4]; self->m_hash[ 4] = rotateLeft(last, 14); last = one;
    one = self->m_hash[15]; self->m_hash[15] = rotateLeft(last, 27); last = one;
    one = self->m_hash[23]; self->m_hash[23] = rotateLeft(last, 41); last = one;
    one = self->m_hash[19]; self->m_hash[19] = rotateLeft(last, 56); last = one;
    one = self->m_hash[13]; self->m_hash[13] = rotateLeft(last,  8); last = one;
    one = self->m_hash[12]; self->m_hash[12] = rotateLeft(last, 25); last = one;
    one = self->m_hash[ 2]; self->m_hash[ 2] = rotateLeft(last, 43); last = one;
    one = self->m_hash[20]; self->m_hash[20] = rotateLeft(last, 62); last = one;
    one = self->m_hash[14]; self->m_hash[14] = rotateLeft(last, 18); last = one;
    one = self->m_hash[22]; self->m_hash[22] = rotateLeft(last, 39); last = one;
    one = self->m_hash[ 9]; self->m_hash[ 9] = rotateLeft(last, 61); last = one;
    one = self->m_hash[ 6]; self->m_hash[ 6] = rotateLeft(last, 20); last = one;
                      self->m_hash[ 1] = rotateLeft(last, 44);

    // Chi
    for (unsigned int j = 0; j < Keccak_StateSize; j += 5)
    {
      // temporaries
      uint64_t one = self->m_hash[j];
      uint64_t two = self->m_hash[j + 1];

      self->m_hash[j]     ^= self->m_hash[j + 2] & ~two;
      self->m_hash[j + 1] ^= self->m_hash[j + 3] & ~self->m_hash[j + 2];
      self->m_hash[j + 2] ^= self->m_hash[j + 4] & ~self->m_hash[j + 3];
      self->m_hash[j + 3] ^=            one      & ~self->m_hash[j + 4];
      self->m_hash[j + 4] ^=            two      & ~one;
    }

    // Iota
    self->m_hash[0] ^= XorMasks[round];
  }
}


/// add arbitrary number of bytes
void Keccak_add(Keccak *self, const void* data, size_t numBytes)
{
  const uint8_t* current = (const uint8_t*) data;

  if (self->m_bufferSize > 0)
  {
    while (numBytes > 0 && self->m_bufferSize < self->m_blockSize)
    {
      self->m_buffer[self->m_bufferSize++] = *current++;
      numBytes--;
    }
  }

  // full buffer
  if (self->m_bufferSize == self->m_blockSize)
  {
    processBlock(self, (void*)self->m_buffer);
    self->m_numBytes  += self->m_blockSize;
    self->m_bufferSize = 0;
  }

  // no more data ?
  if (numBytes == 0)
    return;

  // process full blocks
  while (numBytes >= self->m_blockSize)
  {
    processBlock(self, current);
    current          += self->m_blockSize;
    self->m_numBytes += self->m_blockSize;
    numBytes         -= self->m_blockSize;
  }

  // keep remaining bytes in buffer
  while (numBytes > 0)
  {
    self->m_buffer[self->m_bufferSize++] = *current++;
    numBytes--;
  }
}


/// process everything left in the internal buffer
static void processBuffer(Keccak * self)
{
  unsigned int blockSize = 200 - 2 * (self->m_bits / 8);

  // add padding
  size_t offset = self->m_bufferSize;
  // add a "1" byte
  self->m_buffer[offset++] = 1;
  // fill with zeros
  while (offset < blockSize)
    self->m_buffer[offset++] = 0;

  // and add a single set bit
  self->m_buffer[blockSize - 1] |= 0x80;

  processBlock(self, self->m_buffer);
}


/// return latest hash as 16 hex characters
char * Keccak_getHash_str(Keccak *self)
{
  // save hash state
  uint64_t oldHash[Keccak_StateSize];
  for (unsigned int i = 0; i < Keccak_StateSize; i++)
    oldHash[i] = self->m_hash[i];

  // process remaining bytes
  processBuffer(self);

  // convert hash to string
  static const char dec2hex[16 + 1] = "0123456789abcdef";

  // number of significant elements in hash (uint64_t)
  unsigned int hashLength = self->m_bits / 64;

  char result[(self->m_bits / 4) + 1];
  char *p;
  p = result;
  for (unsigned int i = 0; i < hashLength; i++)
    for (unsigned int j = 0; j < 8; j++) // 64 bits => 8 bytes
    {
      // convert a byte to hex
      unsigned char oneByte = (unsigned char) (self->m_hash[i] >> (8 * j));
      *p++ = dec2hex[oneByte >> 4];
      *p++ = dec2hex[oneByte & 15];
    }

  // Keccak224's last entry in m_hash provides only 32 bits instead of 64 bits
  unsigned int remainder = self->m_bits - hashLength * 64;
  unsigned int processed = 0;
  while (processed < remainder)
  {
    // convert a byte to hex
    unsigned char oneByte = (unsigned char) (self->m_hash[hashLength] >> processed);
    *p++ = dec2hex[oneByte >> 4];
    *p++ = dec2hex[oneByte & 15];

    processed += 8;
  }
  *p = '\0';

  // restore state
  for (unsigned int i = 0; i < Keccak_StateSize; i++)
    self->m_hash[i] = oldHash[i];

  return strdup(result);
}


/// compute Keccak hash of a memory block
char *Keccak_block(Keccak *self, const void* data, size_t numBytes)
{
  Keccak_reset(self);
  Keccak_add(self, data, numBytes);
  return Keccak_getHash_str(self);
}


/// compute Keccak hash of a string, excluding final zero
char *Keccak_str(Keccak *self, const char * text)
{
  Keccak_reset(self);
  Keccak_add(self, text, strlen(text));
  return Keccak_getHash_str(self);
}
