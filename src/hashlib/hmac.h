// //////////////////////////////////////////////////////////
// hmac.h
// Copyright (c) 2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once

// based on http://tools.ietf.org/html/rfc2104
// see also http://en.wikipedia.org/wiki/Hash-based_message_authentication_code

/** Usage:
    char *msg = "The quick brown fox jumps over the lazy dog";
    char *key = "key";
    char *md5hmac  = hmac_MD5(msg, key);
    char *sha1hmac = hmac_SHA1(msg, key);
    char *sha2hmac = hmac_SHA256(msg, key);

    Note:
    To keep the code simple, HMAC computation currently needs the whole message at once.
    This is in contrast to the hashes MD5, SHA1, etc. where an add() method is available
    for incremental computation.
    You can use any hash for HMAC as long as it provides:
    - constant HashMethod::BlockSize (typically 64)
    - constant HashMethod::HashBytes (length of hash in bytes, e.g. 20 for SHA1)
    - HashMethod::add(buffer, bufferSize)
    - HashMethod::getHash(unsigned char buffer[HashMethod::BlockSize])
    - The init routine does not require a parameter e.g. for SHA3
    The code will need to be refactored to support SHA3/Keccak
  */

#include "md5.h"
#include "sha256.h"
#include "sha1.h"
#include <string.h>

/// compute HMAC hash of data and key using MD5, SHA1 or SHA256
#define hmac_full(HashMethod) \
char *hmac_##HashMethod##_full(const void* data, size_t numDataBytes, const void* key, size_t numKeyBytes)\
{\
  /* initialize key with zeros */\
  unsigned char usedKey[HashMethod##_BlockSize] = {0};\
\
  /* adjust length of key: must contain exactly blockSize bytes */\
  if (numKeyBytes <= HashMethod##_BlockSize)\
  {\
    /* copy key */\
    memcpy(usedKey, key, numKeyBytes);\
  }\
  else\
  {\
    /* shorten key: usedKey = hashed(key) */\
    HashMethod *keyHasher = HashMethod##_init();\
    HashMethod##_add(keyHasher, key, numKeyBytes);\
    HashMethod##_getHash_bytes(keyHasher, usedKey);\
    HashMethod##_free(keyHasher);\
  }\
\
  /* create initial XOR padding */\
  for (size_t i = 0; i < HashMethod##_BlockSize; i++)\
    usedKey[i] ^= 0x36;\
\
  /* inside = hash((usedKey ^ 0x36) + data) */\
  unsigned char inside[HashMethod##_HashBytes];\
  HashMethod *insideHasher = HashMethod##_init();\
  HashMethod##_add(insideHasher, usedKey, HashMethod##_BlockSize);\
  HashMethod##_add(insideHasher, data, numDataBytes);\
  HashMethod##_getHash_bytes(insideHasher, inside);\
  HashMethod##_free(insideHasher);\
\
  /* undo usedKey's previous 0x36 XORing and apply a XOR by 0x5C */\
  for (size_t i = 0; i < HashMethod##_BlockSize; i++)\
    usedKey[i] ^= 0x5C ^ 0x36;\
\
  /* hash((usedKey ^ 0x5C) + hash((usedKey ^ 0x36) + data)) */\
  HashMethod *finalHasher = HashMethod##_init();\
  HashMethod##_add(finalHasher, usedKey, HashMethod##_BlockSize);\
  HashMethod##_add(finalHasher, inside, HashMethod##_HashBytes);\
  char *finalHash =  HashMethod##_getHash_str(finalHasher);\
  HashMethod##_free(finalHasher);\
\
  return finalHash;\
}

hmac_full(MD5)
hmac_full(SHA256)
hmac_full(SHA1)
// hmac_full(SHA3)
// hmac_full(Keccak)

/// convenience function for character strings
#define hmac_str(HashMethod) \
char *hmac_##HashMethod(const char *data, const char *key) \
{ \
  return hmac_##HashMethod##_full(data, strlen(data), key, strlen(key)); \
}

hmac_str(MD5)
hmac_str(SHA256)
hmac_str(SHA1)
// hmac_str(SHA3)
// hmac_str(Keccak)
