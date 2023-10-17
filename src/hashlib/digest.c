// //////////////////////////////////////////////////////////
// digest.c
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

// cc -Wall -O3 digest.c crc32.c md5.c sha1.c sha256.c keccak.c sha3.c -o digest

#include "crc32.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "keccak.h"
#include "sha3.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char** argv)
{
  // syntax check
  if (argc < 2 || argc > 3)
  {
    fprintf(stderr, "digest filename [--crc|--md5|--sha1|--sha256|--keccak|--sha3]\n");
    return 1;
  }

  // parameters
  char *filename  = argv[1];
  char *algorithm = argc == 3 ? argv[2] : "";
  bool all = (argc == 2);
  bool computeCrc32     = all || !strcmp(algorithm, "--crc");
  bool computeMd5       = all || !strcmp(algorithm, "--md5");
  bool computeSha1      = all || !strcmp(algorithm, "--sha1");
  bool computeSha2      = all || !strcmp(algorithm, "--sha2") || !strcmp(algorithm, "--sha256");
  bool computeKeccak    = all || !strcmp(algorithm, "--keccak");
  bool computeSha3      = all || !strcmp(algorithm, "--sha3");

  CRC32  *digestCrc32 = CRC32_init();
  MD5    *digestMd5 = MD5_init();
  SHA1   *digestSha1 = SHA1_init();
  SHA256 *digestSha2 = SHA256_init();
  Keccak *digestKeccak = Keccak_init(Keccak256);
  SHA3   *digestSha3 = SHA3_init(Bits256);

  // select input source: either file or standard-in
  int fd;
  // accept stdin, syntax will be: "./digest - --sha3 < data"
  if (!strcmp(filename, "-"))
  {
    fd = 0;
  }
  else
  {
    // open file
    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
      fprintf(stderr, "Can't open '%s'\n", filename);
      return 2;
    }
  }

  // each cycle processes about 1 MByte (divisible by 144 => improves Keccak/SHA3 performance)
  const size_t BufferSize = 144*7*1024;
  char* buffer = malloc(BufferSize);

  // process file
  size_t numBytesRead;
  while ((numBytesRead = read(fd, buffer, BufferSize)) > 0)
  {
    if (computeCrc32)
      CRC32_add(digestCrc32, buffer, numBytesRead);
    if (computeMd5)
      MD5_add(digestMd5, buffer, numBytesRead);
    if (computeSha1)
      SHA1_add(digestSha1, buffer, numBytesRead);
    if (computeSha2)
      SHA256_add(digestSha2, buffer, numBytesRead);
    if (computeKeccak)
      Keccak_add(digestKeccak, buffer, numBytesRead);
    if (computeSha3)
      SHA3_add(digestSha3, buffer, numBytesRead);
  }

  // clean up
  close(fd);
  free(buffer);

  // show results
  if (computeCrc32)
    printf("CRC32:      %s\n", CRC32_getHash_str(digestCrc32));
  if (computeMd5)
    printf("MD5:        %s\n", MD5_getHash_str(digestMd5));
  if (computeSha1)
    printf("SHA1:       %s\n", SHA1_getHash_str(digestSha1));
  if (computeSha2)
    printf("SHA2/256:   %s\n", SHA256_getHash_str(digestSha2));
  if (computeKeccak)
    printf("Keccak/256: %s\n", Keccak_getHash_str(digestKeccak));
  if (computeSha3)
    printf("SHA3/256:   %s\n", SHA3_getHash_str(digestSha3));

  return 0;
}
