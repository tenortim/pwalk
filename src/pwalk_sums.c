#include <unistd.h>

#include "pwalk_sums.h"
#include "hashlib/crc32.h"
#include "hashlib/md5.h"

// hash() - Reads entire open file and calculates checksum results
// final argument is both used to determine which hashes are enabled and to
// pass back the results
// MT-safe.
size_t
pwalk_hash(int fd, char *rbuf, int rbuf_size, struct checksum *checksums)
{
   size_t nbytes, nbytes_t;
   CRC32 *crc32;
   MD5 *md5;

   if (checksums->crc_enabled)
      crc32 = CRC32_init();
   if (checksums->md5_enabled)
      md5 = MD5_init();

   nbytes_t = 0;
   while ((nbytes = pread(fd, rbuf, rbuf_size, nbytes_t)) > 0) {
      if (checksums->crc_enabled)
         CRC32_add(crc32, rbuf, nbytes);
      if (checksums->md5_enabled)
         MD5_add(md5, rbuf, nbytes);
      nbytes_t += nbytes;
   }
   if (checksums->crc_enabled) {
      checksums->crc_str = CRC32_getHash_str(crc32);
      CRC32_free(crc32);
   }
   if (checksums->md5_enabled) {
      checksums->md5_str = MD5_getHash_str(md5);
      MD5_free(md5);
   }
   return nbytes_t;
}
