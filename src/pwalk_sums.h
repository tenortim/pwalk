#ifndef PWALK_SUMS_H
#define PWALK_SUMS_H 1

#include <stdbool.h>
#include <stddef.h>

struct checksum {
    int crc_enabled;
    char *crc_str;
    int md5_enabled;
    char *md5_str;
};

size_t pwalk_hash(int fd, char *rbuf, int rbuf_size, struct checksum *checksums);

#define MD5_SUM_ZERO "d41d8cd98f00b204e9800998ecf8427e"
#define SHA1_SUM_ZERO "da39a3ee5e6b4b0d3255bfef95601890afd80709"
#define SHA224_SUM_ZERO "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
#define SHA256_SUM_ZERO "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define SHA384_SUM_ZERO "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"

#endif // PWALK_SUMS_H
