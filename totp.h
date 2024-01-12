#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <assert.h>

/* convert u32 to 4 bytes, big-endian */
static inline void
unpack32(uint32_t x, uint8_t a[4])
{
	a[0] = (uint8_t)(x >> 24);
	a[1] = (uint8_t)(x >> 16);
	a[2] = (uint8_t)(x >> 8);
	a[3] = (uint8_t)x;
}

/* convert u64 to 8 bytes, big-endian */
static inline void
unpack64(uint64_t x, uint8_t a[8])
{
	unpack32((uint32_t)(x >> 32), &a[0]);
	unpack32((uint32_t)x, &a[4]);
}

/* convert 4 bytes to u32, big-endian */
static inline uint32_t
pack32(const uint8_t a[4])
{
	return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

/* FIPS 180-3 2.2.2 */
static inline uint32_t
rotl(uint32_t x, int n)
{
	assert(n >= 0); assert(n <= 32);
	return x << n | x >> (32-n);
}

/* clobbers buf; len and cap in bytes */
void sha1(uint8_t *buf, size_t len, size_t cap, uint8_t hash[20]);

/* outputs to hash */
void hmac_sha1(const uint8_t key[64], const uint8_t *data, size_t len,
    uint8_t hash[20]);

/* returns code */
int hotp(const uint8_t key[64], uint64_t counter);
int totp(const uint8_t key[64], uint64_t time);

/* writes to buf, returns length */
size_t from_base32(const char *s, uint8_t *buf, size_t cap);
