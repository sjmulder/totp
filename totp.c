#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <assert.h>

/* convert u32 to 4 bytes, big-endian */
static void
unpack32(uint32_t x, uint8_t a[4])
{
	a[0] = (uint8_t)(x >> 24);
	a[1] = (uint8_t)(x >> 16);
	a[2] = (uint8_t)(x >> 8);
	a[3] = (uint8_t)x;
}

/* convert u64 to 8 bytes, big-endian */
static void
unpack64(uint64_t x, uint8_t a[8])
{
	unpack32((uint32_t)(x >> 32), &a[0]);
	unpack32((uint32_t)x, &a[4]);
}

/* convert 4 bytes to u32, big-endian */
static uint32_t
pack32(const uint8_t a[4])
{
	return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

/* FIPS 180-3 2.2.2 */
static uint32_t
rotl(uint32_t x, int n)
{
	assert(n >= 0); assert(n <= 32);
	return x << n | x >> (32-n);
}

/* FIPS 180-3 6.1.1; clobbers buf; len and cap in bytes */
static void
sha1(uint8_t *buf, size_t len, size_t cap, uint8_t hash[20])
{
	/* 4.2.1, use k[t/20] */
	static const uint32_t k[] = { 0x5A827999, 0x6ED9EBA1,
	    0x8F1BBCDC, 0xCA62C1D6 };

	size_t len2, i,t;		/* len2 = len after padding */
	uint32_t h[5], w[80];		/* hash values, msg schedule */
	uint32_t a,b,c,d,e, f, T;	/* working variables */

	/* 5.1.1 (padding) */
	assert(len < SIZE_MAX-9-63);	/* don't overflow size_t */
	len2 = (len+9+63)/64*64;	/* ceil len+9 to 64 multiple */
	assert(len2 <= cap);

	memset(buf+len, 0, len2-len);
	buf[len] = 1<<7;
	unpack64(len*8, &buf[len2-8]);

	/* 5.3.1 */
	h[0] = 0x67452301; h[1] = 0xEFCDAB89; h[2] = 0x98BADCFE;
	h[3] = 0x10325476; h[4] = 0xC3D2E1F0;

	/* 6.1.2 */
	for (i=0; i < len2/64; i++) {
		for (t=0; t<16; t++)
			w[t] = pack32(&buf[i*64 + t*4]);
		for (; t<80; t++)
			w[t] = rotl(w[t-3]^w[t-8]^w[t-14]^w[t-16], 1);

		a=h[0]; b=h[1]; c=h[2]; d=h[3]; e=h[4];

		for (t=0; t<80; t++) {
			/* 4.1.1 (f function) */
			f = t < 20 ? (b&c) ^ (~b&d) :
			    t < 40 ? b^c^d :
			    t < 60 ? (b&c) ^ (b&d) ^ (c&d) : b^c^d;

			T = rotl(a,5) + f + e + k[t/20] + w[t];
			e = d; d = c; c = rotl(b,30);
			b = a; a = T;
		}

		h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
	}

	for (i=0; i<5; i++)
		unpack32(h[i], &hash[i*4]);
}

/* RFC 2104; outputs to hash */
static void
hmac_sha1(const uint8_t key[64], const uint8_t *data, size_t len,
    uint8_t hash[20])
{
	uint8_t buf[196];
	size_t i;

	assert(len <= 64);

	for (i=0; i<64; i++) buf[i] = key[i] ^ 0x36;
	memcpy(&buf[64], data, len);
	sha1(buf, 64+len, sizeof(buf), hash);

	for (i=0; i<64; i++) buf[i] = key[i] ^ 0x5C;
	memcpy(&buf[64], hash, 20);
	sha1(buf, 64+20, sizeof(buf), hash);
}

/* RFC 4226 */
static int
hotp(const uint8_t key[64], uint64_t counter)
{
	uint8_t data[8], hash[20];
	uint32_t trunc;

	unpack64(counter, data);
	hmac_sha1(key, data, 8, hash);

	trunc = pack32(&hash[hash[19] & 0xF]) & 0x7FFFFFFF;

	return (int)(trunc % 1000000);
}

/* RFC 6238 */
static int
totp(const uint8_t key[64])
{
	return hotp(key, time(NULL) / 30);
}

/* RFC 4648 */
static size_t
from_base32(const char *s, uint8_t *buf, size_t cap)
{
	size_t i,j;
	uint8_t v[8];
	char c;

	assert(strlen(s) % 8 == 0);
	assert(cap >= (strlen(s)+1)/8*5);

	for (i=0; s[i*8]; i++) {
		for (j=0; j<8; j++)
			if ((c = s[i*8+j]) == '=') v[j] = 0;
			else if (c>='A' && c<='Z') v[j] = c-'A';
			else if (c>='a' && c<='z') v[j] = c-'a';
			else if (c>='2' && c<='7') v[j] = c-'2' + 26;
			else assert(!"bad base32 char");

		buf[i*5]   = (v[0] << 3) | (v[1] >> 2);
		buf[i*5+1] = (v[1] << 6) | (v[2] << 1) | (v[3] >> 4);
		buf[i*5+2] = (v[3] << 4) | (v[4] >> 1);
		buf[i*5+3] = (v[4] << 7) | (v[5] << 2) | (v[6] >> 3);
		buf[i*5+4] = (v[6] << 5) | v[7];

		if (s[i*8+2] == '=') return i*5 + 1;
		if (s[i*8+4] == '=') return i*5 + 2;
		if (s[i*8+5] == '=') return i*5 + 3;
		if (s[i*8+7] == '=') return i*5 + 4;
	}

	return i*5;
}

#ifdef TEST
static void
to_hex(const uint8_t *a, size_t len, char *buf)
{
	size_t i;

	for (i=0; i<len; i++) {
		buf[i*2]   = "0123456789abcdef"[a[i] >> 4];
		buf[i*2+1] = "0123456789abcdef"[a[i] & 0xF];
	}

	buf[len*2] = '\0';
}

static void
test_pack(void)
{
	uint8_t a[8];

	unpack32(0x12345678, a);
	assert(a[0] == 0x12);
	assert(a[1] == 0x34);
	assert(a[2] == 0x56);
	assert(a[3] == 0x78);

	unpack64(0x123456789ABCDEF0, a);
	assert(a[0] == 0x12);
	assert(a[1] == 0x34);
	assert(a[2] == 0x56);
	assert(a[3] == 0x78);
	assert(a[4] == 0x9A);
	assert(a[5] == 0xBC);
	assert(a[6] == 0xDE);
	assert(a[7] == 0xF0);

	assert(pack32(a) == 0x12345678);
}

static void
test_sha1(void)
{
	uint8_t buf[512], hash[20];
	char str[41];

	buf[0] = 0;
	sha1(buf, 0, sizeof(buf), hash);
	to_hex(hash, 20, str);
	assert(!strcmp(str,
	    "da39a3ee5e6b4b0d3255bfef95601890afd80709"));

	snprintf((char *)buf, sizeof(buf), "%s", "abc");
	sha1(buf, strlen((char *)buf), sizeof(buf), hash);
	to_hex(hash, 20, str);
	assert(!strcmp(str,
	    "a9993e364706816aba3e25717850c26c9cd0d89d"));

	snprintf((char *)buf, sizeof(buf), "%s",
	    "The quick brown fox jumps over the lazy dog");
	sha1(buf, strlen((char *)buf), sizeof(buf), hash);
	to_hex(hash, 20, str);
	assert(!strcmp(str,
	    "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"));
}

static void
test_hmac_sha1(void)
{
	uint8_t key[64], text[64], hash[20];
	char str[41];
	size_t i;

	/* RFC 2202 */
	memset(key, 0, sizeof(key));
	memset(text, 0, sizeof(text));
	for (i=0; i<20; i++) key[i] = 0xAA;
	for (i=0; i<50; i++) text[i] = 0xDD;

	hmac_sha1(key, text, 50, hash);
	to_hex(hash, 20, str);
	assert(!strcmp(str,
	    "125d7342b9ac11cd91a39af48aa17b4f63f175d3"));
}

static void
test_hotp(void)
{
	/* Appendix D */
	static const uint8_t secret[64] = {
	    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	    0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
	    0x37, 0x38, 0x39, 0x30 };
	
	assert(hotp(secret, 0) == 755224);
	assert(hotp(secret, 1) == 287082);
	assert(hotp(secret, 2) == 359152);
}

static void
test_from_base64(void)
{
	uint8_t buf[10];

	assert(from_base32("MZxw6===", buf, sizeof(buf)) == 3);
	assert(from_base32("MZxw6YQ=", buf, sizeof(buf)) == 4);
	assert(from_base32("MZxw6YTB", buf, sizeof(buf)) == 5);
	assert(from_base32("MZxw6YTBOI======", buf, sizeof(buf)) == 6);

	assert(!strncmp("foobar", (char *)buf, 6));
}

int
main()
{
	test_pack();
	test_sha1();
	test_hmac_sha1();
	test_hotp();
	test_from_base64();

	(void)totp;

	return 0;
}
#else
int
main(int argc, char **argv)
{
	const char *seed;
	size_t len, i;
	uint8_t key[64];

	if (argc != 2) {
		fprintf(stderr, "usage: totp [seed in base32]\n");
		return 64; /* EX_USAGE */
	}

	seed = argv[1];
	len = strlen(seed);

	if (len % 8) {
		fprintf(stderr, "seed must be a multiple of 8 long\n");
		return 64; /* EX_USAGE */
	}

	if (len > sizeof(key)/5*8) {
		fprintf(stderr, "seed is too long\n");
		return 64; /* EX_USAGE */
	}

	for (i=0; seed[i]; i++)
		if (seed[i] != '=' &&
		    (seed[i] < 'A' || seed[i] > 'Z') &&
		    (seed[i] < 'a' || seed[i] > 'z') &&
		    (seed[i] < '2' || seed[i] > '7')) {
			fprintf(stderr, "seed is invalid base64\n");
			return 64; /* EX_USAGE */
		}
	
	memset(key, 0, sizeof(key));
	from_base32(seed, key, sizeof(key));

	printf("%d\n", totp(key));
	return 0;
}
#endif
