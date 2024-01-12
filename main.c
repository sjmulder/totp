#include <stdio.h>
#include <string.h>
#include <time.h>
#include "totp.h"

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

	printf("%d\n", totp(key, time(NULL)));
	return 0;
}
