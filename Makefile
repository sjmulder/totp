CFLAGS+=	-Wall -Wextra

all: totp test

clean:
	rm -f totp test *.o

check: all
	./test

totp: totp.c
	${LINK.c} -o totp totp.c

test: totp.c
	${LINK.c} -DTEST -o test totp.c

.PHONY: all clean check
