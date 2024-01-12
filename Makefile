SRC.totp=	totp.c main.c
SRC.test=	totp.c test.c

CFLAGS+=	-Wall -Wextra

all: totp test

clean: ; rm -f totp test *.o
check: all ; ./test

totp: ${SRC.totp} *.h ; ${LINK.c} -o totp ${SRC.totp}
test: ${SRC.test} *.h ; ${LINK.c} -o test ${SRC.test}

.PHONY: all clean check
