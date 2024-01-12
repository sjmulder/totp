PROGS?=		totp test
PROGS.cross?=	totp32.exe test32.exe \
		totp64.exe test64.exe

SRC.totp=	totp.c main.c
SRC.test=	totp.c test.c

CC.win32?=	i686-w64-mingw32-gcc
CC.win64?=	x86_64-w64-mingw32-gcc

CFLAGS+=	-Wall -Wextra

all:   ${PROGS}
cross: ${PROGS.cross}

clean:
	rm -f ${PROGS} ${PROGS.cross} *.o

check: all
	./test

cross-check: cross
	wine ./test32.exe
	wine ./test64.exe

totp: ${SRC.totp} *.h
	${LINK.c} -o $@ ${SRC.totp}

totp32.exe: ${SRC.totp} *.h
	${CC.win32} ${CFLAGS} -o $@ ${SRC.totp}

totp64.exe: ${SRC.totp} *.h
	${CC.win64} ${CFLAGS} -o $@ ${SRC.totp}

test: ${SRC.test} *.h
	${LINK.c} -o test ${SRC.test}

test32.exe: ${SRC.test} *.h
	${CC.win32} ${CFLAGS} -o $@ ${SRC.test}

test64.exe: ${SRC.test} *.h
	${CC.win64} ${CFLAGS} -o $@ ${SRC.test}

.PHONY: all cross clean check cross-check
