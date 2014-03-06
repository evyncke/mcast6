CFLAGS = -Wall

all: mcast6

mcast6: mcast6.o hash.o
	${CC} ${CFLAGS} mcast6.o hash.o -lpcap -o mcast6

mcast6.o: mcast6.c hash.h

hash.o: hash.c hash.h

clean:
	rm -f mcast6 *.o

