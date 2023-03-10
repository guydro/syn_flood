CC = gcc
LNK = gcc

LNKFLAGS =  -ggdb -Wall -O3
CFLAGS = -ggdb -Wall -m64 -O0


all: main

%.o: %.c
		$(CC) $(CFLAGS) $< -c

main : main.o
		$(LNK) -o $@ $^ $(LNKFLAGS)


clean:
	-rm *.o