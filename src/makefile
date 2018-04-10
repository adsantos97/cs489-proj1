CC=gcc -m32
NASM=nasm -f elf32
CFLAGS=-c -Wall
LFLAGS=-lelf -lcrypto -lcapstone

all: analyze

analyze: analyzer.o doubleSum.o
	$(CC) doubleSum.o analyzer.o -o ../bin/analyze $(LFLAGS)

doubleSum.o: doubleSum.asm
	$(NASM) doubleSum.asm

analyzer.o: analyzer.c analyzer.h
	$(CC) $(CFLAGS) analyzer.c

.PHONY clean:
	rm *o ../bin/analyze ../bin/mydata.bin
