CC=gcc -m32
NASM=nasm -f elf32
CFLAGS=-c -Wall
LFLAGS=-lelf -lcrypto -lcapstone

all: example

example: proj1_example_file.o doubleSum.o
	$(CC) doubleSum.o proj1_example_file.o -o example $(LFLAGS)

proj1_example_file.o: proj1_example_file.c proj1_example_file.h
	$(CC) $(CFLAGS) proj1_example_file.c

doubleSum.o: doubleSum.asm
	$(NASM) doubleSum.asm

.PHONY clean:
	rm *o example mydata.bin
