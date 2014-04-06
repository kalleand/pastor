.PHONY: all, clean

CC=gcc
CFLAGS= -Wall -std=c11 -lgcrypt -largtable2

default: pastor

pastor: pastor.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm pastor
