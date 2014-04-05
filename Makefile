.PHONY: all, clean

CC=gcc
CFLAGS= -Wall -std=c11 -lgcrypt

default: pastor

pastor: pastor.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm pastor
