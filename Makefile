.PHONY: all, clean

CC=gcc
CFLAGS= -Wall -std=c11 -lgcrypt -largtable2
PROGRAM_NAME=pastor

default: $(PROGRAM_NAME)

$(PROGRAM_NAME): $(PROGRAM_NAME).c
	$(CC) $(CFLAGS) $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(PROGRAM_NAME)
