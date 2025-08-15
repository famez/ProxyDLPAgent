# Makefile for proxydlp + dnslog on MinGW-w64

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Wall -O2 -I../include/
#CFLAGS = -Wall -O0 -g -I$(PWD)          # -O0 disables optimizations, -g adds debug symbols
LDFLAGS = -L../libs/ -lWinDivert -lws2_32 -lcurl

SRC  = $(wildcard *.c)
OBJS = $(SRC:.c=.o)

all: proxydlp.exe

proxydlp.exe: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o proxydlp.exe
