# Makefile for proxydlp + dnslog on MinGW-w64

CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -O2 -I$(PWD)
#CFLAGS = -Wall -O0 -g -I$(PWD)          # -O0 disables optimizations, -g adds debug symbols
LDFLAGS = -L$(PWD) -lWinDivert -lws2_32

OBJS = proxydlp.o dns.o

all: proxydlp.exe

proxydlp.exe: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

proxydlp.o: proxydlp.c
	$(CC) $(CFLAGS) -c proxydlp.c

dns.o: dns.c
	$(CC) $(CFLAGS) -c dns.c

clean:
	rm -f *.o proxydlp.exe
