# Makefile for proxydlp + dnslog on MinGW-w64

CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -O2 -I$(PWD)
LDFLAGS = -L$(PWD) -lWinDivert -lws2_32

OBJS = proxydlp.o dnslog.o

all: proxydlp.exe

proxydlp.exe: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

proxydlp.o: proxydlp.c dnslog.h
	$(CC) $(CFLAGS) -c proxydlp.c

dnslog.o: dnslog.c dnslog.h
	$(CC) $(CFLAGS) -c dnslog.c

clean:
	rm -f *.o proxydlp.exe
