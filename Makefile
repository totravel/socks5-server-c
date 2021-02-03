
CC = gcc
CFLAGS = -c -W -std=gnu99
CFLAGS += $(CFLAG)
LDFLAGS = -lm

all: server

server: log.o util.o lib.o proto.o main.o
	$(CC) $(LDFLAGS) $^ -o $@

log.o: log.c log.h
	$(CC) $(CFLAGS) $< -o $@

util.o: util.c log.h util.h
	$(CC) $(CFLAGS) $< -o $@

lib.o: lib.c log.h lib.h
	$(CC) $(CFLAGS) $< -o $@

proto.o: proto.c log.h util.h proto.h
	$(CC) $(CFLAGS) $< -o $@

main.o: main.c log.h util.h lib.h main.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o
	rm -f server
