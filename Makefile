CC=gcc
CFLAGS=-Wall -fPIC
LDFLAGS=-shared -ldl

all: libmymalloc.so

libmymalloc.so: memory_manager.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

memory_manager.o: memory_manager.c memory_manager.h
	$(CC) $(CFLAGS) -c memory_manager.c -o memory_manager.o

clean:
	rm -f *.o libmymalloc.so test_memory_manager test_linked_list
