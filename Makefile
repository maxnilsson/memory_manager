CC=gcc
CFLAGS=-Wall -fPIC -g
LDFLAGS=-shared -ldl

all: libmymalloc.so test_memory_manager test_linked_list

# ------------------------
# Build preload library
# ------------------------
libmymalloc.so: memory_manager.o
	$(CC) -o $@ $^ $(LDFLAGS)

memory_manager.o: memory_manager.c memory_manager.h
	$(CC) $(CFLAGS) -c memory_manager.c -o memory_manager.o

# ------------------------
# Test program for memory_manager
# ------------------------
test_memory_manager: test_memory_manager.c memory_manager.o
	$(CC) $(CFLAGS) -o $@ test_memory_manager.c memory_manager.o -ldl

# ------------------------
# Test program for linked_list
# ------------------------
test_linked_list: test_linked_list.c linked_list.c linked_list.h
	$(CC) $(CFLAGS) -o $@ test_linked_list.c linked_list.c

# ------------------------
clean:
	rm -f *.o libmymalloc.so test_memory_manager test_linked_list
