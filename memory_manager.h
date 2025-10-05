#ifndef MEMORY_MANAGER_H
#define MEMORY_MANAGER_H

#include <stddef.h>

void   mem_init(size_t size);
void*  mem_alloc(size_t size);
void   mem_free(void* block);
void*  mem_resize(void* block, size_t size);
void   mem_deinit(void);

size_t mem_total_size(void);
size_t mem_free_bytes(void);
size_t mem_largest_free_block(void);

#endif

