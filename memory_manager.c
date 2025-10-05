#include "memory_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdalign.h>
#include <sys/mman.h>
#include <unistd.h>

#define MM_MAGIC 0xC0FFEE42u
#define ALIGNMENT ((size_t)alignof(max_align_t))

typedef struct block_header {
    size_t size;                 // payload-storlek i bytes
    int    free;                 // 1 = fri, 0 = allokerad
    struct block_header* next;   // nästa block i poolen
    struct block_header* prev;   // föregående block i poolen
    uint32_t magic;              // enkel korruptions-/valideringskontroll
} block_header_t;

static block_header_t* g_head = NULL;      // första blocket i poolen
static unsigned char* pool_start = NULL;   // poolens råa startadress (mmap)
static size_t pool_bytes = 0;              // totalt antal bytes i poolen

/* slår ihop ett fritt block med fria grannar */
static block_header_t* coalesce(block_header_t* b) {
    if (b->prev && b->prev->free) {
        block_header_t* p = b->prev;
        p->size += sizeof(block_header_t) + b->size;
        p->next = b->next;
        if (b->next) b->next->prev = p;
        b = p;
    }
    if (b->next && b->next->free) {
        block_header_t* n = b->next;
        b->size += sizeof(block_header_t) + n->size;
        b->next = n->next;
        if (n->next) n->next->prev = b;
    }
    return b;
}

/* delar blocket i två om plats finns */
static void split_block(block_header_t* b, size_t needed) {
    size_t total = b->size;
    if (total >= needed + sizeof(block_header_t) + ALIGNMENT) {
        unsigned char* payload_start = (unsigned char*)(b + 1);
        block_header_t* newb = (block_header_t*)(payload_start + needed);
        newb->size = total - needed - sizeof(block_header_t);
        newb->free = 1;
        newb->magic = MM_MAGIC;
        newb->prev = b;
        newb->next = b->next;
        if (newb->next) newb->next->prev = newb;
        b->next = newb;
        b->size = needed;
    }
}

/* rundar upp till korrekt alignment */
static inline size_t align_up(size_t n) {
    size_t rem = n % ALIGNMENT;
    if (rem == 0) return n;
    return n + (ALIGNMENT - rem);
}

/* kollar om pekaren ligger i poolen */
static inline int ptr_in_pool(const void* p) {
    return pool_start &&
           (const unsigned char*)p >= pool_start &&
           (const unsigned char*)p <  (pool_start + pool_bytes);
}

/* startar poolen och skapar ett stort fritt block */
void mem_init(size_t size) {
    if (pool_start) {
        mem_deinit();
    }
    if (size < sizeof(block_header_t) + ALIGNMENT) {
        fprintf(stderr, "mem_init: size too small (min %zu)\n",
                sizeof(block_header_t) + ALIGNMENT);
        return;
    }

    void* mapping = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("mem_init: mmap failed");
        return;
    }

    pool_start = (unsigned char*)mapping;
    pool_bytes = size;

    g_head = (block_header_t*)pool_start;
    g_head->size = size - sizeof(block_header_t);
    g_head->free = 1;
    g_head->next = NULL;
    g_head->prev = NULL;
    g_head->magic = MM_MAGIC;
}  // <-- viktig! avslutar mem_init

/* allokerar 'size' bytes från poolen */
void* mem_alloc(size_t size) {
    if (!pool_start) {
        fprintf(stderr, "mem_alloc: pool not initialized\n");
        return NULL;
    }
    if (size == 0) return NULL;

    size_t needed = align_up(size);

    for (block_header_t* b = g_head; b; b = b->next) {
        if (b->free && b->size >= needed) {
            split_block(b, needed);
            b->free = 0;
            return (void*)(b + 1);
        }
    }
    return NULL; // ingen plats
}

/* frigör block och försöker slå ihop med grannar */
void mem_free(void* block) {
    if (!block) return;
    if (!pool_start) {
        fprintf(stderr, "mem_free: pool not initialized\n");
        return;
    }
    if (!ptr_in_pool(block)) {
        fprintf(stderr, "mem_free: pointer not in pool\n");
        return;
    }
    block_header_t* b = ((block_header_t*)block) - 1;
    if (!ptr_in_pool(b)) {
        fprintf(stderr, "mem_free: corrupt header\n");
        return;
    }
    if (b->magic != MM_MAGIC) {
        fprintf(stderr, "mem_free: magic mismatch (corruption?)\n");
        return;
    }
    if (b->free) {
        fprintf(stderr, "mem_free: double free detected\n");
        return;
    }
    b->free = 1;
    (void)coalesce(b);
}

/* ändrar storlek */
void* mem_resize(void* block, size_t size) {
    if (!pool_start) {
        fprintf(stderr, "mem_resize: pool not initialized\n");
        return NULL;
    }
    if (block == NULL) return mem_alloc(size);
    if (size == 0) {
        mem_free(block);
        return NULL;
    }
    if (!ptr_in_pool(block)) {
        fprintf(stderr, "mem_resize: pointer not in pool\n");
        return NULL;
    }

    block_header_t* b = ((block_header_t*)block) - 1;
    if (b->magic != MM_MAGIC || b->free) {
        fprintf(stderr, "mem_resize: invalid block\n");
        return NULL;
    }

    size_t needed = align_up(size);

    if (b->size >= needed) {
        split_block(b, needed);
        return block;
    }

    if (b->next && b->next->free) {
        size_t combined = b->size + sizeof(block_header_t) + b->next->size;
        if (combined >= needed) {
            b->size = combined;
            block_header_t* n = b->next;
            b->next = n->next;
            if (b->next) b->next->prev = b;
            split_block(b, needed);
            return (void*)(b + 1);
        }
    }

    void* newp = mem_alloc(size);
    if (!newp) return NULL;
    memcpy(newp, block, b->size < needed ? b->size : needed);
    mem_free(block);
    return newp;
}

/* stänger poolen och nollställer allt */
void mem_deinit(void) {
    if (pool_start) {
        if (munmap(pool_start, pool_bytes) != 0) {
            perror("mem_deinit: munmap failed");
        }
    }
    pool_start = NULL;
    pool_bytes = 0;
    g_head = NULL;
}

/* ger totala poolstorleken i bytes */
size_t mem_total_size(void) {
    return pool_bytes;
}

/* ger antal lediga bytes i poolen */
size_t mem_free_bytes(void) {
    size_t sum = 0;
    for (block_header_t* b = g_head; b; b = b->next) {
        if (b->free) sum += b->size;
    }
    return sum;
}

/* ger storlek på största lediga blocket */
size_t mem_largest_free_block(void) {
    size_t best = 0;
    for (block_header_t* b = g_head; b; b = b->next) {
        if (b->free && b->size > best) best = b->size;
    }
    return best;
}
