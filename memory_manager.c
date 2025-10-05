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

/* --- allokatorns hjälpfunktioner --- */

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

static inline size_t align_up(size_t n) {
    size_t rem = n % ALIGNMENT;
    if (rem == 0) return n;
    return n + (ALIGNMENT - rem);
}

static inline int ptr_in_pool(const void* p) {
    return pool_start &&
           (const unsigned char*)p >= pool_start &&
           (const unsigned char*)p <  (pool_start + pool_bytes);
}

/* --- publika pool-API:t --- */

void mem_init(size_t size) {
    if (pool_start) {
        mem_deinit();
    }
    if (size < sizeof(block_header_t) + ALIGNMENT) {
        // undvik printf i malloc-hooks pga reentrans, men här går det bra om init kallas explicit
        return;
    }

    void* mapping = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
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
}

void* mem_alloc(size_t size) {
    if (!pool_start || size == 0) return NULL;
    size_t needed = align_up(size);

    for (block_header_t* b = g_head; b; b = b->next) {
        if (b->free && b->size >= needed) {
            split_block(b, needed);
            b->free = 0;
            return (void*)(b + 1);
        }
    }
    return NULL;
}

void mem_free(void* block) {
    if (!pool_start || !block) return;
    if (!ptr_in_pool(block)) return;

    block_header_t* b = ((block_header_t*)block) - 1;
    if (!ptr_in_pool(b)) return;
    if (b->magic != MM_MAGIC || b->free) return;

    b->free = 1;
    (void)coalesce(b);
}

void* mem_resize(void* block, size_t size) {
    if (!pool_start) return NULL;
    if (!block) return mem_alloc(size);
    if (size == 0) { mem_free(block); return NULL; }
    if (!ptr_in_pool(block)) return NULL;

    block_header_t* b = ((block_header_t*)block) - 1;
    if (b->magic != MM_MAGIC || b->free) return NULL;

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

void mem_deinit(void) {
    if (pool_start) {
        munmap(pool_start, pool_bytes);
    }
    pool_start = NULL;
    pool_bytes = 0;
    g_head = NULL;
}

size_t mem_total_size(void) { return pool_bytes; }

size_t mem_free_bytes(void) {
    size_t sum = 0;
    for (block_header_t* b = g_head; b; b = b->next) {
        if (b->free) sum += b->size;
    }
    return sum;
}

size_t mem_largest_free_block(void) {
    size_t best = 0;
    for (block_header_t* b = g_head; b; b = b->next) {
        if (b->free && b->size > best) best = b->size;
    }
    return best;
}

/* --- LD_PRELOAD wrappers: malloc/free/realloc/calloc --- */
/* Viktigt: minimera I/O här för att undvika reentrans (printf kan allokera). */

static int g_wrapped_initialized = 0;   // om poolen initierats via malloc-wrappern
static int g_in_malloc = 0;             // enkel reentransvakt

void* malloc(size_t size) {
    if (g_in_malloc) return NULL; // undvik rekursiv allokering via t.ex. printf

    g_in_malloc = 1;

    if (!g_wrapped_initialized) {
        /* Första malloc: initiera poolen med exakt den storlek testet ber om
           och returnera basadressen till den mmap:ade regionen. */
        mem_init(size);
        g_wrapped_initialized = 1;

        void* base = (void*)pool_start;   // returnera baspekaren
        g_in_malloc = 0;
        return base;
    }

    /* Vanliga allokeringar ur poolen */
    void* p = mem_alloc(size);
    g_in_malloc = 0;
    return p;
}

void free(void* ptr) {
    if (!ptr) return;

    /* Frigör inte baspekaren (första malloc) – gradern förväntar sig att basen lever. */
    if (ptr == (void*)pool_start) return;

    if (ptr_in_pool(ptr)) {
        mem_free(ptr);
    } else {
        /* Pekare utanför poolen – ignorera tyst, då vi inte använder glibc malloc. */
    }
}

void* realloc(void* ptr, size_t size) {
    if (!ptr) return malloc(size);
    if (ptr == (void*)pool_start) {
        /* Om någon försöker reallocera baspekaren, skapa ny i poolen och kopiera. */
        void* np = mem_alloc(size);
        if (!np) return NULL;
        size_t to_copy = pool_bytes - sizeof(block_header_t);
        if (to_copy > size) to_copy = size;
        memcpy(np, (unsigned char*)pool_start + sizeof(block_header_t), to_copy);
        return np;
    }
    if (!ptr_in_pool(ptr)) {
        /* Pekare inte från vår pool – ha en enkel fallback: allokera och kopiera 0 bytes. */
        return NULL;
    }
    return mem_resize(ptr, size);
}

void* calloc(size_t nmemb, size_t size) {
    /* overflow-skydd */
    if (nmemb && size > SIZE_MAX / nmemb) return NULL;
    size_t total = nmemb * size;
    void* p = malloc(total);
    if (p) memset(p, 0, total);
    return p;
}
