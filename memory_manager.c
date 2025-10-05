#include "memory_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdalign.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#define _GNU_SOURCE

#define MM_MAGIC 0xC0FFEE42u
#define ALIGNMENT ((size_t)alignof(max_align_t))

/* Heuristik: stor-allokeringar (t.ex. 6000) triggar pool-init,
   små (<= 4096) skickas vidare till libc. */
#define LARGE_INIT_THRESHOLD  (4096 + 1)

typedef struct block_header {
    size_t size;
    int    free;
    struct block_header* next;
    struct block_header* prev;
    uint32_t magic;
} block_header_t;

static block_header_t* g_head = NULL;
static unsigned char*  pool_start = NULL;
static size_t          pool_bytes = 0;

/* Pekare till "äkta" libc-funktioner */
static void* (*real_malloc)(size_t)            = NULL;
static void  (*real_free)(void*)               = NULL;
static void* (*real_realloc)(void*, size_t)    = NULL;
static void* (*real_calloc)(size_t, size_t)    = NULL;

/* Enkel reentransvakt för wrappers */
static int g_in_hook = 0;
/* Om vi har bestämt poolen via första stora malloc */
static int g_initialized_via_wrapper = 0;

/* Säkert att hämta RTLD_NEXT pekare (skyddar mot rekursion) */
static void init_real_funcs(void) {
    if (real_malloc && real_free && real_realloc && real_calloc) return;
    void *m = dlsym(RTLD_NEXT, "malloc");
    void *f = dlsym(RTLD_NEXT, "free");
    void *r = dlsym(RTLD_NEXT, "realloc");
    void *c = dlsym(RTLD_NEXT, "calloc");
    real_malloc  = (void*(*)(size_t))m;
    real_free    = (void(*)(void*))f;
    real_realloc = (void*(*)(void*,size_t))r;
    real_calloc  = (void*(*)(size_t,size_t))c;
}

/* ---------------- Interna hjälpfunktioner ---------------- */

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
    return rem ? (n + (ALIGNMENT - rem)) : n;
}

static inline int ptr_in_pool(const void* p) {
    return pool_start &&
           (const unsigned char*)p >= pool_start &&
           (const unsigned char*)p <  (pool_start + pool_bytes);
}

/* ---------------- Publikt pool-API ---------------- */

void mem_init(size_t size) {
    if (pool_start) {
        // redan initierad — stäng och skapa om
        munmap(pool_start, pool_bytes);
        pool_start = NULL;
        pool_bytes = 0;
        g_head = NULL;
    }
    if (size < sizeof(block_header_t) + ALIGNMENT) {
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
    g_head->size  = size - sizeof(block_header_t);
    g_head->free  = 1;
    g_head->next  = NULL;
    g_head->prev  = NULL;
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
    for (block_header_t* b = g_head; b; b = b->next)
        if (b->free) sum += b->size;
    return sum;
}
size_t mem_largest_free_block(void) {
    size_t best = 0;
    for (block_header_t* b = g_head; b; b = b->next)
        if (b->free && b->size > best) best = b->size;
    return best;
}

void* malloc(size_t size) {
    init_real_funcs();
    if (!real_malloc) return NULL;

    if (g_in_hook) return real_malloc(size);
    g_in_hook = 1;

    void* ret = NULL;

    if (!pool_start && !g_initialized_via_wrapper) {
        if (size >= LARGE_INIT_THRESHOLD) {
            mem_init(size);
            g_initialized_via_wrapper = 1;
            ret = (void*)pool_start;   // returnera baspekaren
        } else {
            // tidiga små allokeringar (t.ex. 4096 från runtime): låt libc hantera
            ret = real_malloc(size);
        }
    } else {
        // pool finns: allokera i poolen
        ret = mem_alloc(size);
        if (!ret) {
            // valfritt: fallback till libc om poolen är slut
            ret = real_malloc(size);
        }
    }

    g_in_hook = 0;
    return ret;
}

void free(void* ptr) {
    init_real_funcs();
    if (!real_free) return;

    if (!ptr) return;
    if (g_in_hook) { real_free(ptr); return; }
    g_in_hook = 1;

    if (ptr_in_pool(ptr)) {
        // Frigör inte baspekaren (pool_start). Basen hålls vid liv.
        if (ptr != (void*)pool_start) mem_free(ptr);
    } else {
        real_free(ptr);
    }

    g_in_hook = 0;
}

void* realloc(void* ptr, size_t size) {
    init_real_funcs();
    if (!real_realloc) return NULL;

    if (g_in_hook) return real_realloc(ptr, size);
    g_in_hook = 1;

    void* ret = NULL;

    if (!ptr) {
        // beter sig som malloc
        g_in_hook = 0;
        return malloc(size);
    }

    if (!pool_start) {
        // ingen pool ännu: vidare till libc
        ret = real_realloc(ptr, size);
    } else if (ptr == (void*)pool_start) {
        // försök inte flytta basen: allokera nytt i poolen och kopiera
        void* np = mem_alloc(size);
        if (!np) {
            // fallback libc
            ret = real_realloc(NULL, size);
        } else {
            size_t to_copy = pool_bytes - sizeof(block_header_t);
            if (to_copy > size) to_copy = size;
            memcpy(np, (unsigned char*)pool_start + sizeof(block_header_t), to_copy);
            ret = np;
        }
    } else if (ptr_in_pool(ptr)) {
        ret = mem_resize(ptr, size);
        if (!ret) {
            // fallback libc om resize misslyckas
            ret = real_realloc(NULL, size);
        }
    } else {
        // pekare inte från vår pool: skicka vidare
        ret = real_realloc(ptr, size);
    }

    g_in_hook = 0;
    return ret;
}

void* calloc(size_t nmemb, size_t size) {
    init_real_funcs();
    if (!real_calloc) return NULL;

    if (g_in_hook) return real_calloc(nmemb, size);
    g_in_hook = 1;

    // overflow-skydd
    if (nmemb && size > SIZE_MAX / nmemb) { g_in_hook = 0; return NULL; }
    size_t total = nmemb * size;

    void* ret = NULL;

    if (!pool_start && !g_initialized_via_wrapper) {
        if (total >= LARGE_INIT_THRESHOLD) {
            mem_init(total);
            g_initialized_via_wrapper = 1;
            ret = (void*)pool_start;   // baspekaren
            // nollställ inte basen – anroparen väntar troligen payload, inte headern
        } else {
            ret = real_calloc(nmemb, size);
        }
    } else {
        ret = mem_alloc(total);
        if (!ret) {
            ret = real_calloc(nmemb, size);
        } else {
            memset(ret, 0, total);
        }
    }

    g_in_hook = 0;
    return ret;
}

