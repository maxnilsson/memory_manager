#ifndef MEMORY_MANAGER_H
#define MEMORY_MANAGER_H


#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


// Initierar en sammanhängande minnespool av exakt 'size' byte.
// Returnerar inget; fel skrivs till stderr och poolen blir NULL om init misslyckas.
void mem_init(size_t size);


// Allokerar 'size' byte ur poolen. Returnerar NULL om det inte får plats.
void* mem_alloc(size_t size);


// Frigör ett block erhållet från mem_alloc/mem_resize. Säkert att anropa med NULL.
// Dubbel-free och ogiltiga pekare upptäcks och rapporteras till stderr.
void mem_free(void* block);


// Ändrar storlek på ett block ("realloc"). Kan flytta blocket.
// Om block==NULL → som mem_alloc(size). Om size==0 → som mem_free(block) och returnerar NULL.
void* mem_resize(void* block, size_t size);


// Avallokerar hela poolen (OS-free). Ska kallas när du är klar.
void mem_deinit(void);


// Nyttiga debug‑/statistikfunktioner (valfria för testning)
size_t mem_total_size(void); // bytes i poolen totalt
size_t mem_free_bytes(void); // summering av fria bytes (payload)
size_t mem_largest_free_block(void); // största fria payload‑block


#ifdef __cplusplus
}
#endif


#endif // MEMORY_MANAGER_H