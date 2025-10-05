#ifndef LINKED_LIST_H
#define LINKED_LIST_H


#include <stdint.h>
#include <stddef.h>


typedef struct Node {
uint16_t data; // 16-bitars nyttolast
struct Node* next; // enkel-länkad
} Node;


// Initierar listan och underliggande minnespool (via mem_init).
void list_init(Node** head, size_t pool_size);


// Infogar node i slutet (tail). Använder mem_alloc.
void list_insert(Node** head, uint16_t data);


// Infogar direkt efter given node.
void list_insert_after(Node* prev_node, uint16_t data);


// Infogar direkt före given node. Hanterar fallet när next_node är head.
void list_insert_before(Node** head, Node* next_node, uint16_t data);


// Raderar första node vars data matchar.
void list_delete(Node** head, uint16_t data);


// Linjär sökning efter 'data'. Returnerar pekare eller NULL.
Node* list_search(Node** head, uint16_t data);


// Skriver listan som [a, b, c] till stdout.
void list_display(Node** head);


// Skriver ett intervall inklusivt från start_node till end_node.
// Om start_node==NULL börjar från head. Om end_node==NULL slutar vid listans slut.
void list_display_range(Node** head, Node* start_node, Node* end_node);


// Räknar noder.
int list_count_nodes(Node** head);


// Frigör alla noder (via mem_free) och sätter *head=NULL.
void list_cleanup(Node** head);


#endif // LINKED_LIST_H