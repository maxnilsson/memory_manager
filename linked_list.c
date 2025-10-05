#include "linked_list.h"
#include "memory_manager.h"
#include <stdio.h>

static Node* new_node(uint16_t data) {
    Node* n = (Node*)mem_alloc(sizeof(Node));
    if (!n) {
        fprintf(stderr, "list: out of memory (allocating Node)\n");
        return NULL;
    }
    n->data = data;
    n->next = NULL;
    return n;
}

void list_init(Node** head, size_t pool_size) {
    if (!head) return;
    *head = NULL;
    mem_init(pool_size);
}

void list_insert(Node** head, uint16_t data) {
    if (!head) return;
    Node* n = new_node(data);
    if (!n) return;
    if (*head == NULL) {
        *head = n;
        return;
    }
    Node* cur = *head;
    while (cur->next) cur = cur->next;
    cur->next = n;
}

void list_insert_after(Node* prev_node, uint16_t data) {
    if (!prev_node) {
        fprintf(stderr, "list_insert_after: prev_node is NULL\n");
        return;
    }
    Node* n = new_node(data);
    if (!n) return;
    n->next = prev_node->next;
    prev_node->next = n;
}

void list_insert_before(Node** head, Node* next_node, uint16_t data) {
    if (!head || !next_node) {
        fprintf(stderr, "list_insert_before: bad arguments\n");
        return;
    }
    Node* n = new_node(data);
    if (!n) return;
    if (*head == next_node) {
        n->next = *head;
        *head = n;
        return;
    }
    Node* prev = *head;
    while (prev && prev->next != next_node) prev = prev->next;
    if (!prev) {
        fprintf(stderr, "list_insert_before: next_node not in list\n");
        mem_free(n);
        return;
    }
    n->next = next_node;
    prev->next = n;
}

void list_delete(Node** head, uint16_t data) {
    if (!head || !*head) {
        fprintf(stderr, "list_delete: empty list\n");
        return;
    }
    Node* cur = *head;
    Node* prev = NULL;
    while (cur && cur->data != data) {
        prev = cur;
        cur = cur->next;
    }
    if (!cur) {
        fprintf(stderr, "list_delete: value %u not found\n", (unsigned)data);
        return;
    }
    if (prev) prev->next = cur->next;
    else *head = cur->next;
    mem_free(cur);
}

Node* list_search(Node** head, uint16_t data) {
    if (!head) return NULL;
    for (Node* cur = *head; cur; cur = cur->next) {
        if (cur->data == data) return cur;
    }
    return NULL;
}

void list_display(Node** head) {
    if (!head) return;
    printf("[");
    Node* cur = *head;
    while (cur) {
        printf("%u", (unsigned)cur->data);
        if (cur->next) printf(", ");
        cur = cur->next;
    }
    printf("]\n");
}

void list_display_range(Node** head, Node* start_node, Node* end_node) {
    if (!head) return;
    Node* cur = *head;

    if (start_node) {
        while (cur && cur != start_node) cur = cur->next;
        if (!cur) { printf("[]\n"); return; }
    }

    printf("[");
    int first = 1;
    while (cur) {
        if (!first) printf(", ");
        first = 0;
        printf("%u", (unsigned)cur->data);
        if (cur == end_node) break;
        cur = cur->next;
    }
    printf("]\n");
}

int list_count_nodes(Node** head) {
    if (!head) return 0;
    int c = 0;
    for (Node* cur = *head; cur; cur = cur->next) ++c;
    return c;
}

void list_cleanup(Node** head) {
    if (!head) return;
    Node* cur = *head;
    while (cur) {
        Node* nxt = cur->next;
        mem_free(cur);
        cur = nxt;
    }
    *head = NULL;
}
