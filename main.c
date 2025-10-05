#include "memory_manager.h"
#include "linked_list.h"

#include <stdio.h>
#include <stdlib.h>   // strtoull
#include <stdint.h>

int main(int argc, char* argv[]) {
    size_t pool = 4096; // default poolstorlek
    if (argc > 1) {
        pool = (size_t)strtoull(argv[1], NULL, 10);
    }

    Node* head = NULL;
    list_init(&head, pool);

    printf("Init pool = %zu bytes\n", pool);

    list_insert(&head, 10);
    list_insert(&head, 20);
    list_insert(&head, 30);
    list_insert(&head, 40);

    printf("List: ");
    list_display(&head);

    Node* n20 = list_search(&head, 20);
    if (n20) list_insert_after(n20, 25);

    printf("After insert_after(20,25): ");
    list_display(&head);

    Node* n30 = list_search(&head, 30);
    if (n30) list_insert_before(&head, n30, 28);

    printf("After insert_before(30,28): ");
    list_display(&head);

    list_delete(&head, 10);
    printf("After delete(10): ");
    list_display(&head);

    printf("Count = %d\n", list_count_nodes(&head));

    printf("Range (from head to node 30): ");
    list_display_range(&head, head, n30);

    list_cleanup(&head);

    printf("After cleanup, count = %d\n", list_count_nodes(&head));

    mem_deinit();
    return 0;
}
