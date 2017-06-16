
#include "swoole.h"
#include "heap.h"
#include "tests.h"

typedef struct node_t
{
    int pri;
    int val;
} node_t;

bool heap()
{
    swHeap *pq;
    node_t *ns;
    node_t *n;

#define SIZE    100

    pq = swHeap_new(SIZE, SW_MAX_HEAP);
    if (!pq)
    {
        return 1;
    }

    int i;
    for (i = 0; i < SIZE - 1; i++)
    {
        int pri = swoole_system_random(10000, 99999);
        ns = malloc(sizeof(node_t));
        ns->val = i;
        ns->pri = pri;
        swHeap_insert(pq, pri, ns);
    }

    while ((n = swHeap_pop(pq)))
    {
        printf("pop: %d [%d]\n", n->pri, n->val);
        free(n);
    }

    swHeap_free(pq);
    free(ns);

    return 0;
}
