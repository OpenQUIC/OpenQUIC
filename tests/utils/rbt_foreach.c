#include "utils/rbt.h"
#include <malloc.h>

typedef struct quic_rbt_test_s quic_rbt_test_t;
struct quic_rbt_test_s {
    QUIC_RBT_UINT64_FIELDS
};

int main() {
    quic_rbt_t *root = quic_rbt_nil;

    int i;
    for (i = 0; i < 999; i++) {
        quic_rbt_test_t *test1 = malloc(sizeof(quic_rbt_test_t));
        quic_rbt_init(test1);
        test1->key = i;

        quic_rbt_insert(&root, test1, quic_rbt_uint64_comparer);
    }
    quic_rbt_test_t *iter = NULL;
    quic_rbt_foreach(iter, root) {
        printf("%ld\n", iter->key);
    }

    return 0;
}
