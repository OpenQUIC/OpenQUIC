#include "utils/rbt.h"
#include <malloc.h>

typedef struct quic_rbt_test_s quic_rbt_test_t;
struct quic_rbt_test_s {
    QUIC_RBT_UINT64_FIELDS
};

int main() {
    quic_rbt_t *root = quic_rbt_nil;

    int i;
    for (i = 0; i < 255; i++) {
        quic_rbt_test_t *test1 = malloc(sizeof(quic_rbt_test_t));
        quic_rbt_init(test1);
        test1->key = i;

        quic_rbt_insert(&root, test1, quic_rbt_uint64_comparer);
    }

    uint64_t key;
    quic_rbt_test_t *val;
    for (i = 0; i < 255; i++) {
        key = i;
        val = (quic_rbt_test_t *) quic_rbt_find(root, &key, quic_rbt_uint64_key_comparer);

        printf("%ld\n", val->key);
    }

    key = 10;
    val = (quic_rbt_test_t *) quic_rbt_find(root, &key, quic_rbt_uint64_key_comparer);
    printf("%d\n", quic_rbt_is_nil(val));

    for (i = 0; i < 255; i++) {
        key = i;
        val = (quic_rbt_test_t *) quic_rbt_find(root, &key, quic_rbt_uint64_key_comparer);
        printf("%d\n", quic_rbt_is_nil(val));
        quic_rbt_remove(&root, &val);

        val = (quic_rbt_test_t *) quic_rbt_find(root, &key, quic_rbt_uint64_key_comparer);
        printf("hehe %d\n", quic_rbt_is_nil(val));
    }

    return 0;
}
