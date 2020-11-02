#include "utils/rbt.h"
#include "recovery/flowctrl.h"
#include <malloc.h>

typedef struct quic_rbt_test_s quic_rbt_test_t;
struct quic_rbt_test_s {
    QUIC_RBT_UINT64_FIELDS
};

uint64_t get_swnd(quic_stream_flowctrl_t *const flowctrl) {
    (void) flowctrl;
    return 13;
}

void sent(quic_stream_flowctrl_t *const flowctrl, const uint64_t bytes) {
    (void) flowctrl;
    (void) bytes;
}

void update_rwnd(quic_stream_flowctrl_t *const flowctrl, const uint64_t t_off, const bool fin) {
    (void) flowctrl;
    (void) t_off;
    (void) fin;
}

quic_err_t quic_stream_flowctrl_module_init(void *const module) {
    quic_stream_flowctrl_module_t *const ref = module;
    ref->init = NULL;
    ref->get_swnd = get_swnd;
    ref->sent = sent;
    ref->update_rwnd = update_rwnd;

    return quic_err_success;
}

quic_module_t quic_stream_flowctrl_module = {
    .module_size = sizeof(quic_stream_flowctrl_module_t),
    .init        = quic_stream_flowctrl_module_init,
    .destory     = NULL
};

quic_module_t quic_connection_flowctrl_module = {
    .module_size = 0,
    .init = NULL,
    .destory = NULL
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

    quic_rbt_test_t *node;
    {
        quic_rbt_foreach(node, root) {
            printf("key: %ld\n", node->key);
        }
    }

    return 0;
}
