#include "utils/rbt_extend.h"

liteco_rbt_cmp_result_t quic_rbt_string_cmp_cb(const void *const key, const liteco_rbt_t *const node) {
    const quic_buf_t *const spec_key = key;
    const quic_string_rbt_t *const spec_node = (quic_string_rbt_t *) node;

    if (quic_buf_size(spec_key) == quic_buf_size(&spec_node->key)) {
        int cmpret = memcmp(spec_key->pos, spec_node->key.pos, quic_buf_size(spec_key));
        if (cmpret == 0) {
            return LITECO_RBT_EQ;
        }
        else if (cmpret < 0) {
            return LITECO_RBT_LS;
        }
        else {
            return LITECO_RBT_GT;
        }
    }
    else if (quic_buf_size(spec_key) < quic_buf_size(&spec_node->key)) {
        return LITECO_RBT_LS;
    }
    else {
        return LITECO_RBT_GT;
    }
}

liteco_rbt_cmp_result_t quic_rbt_addr_cmp_cb(const void *const key, const liteco_rbt_t *const node) {
    const quic_addr_t *const spec_key = key;
    const quic_addr_rbt_t *const spec_node = (quic_addr_rbt_t *) node;

    int cmpret = quic_addr_cmp(*spec_key, spec_node->key);
    if (cmpret == 0) {
        return LITECO_RBT_EQ;
    }
    else if (cmpret < 0) {
        return LITECO_RBT_LS;
    }
    else {
        return  LITECO_RBT_GT;
    }
}

liteco_rbt_cmp_result_t quic_rbt_path_cmp_cb(const void *const key, const liteco_rbt_t *const node) {
    const quic_path_t *const spec_key = key;
    const quic_path_rbt_t *const spec_node = (quic_path_rbt_t *) node;

    int cmpret = quic_path_cmp(*spec_key, spec_node->key);
    if (cmpret == 0) {
        return LITECO_RBT_EQ;
    }
    else if (cmpret < 0) {
        return LITECO_RBT_LS;
    }
    else {
        return  LITECO_RBT_GT;
    }
}
