#include "utils/buf.h"
#include "session.h"
#include "modules/stream.h"
#include "modules/udp_fd.h"
#include "modules/migrate.h"
#include "client.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>

void *pthread_loop(void *const client_) {
    quic_client_t *const client = client_;

    quic_client_start_loop(client);

    return NULL;
}

int main() {
    quic_config_t cfg = quic_client_default_config;
    cfg.conn_len = 1;
    cfg.is_cli = false;
    cfg.src.buf = "1";
    cfg.src.capa = 1;
    quic_buf_setpl(&cfg.src);
    cfg.dst.buf = "1";
    cfg.dst.capa = 1;
    quic_buf_setpl(&cfg.dst);

    cfg.tls_cert_chain_file = "./tests/crt.crt";
    cfg.tls_key_file = "./tests/key.key";

    cfg.mtu = 1460;

    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    local_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    remote_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    local_addr.sin_family = AF_INET;
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(11000);
    local_addr.sin_port = htons(11001);

    quic_client_t client;
    quic_client_init(&client, cfg);
    quic_client_create_ipv4_path(&client, 0, 1460, local_addr, remote_addr);
    quic_client_use_path(&client, 0);

    pthread_t thr;
    pthread_create(&thr, NULL, pthread_loop, &client);

    quic_stream_t *stream = quic_session_accept_stream(client.session, true);

    uint64_t len = 0;
    for ( ;; ) {
        char buf[1024];
        
        len += quic_stream_read(stream, buf, 1024);
        printf("recv len: %ld\n", len);
        if (quic_stream_remote_closed(stream)) {
            quic_stream_close(stream);
            break;
        }
    }

    return 0;
}
