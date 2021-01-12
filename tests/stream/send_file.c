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
    cfg.is_cli = true;
    cfg.src.buf = "1";
    cfg.src.capa = 1;
    quic_buf_setpl(&cfg.src);
    cfg.dst.buf = "1";
    cfg.dst.capa = 1;
    quic_buf_setpl(&cfg.dst);

    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    local_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    remote_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    local_addr.sin_family = AF_INET;
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(11001);
    local_addr.sin_port = htons(11000);
    quic_client_t client;
    quic_client_init(&client, cfg);
    quic_client_create_ipv4_path(&client, 0, 1460, local_addr, remote_addr);
    quic_client_use_path(&client, 0);

    pthread_t thr;
    pthread_create(&thr, NULL, pthread_loop, &client);

    quic_stream_t *stream = quic_session_open_stream(client.session, true);

    struct stat file_stat;
    int fd = open("./nginx-1.19.4.tar.gz", O_RDWR);
    fstat(fd, &file_stat);
    void *mapped = mmap(NULL, file_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    quic_stream_write(stream, mapped, file_stat.st_size);

    quic_stream_close(stream);
    printf("done\n");

    return 0;
}
