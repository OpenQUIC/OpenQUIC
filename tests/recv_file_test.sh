gcc -g \
    -I deps/liteco/include/ \
    -I deps/boringssl/include/ \
    -I src/ \
    -I gen/ \
    deps/liteco/src/arch/x86_64/*.s \
    deps/liteco/src/*.c \
    gen/modules.c \
    gen/frame_sizer.c \
    gen/frame_formatter.c \
    gen/frame_parser.c \
    gen/frame_handler.c \
    src/utils/*.c \
    src/session.c \
    src/format/frame.c \
    src/sorter.c \
    src/module.c \
    src/modules/stream.c \
    src/modules/framer.c \
    src/modules/packet_number_generator.c \
    src/modules/sender.c \
    src/modules/recver.c \
    src/modules/udp_fd.c \
    src/modules/ack_generator.c \
    src/modules/retransmission.c \
    src/modules/congestion.c \
    src/modules/stream_flowctrl.c \
    src/modules/conn_flowctrl.c \
    src/modules/sealer.c \
    src/modules/migrate.c \
    src/client.c \
    src/events/epoll.c \
    tests/stream/recv_file.c \
    -o recv.out \
    -Wl,-dy -lpthread -lm -ldl -Wl,-dn -Ldeps/boringssl/ssl -lssl -Ldeps/boringssl/crypto -lcrypto -Wl,-dy && ./recv.out
