#!/bin/sh
#
# Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
#
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
#

. conf/make-gen-dir.sh

awk '
BEGIN {
    print "#include \"format/frame.h\""
    print "#include \"session.h\""
    for (i = 0; i < 256; i++) handler[i] = "NULL";
}
{
    if ($1 == "handler") {
        print "extern quic_err_t " $3 "(quic_session_t *const, const quic_frame_t *const frame);";
        handler[strtonum($2)] = $3;
    }
}
END {
    print "const quic_session_handler_t quic_session_handler[256] = {";
    for (i = 0; i < 256; i++) print "    " handler[i] ",";
    print "};"
}' $@ > gen/frame_handler.c
