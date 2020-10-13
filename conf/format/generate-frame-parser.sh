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
    for (i = 0; i < 256; i++) parser[i] = "NULL";
}
{
    if ($1 == "parser") {
        print "extern quic_err_t " $3 "(quic_frame_t **const, quic_buf_t *const);";
        parser[strtonum($2)] = $3;
    }
}
END {
    print "const quic_frame_parser_t quic_frame_parser[256] = {";
    for (val in parser) print "    " parser[val] ",";
    print "};"
}' $@ > gen/frame_parser.c
