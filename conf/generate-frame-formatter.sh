#!/bin/sh

awk '
BEGIN {
    print "#include \"format/frame.h\""
    for (i = 0; i < 256; i++) formatter[i] = "NULL";
}
{
    if ($1 == "formatter") {
        print "extern quic_err_t " $3 "(quic_buf_t *const, quic_frame_t *const frame);";
        formatter[strtonum($2)] = $3;
    }
}
END {
    print "const quic_frame_formatter_t quic_frame_formatter[256] = {";
    for (val in formatter) print "    " formatter[val] ",";
    print "};"
}' $@ > src/_generated_frame_formatter.c
