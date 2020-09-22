#!/bin/sh

awk '
BEGIN {
    print "#include \"format/frame.h\""
    print "#include \"session.h\""
    for (i = 0; i < 256; i++) handler[i] = "NULL";
}
{
    if ($1 == "handler") {
        print "extern quic_err_t " $3 "(quic_session_t *const, quic_frame_t *const frame);";
        handler[strtonum($2)] = $3;
    }
}
END {
    print "const quic_session_handler_t quic_session_handler_t[256] = {";
    for (val in handler) print "    " handler[val] ",";
    print "};"
}' $@ > src/_generated_frame_handler.c
