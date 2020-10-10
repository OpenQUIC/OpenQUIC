#!/bin/sh

. conf/make-gen-dir.sh

awk '
BEGIN {
    print "#include \"format/frame.h\""
    for (i = 0; i < 256; i++) sizer[i] = "NULL";
}
{
    if ($1 == "sizer") {
        print "extern uint64_t " $3 "(const quic_frame_t *const);";
        sizer[strtonum($2)] = $3;
    }
}
END {
    print "const quic_frame_sizer_t quic_frame_sizer[256] = {";
    for (val in sizer) print "    " sizer[val] ",";
    print "};"
}' $@ > gen/frame_sizer.c
