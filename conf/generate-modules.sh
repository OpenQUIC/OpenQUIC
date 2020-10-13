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
    print "#include \"module.h\"";
    module_count = 0;
}
{
    if ($1 == "module") {
        print "extern quic_module_t " $2 ";";
        modules[module_count] = $2;
        module_count = module_count + 1;
    }
}
END {
    print "const quic_module_t *quic_modules[] = {";
    for (module in modules) print "    &" modules[module] ",";
    print "    NULL";
    print "};";
}
' $@ > gen/modules.c
