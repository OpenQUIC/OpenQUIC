#!/bin/sh

# Copyright (c) 2020 Gscienty <gaoxiaochuan@hotmail.com>
#
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .

conf/format/generate-frame-sizer.sh conf/frame.conf
conf/format/generate-frame-parser.sh conf/frame.conf
conf/format/generate-frame-handler.sh conf/frame.conf
conf/format/generate-frame-formatter.sh conf/frame.conf
conf/generate-modules.sh conf/module.conf
