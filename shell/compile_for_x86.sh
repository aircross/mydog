#! /bin/sh

make distclean

./autogen.sh

./configure   --prefix=/home/exist/devel/workspace/mydog/exec_x86_64    --sysconfdir=/home/exist/devel/workspace/mydog/exec_x86_64/etc

make && make install
