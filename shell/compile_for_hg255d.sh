#! /bin/sh

make distclean

./mipsel_autogen.sh

./configure --host=mipsel-openwrt-linux --build=i486-linux --prefix=/usr/local/wifidog --sysconfdir=/usr/local/wifidog/etc

make && make DESTDIR=/home/exist/devel/workspace/mydog/exec install
