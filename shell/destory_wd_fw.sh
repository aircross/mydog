#!/bin/sh
#
#
#

#local run=`ps  | grep  "wifidog"  | wc -l`
local dog=`pgrep wifidog | wc -l`
local iptab=`iptables -nv -L | grep "WD_" | wc -l`
	
#if [ $run -eq 1 ]; then
if [ $dog -eq 0 -a $iptab -ne 0 ]; then
	/usr/local/wifidog/bin/wifidog	
	sleep 5
	/usr/local/wifidog/bin/wdctl stop
fi
