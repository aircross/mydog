<?php

echo "#".time()."\n";

switch($_GET["nodeid"])
{
	case "hg255d":
		echo "GatewayID hg255d 
#ExternalInterface eth0.1 
GatewayInterface br-lan 
# GatewayAddress 192.168.1.1 
# HtmlMessageFile /opt/wifidog/etc/wifidog-.html
AuthServer {
#    Hostname 192.168.10.110
    Hostname 192.168.1.222
    SSLAvailable no
    Path /authpuppy/web/
}
Daemon 1
GatewayPort 2060
# ProxyPort 0
HTTPDName WiFiDog
HTTPDMaxConn 300
HTTPDRealm WiFiDog
HTTPDUserName admin
HTTPDPassword admin
CheckInterval 60
ClientTimeout 12
#TrustedMACList 00:00:DE:AD:BE:AF,00:00:C0:1D:F0:0D
FirewallRuleSet global {
}
FirewallRuleSet validating-users {
    FirewallRule allow to 0.0.0.0/0
}
FirewallRuleSet known-users {
    FirewallRule allow to 0.0.0.0/0
}
FirewallRuleSet unknown-users {
    FirewallRule allow udp port 53
    FirewallRule allow tcp port 53
    FirewallRule allow udp port 67
    FirewallRule allow tcp port 67
}
FirewallRuleSet locked-users {
    FirewallRule block to 0.0.0.0/0
}";
		break;

	case "fc20":
		echo "GatewayID fc20
#ExternalInterface eth0.1 
GatewayInterface br-lan
# GatewayAddress 192.168.1.1
# HtmlMessageFile /opt/wifidog/etc/wifidog-.html
AuthServer {
#    Hostname 192.168.10.110
    Hostname 192.168.1.222
    SSLAvailable no
    Path /authpuppy/web/
}
Daemon 1
GatewayPort 2060
# ProxyPort 0
HTTPDName WiFiDog
HTTPDMaxConn 300
HTTPDRealm WiFiDog
HTTPDUserName admin
HTTPDPassword admin
CheckInterval 60
ClientTimeout 12
#TrustedMACList 00:00:DE:AD:BE:AF,00:00:C0:1D:F0:0D
FirewallRuleSet global {
}
FirewallRuleSet validating-users {
    FirewallRule allow to 0.0.0.0/0
}
FirewallRuleSet known-users {
    FirewallRule allow to 0.0.0.0/0
}
FirewallRuleSet unknown-users {
    FirewallRule allow udp port 53
    FirewallRule allow tcp port 53
    FirewallRule allow udp port 67
    FirewallRule allow tcp port 67
}
FirewallRuleSet locked-users {
    FirewallRule block to 0.0.0.0/0
}";
		break;
}


?>
