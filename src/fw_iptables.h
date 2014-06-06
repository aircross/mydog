
#ifndef _FW_IPTABLES_H_
#define _FW_IPTABLES_H_

#include "firewall.h"

/*@{*/ 
/**Iptable table names used by WifiDog */
#define TABLE_WIFIDOG_OUTGOING  "WiFiDog_$ID$_Outgoing"
#define TABLE_WIFIDOG_WIFI_TO_INTERNET "WiFiDog_$ID$_WIFI2Internet"
#define TABLE_WIFIDOG_WIFI_TO_ROUTER "WiFiDog_$ID$_WIFI2Router"
#define TABLE_WIFIDOG_INCOMING  "WiFiDog_$ID$_Incoming"
#define TABLE_WIFIDOG_AUTHSERVERS "WiFiDog_$ID$_AuthServers"
#define TABLE_WIFIDOG_GLOBAL  "WiFiDog_$ID$_Global"
#define TABLE_WIFIDOG_VALIDATE  "WiFiDog_$ID$_Validate"
#define TABLE_WIFIDOG_KNOWN     "WiFiDog_$ID$_Known"
#define TABLE_WIFIDOG_UNKNOWN   "WiFiDog_$ID$_Unknown"
#define TABLE_WIFIDOG_LOCKED    "WiFiDog_$ID$_Locked"
#define TABLE_WIFIDOG_TRUSTED    "WiFiDog_$ID$_Trusted"
/*@}*/ 

/** Used by iptables_fw_access to select if the client should be granted of denied access */
typedef enum fw_access_t_ {
    FW_ACCESS_ALLOW,
    FW_ACCESS_DENY
} fw_access_t;

/** @brief Initialize the firewall */
int iptables_fw_init(void);

/** @brief Initializes the authservers table */
void iptables_fw_set_authservers(void);

/** @brief Clears the authservers table */
void iptables_fw_clear_authservers(void);

/** @brief Destroy the firewall */
int iptables_fw_destroy(void);

/** @brief Helper function for iptables_fw_destroy */
int iptables_fw_destroy_mention( const char * table, const char * chain, const char * mention);

/** @brief Define the access of a specific client */
int iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag);

/** @brief All counters in the client list */
int iptables_fw_counters_update(void);

#endif /* _IPTABLES_H_ */
