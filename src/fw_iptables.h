
#ifndef _FW_IPTABLES_H_
#define _FW_IPTABLES_H_

#include "firewall.h"

/*@{*/ 
/**
 * Iptable table names used by WifiDog
 * */
#define TABLE_WIFIDOG_OUTGOING  			"WD_$ID$_Out"			/** "WiFiDog_$ID$_Outgoing" 		*/
#define TABLE_WIFIDOG_WIFI_TO_INTERNET 	"WD_$ID$_2Int"			/** "WiFiDog_$ID$_WIFI2Internet" 	*/
#define TABLE_WIFIDOG_WIFI_TO_ROUTER 		"WD_$ID$_2Rot"			/** "WiFiDog_$ID$_WIFI2Router" 		*/
#define TABLE_WIFIDOG_INCOMING  			"WD_$ID$_In"				/** "WiFiDog_$ID$_Incoming" 		*/
#define TABLE_WIFIDOG_AUTHSERVERS 			"WD_$ID$_AS"				/** "WiFiDog_$ID$_AuthServers"		*/
#define TABLE_WIFIDOG_GLOBAL  				"WD_$ID$_Glb"			/** "WiFiDog_$ID$_Global"			*/
#define TABLE_WIFIDOG_VALIDATE  			"WD_$ID$_Vld"			/** "WiFiDog_$ID$_Validate"			*/
#define TABLE_WIFIDOG_KNOWN     			"WD_$ID$_Knw"			/** "WiFiDog_$ID$_Known"				*/
#define TABLE_WIFIDOG_UNKNOWN   			"WD_$ID$_UKn"			/** "WiFiDog_$ID$_Unknown"			*/
#define TABLE_WIFIDOG_LOCKED    			"WD_$ID$_Lck"			/** "WiFiDog_$ID$_Locked"			*/
#define TABLE_WIFIDOG_TRUSTED    			"WD_$ID$_Trs"			/** "WiFiDog_$ID$_Trusted"			*/
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

