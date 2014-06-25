
#ifndef _WDCTL_H_
#define _WDCTL_H_

#include <time.h>

#define DEFAULT_SOCK	"/tmp/wdctl.sock"

#define WDCTL_UNDEF			0
#define WDCTL_STATUS			1
#define WDCTL_STOP			2
#define WDCTL_KILL			3
#define WDCTL_RESTART		4
#define WDCTL_NODEID			5  /** Get node id */
#define WDCTL_CHK_UPDATE	6  /** check update configure file */

typedef struct {
	char	*socket;
	int	command;
	char	*param;
} wdctl_config_t;


typedef struct {
	time_t last_get;  /** 上次更新配置文件的时间   */
	time_t update;    /** 服务器配置文件的更新时间 */
}chk_time_t;


#endif
