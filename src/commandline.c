
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "debug.h"
#include "safe.h"
#include "conf.h"

#include "../config.h"

/*
 * Holds an argv that could be passed to exec*() if we restart ourselves
 */
char ** restartargv = NULL;

static void usage(void);

/*
 * A flag to denote whether we were restarted via a parent wifidog, or started normally
 * 0 means normally, otherwise it will be populated by the PID of the parent
 */
pid_t restart_orig_pid = 0;

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when wifidog is run with -h or with an unknown option
 */
static void
usage(void)
{
    printf("Usage: wifidog [options]\n");
    printf("\n");
    printf("  -c [filename] Use this config file\n");
    printf("  -f            Run in foreground\n");
    printf("  -d <level>    Debug level\n");
    printf("  -s            Log to syslog\n");
    printf("  -w <path>     Wdctl socket path\n");
    printf("  -h            Print usage\n");
    printf("  -v            Print version information\n");
    printf("  -x pid        Used internally by WiFiDog when re-starting itself *DO NOT ISSUE THIS SWITCH MANUAlLY*\n");
    printf("  -i <path>     Internal socket path used when re-starting self\n");
    printf("\n");
}

/** Uses getopt() to parse the command line and set configuration values
 * also populates restartargv
 */
void parse_commandline(int argc, char **argv) {
    int c;
	 int skiponrestart;		/** wdctl restart时，是否使用原来的参数的标志位 0保留，非0不再使用 */
	 int i;

    s_config *config = config_get_config();

	//MAGIC 3: Our own -x, the pid, and NULL :
	restartargv = safe_malloc((argc + 3) * sizeof(char*));			/** commandline.c line 17 */
	i=0;
	restartargv[i++] = safe_strdup(argv[0]);

    while (-1 != (c = getopt(argc, argv, "c:hfd:sw:vx:i:"))) {

		skiponrestart = 0;		/** 是否在重启动的时候使用某参数的标志变量 */

		switch(c) {

			case 'h':
				usage();
				exit(1);
				break;

			case 'c':
				if (optarg) {
					strncpy(config->configfile, optarg, sizeof(config->configfile));
				}
				break;

			case 'w':
				if (optarg) {
					free(config->wdctl_sock);
					config->wdctl_sock = safe_strdup(optarg);
				}
				break;

			case 'f':
				skiponrestart = 1;		/** 在重启动的时候 不会再使用"f"参数 */
				config->daemon = 0;
				break;

			case 'd':
				if (optarg) {				/** 如果-d 8 ，-d -2 是怎样？ */
					config->debuglevel = atoi(optarg);
				}
				break;

			case 's':
				config->log_syslog = 1;
				break;

			case 'v':
				printf("This is WiFiDog version " VERSION "\n");
				exit(1);
				break;

			case 'x':
				skiponrestart = 1;	/** 在重启动的时候 不会再使用"x"参数 */
				if (optarg) {
					restart_orig_pid = atoi(optarg);
				}
				else {
					printf("The expected PID to the -x switch was not supplied!");
					exit(1);
				}
				break;

			case 'i':
				if (optarg) {
					free(config->internal_sock);
					config->internal_sock = safe_strdup(optarg);
				}
				break;

			default:
				usage();
				exit(1);
				break;

		}

		if (!skiponrestart) {
			/* Add it to restartargv */
			safe_asprintf(&(restartargv[i++]), "-%c", c);
			if (optarg) {
				restartargv[i++] = safe_strdup(optarg);
			}
		}

	}

	/* Finally, we should add  the -x, pid and NULL to restartargv
	 * HOWEVER we cannot do it here, since this is called before we fork to background
	 * so we'll leave this job to gateway.c after forking is completed
	 * so that the correct PID is assigned
	 *
	 * We add 3 nulls, and the first 2 will be overridden later---in main()
	 */
	restartargv[i++] = NULL;
	restartargv[i++] = NULL;
	restartargv[i++] = NULL;

}


