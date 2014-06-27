
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>
#include <netdb.h>

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"
#include "firewall.h"

#include "config.h"

#include "util.h"

/** @internal Holds the current configuration of the gateway */
static s_config config;

/** Mutex for the configuration file, used by the auth_servers related functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal A flag.  If set to 1, there are missing or empty mandatory parameters in the config */
static int missing_parms;

/** @internal The different configuration options */
typedef enum {
	oBadOption,
	oDaemon,
	oDebugLevel,
	oExternalInterface,
	oGatewayID,
	oGatewayInterface,
	oGatewayAddress,
	oGatewayPort,
	oAuthServer,
	oAuthServHostname,
	oAuthServSSLAvailable,
	oAuthServSSLPort,
	oAuthServHTTPPort,
	oAuthServPath,
	oAuthServLoginScriptPathFragment,
	oAuthServPortalScriptPathFragment,
	oAuthServMsgScriptPathFragment,
	oAuthServPingScriptPathFragment,
	oAuthServAuthScriptPathFragment,
	oHTTPDMaxConn,
	oHTTPDName,
	oHTTPDRealm,
        oHTTPDUsername,
        oHTTPDPassword,
	oClientTimeout,
	oCheckInterval,
	oWdctlSocket,
	oSyslogFacility,
	oFirewallRule,
	oFirewallRuleSet,
	oTrustedMACList,
        oHtmlMessageFile,
	oProxyPort,
} OpCodes;

/** @internal The config file keywords for the different configuration options */
static const struct {
	const char *name;
	OpCodes opcode;
} keywords[] = {
	{ "daemon",             	oDaemon },
	{ "debuglevel",         	oDebugLevel },
	{ "externalinterface",  	oExternalInterface },
	{ "gatewayid",          	oGatewayID },
	{ "gatewayinterface",   	oGatewayInterface },
	{ "gatewayaddress",     	oGatewayAddress },
	{ "gatewayport",        	oGatewayPort },
	{ "authserver",         	oAuthServer },
	{ "httpdmaxconn",       	oHTTPDMaxConn },
	{ "httpdname",          	oHTTPDName },
	{ "httpdrealm",			oHTTPDRealm },
	{ "httpdusername",		oHTTPDUsername },
	{ "httpdpassword",		oHTTPDPassword },
	{ "clienttimeout",      	oClientTimeout },
	{ "checkinterval",      	oCheckInterval },
	{ "syslogfacility", 		oSyslogFacility },
	{ "wdctlsocket",		oWdctlSocket },
	{ "hostname",			oAuthServHostname },
	{ "sslavailable",		oAuthServSSLAvailable },
	{ "sslport",			oAuthServSSLPort },
	{ "httpport",			oAuthServHTTPPort },
	{ "path",			oAuthServPath },
	{ "loginscriptpathfragment",	oAuthServLoginScriptPathFragment },
	{ "portalscriptpathfragment",	oAuthServPortalScriptPathFragment },
	{ "msgscriptpathfragment",	oAuthServMsgScriptPathFragment },
	{ "pingscriptpathfragment",	oAuthServPingScriptPathFragment },
	{ "authscriptpathfragment",	oAuthServAuthScriptPathFragment },
	{ "firewallruleset",		oFirewallRuleSet },
	{ "firewallrule",		oFirewallRule },
	{ "trustedmaclist",		oTrustedMACList },
        { "htmlmessagefile",		oHtmlMessageFile },
	{ "proxyport",			oProxyPort },
	{ NULL,				oBadOption },
};

static int 		parse_boolean_value(char *);
static int 		_parse_firewall_rule(const char *ruleset, char *leftover);
static void 	config_notnull(const void *parm, const char *parmname);
static void 	parse_auth_server(FILE *, const char *, int *);
static void 	parse_firewall_ruleset(const char *, FILE *, const char *, int *);
static long 	ret_file_size(char *recv_buf);
static OpCodes config_parse_token(const char *cp, const char *filename, int linenum);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_config *
config_get_config(void)
{
    return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
	debug(LOG_DEBUG, "Setting default config parameters");
	strncpy(config.configfile, DEFAULT_CONFIGFILE, sizeof(config.configfile));
	config.htmlmsgfile 			= safe_strdup(DEFAULT_HTMLMSGFILE);
	config.debuglevel 			= DEFAULT_DEBUGLEVEL;
	config.httpdmaxconn 			= DEFAULT_HTTPDMAXCONN;
	config.external_interface 	= NULL;
	config.gw_id 					= DEFAULT_GATEWAYID;
	config.gw_interface 			= NULL;
	config.gw_address 			= NULL;
	config.gw_port 				= DEFAULT_GATEWAYPORT;
	config.auth_servers 			= NULL;
	config.httpdname 				= NULL;
	config.httpdrealm 			= DEFAULT_HTTPDNAME;
	config.httpdusername 		= NULL;
	config.httpdpassword			= NULL;
	config.clienttimeout 		= DEFAULT_CLIENTTIMEOUT;
	config.checkinterval 		= DEFAULT_CHECKINTERVAL;
	config.syslog_facility 		= DEFAULT_SYSLOG_FACILITY;
	config.daemon 					= -1;
	config.log_syslog 			= DEFAULT_LOG_SYSLOG;
	config.wdctl_sock 			= safe_strdup(DEFAULT_WDCTL_SOCK);
	config.internal_sock 		= safe_strdup(DEFAULT_INTERNAL_SOCK);
	config.rulesets 				= NULL;
	config.trustedmaclist 		= NULL;
	config.proxy_port 			= 0;
}

/**
 * If the command-line didn't provide a config, use the default.
 */
void
config_init_override(void)
{
    if (config.daemon == -1) config.daemon = DEFAULT_DAEMON;
}

/** @internal
Parses a single token from the config file
*/
static OpCodes
config_parse_token(const char *cp, const char *filename, int linenum)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	debug(LOG_ERR, "%s: line %d: Bad configuration option: %s",	filename, linenum, cp);
	return oBadOption;
}

/** @internal
Parses auth server information
*/
static void
parse_auth_server(FILE *file, const char *filename, int *linenum)
{
	char	*host = NULL;
	char	*path = NULL;
	char	*loginscriptpathfragment 	= NULL;
	char	*portalscriptpathfragment 	= NULL;
	char	*msgscriptpathfragment 		= NULL;
	char	*pingscriptpathfragment		= NULL;
	char	*authscriptpathfragment		= NULL;
	char	line[MAX_BUF] = {0};
	char	*p1 = NULL;
	char	*p2 = NULL;
	int	http_port;
	int	ssl_port;
	int	ssl_available;
	int	opcode;
	t_auth_serv	*new = NULL;
	t_auth_serv *tmp = NULL;

	/* Defaults */
	path = safe_strdup(DEFAULT_AUTHSERVPATH);
	loginscriptpathfragment 	= safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
	portalscriptpathfragment 	= safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
	msgscriptpathfragment 		= safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
	pingscriptpathfragment 		= safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
	authscriptpathfragment 		= safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);
	http_port = DEFAULT_AUTHSERVPORT;
	ssl_port	 = DEFAULT_AUTHSERVSSLPORT;
	ssl_available = DEFAULT_AUTHSERVSSLAVAILABLE;


	/* Parsing loop */
	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
		(*linenum)++; /* increment line counter. */

		/* skip leading blank spaces */
		for (p1 = line; isblank(*p1); p1++);

		/* End at end of line */
		if ((p2 = strchr(p1, '#')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\r')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\n')) != NULL) {
			*p2 = '\0';
		}

		/* next, we coopt the parsing of the regular config */
		if (strlen(p1) > 0) {
			p2 = p1;
			/* keep going until word boundary is found. */
			while ((*p2 != '\0') && (!isblank(*p2)))
				p2++;

			/* Terminate first word. */
			*p2 = '\0';
			p2++;

			/* skip all further blanks. */
			while (isblank(*p2))
				p2++;

			/* Get opcode */
			opcode = config_parse_token(p1, filename, *linenum);

			switch (opcode) {
				case oAuthServHostname:
					host = safe_strdup(p2);
					break;
				case oAuthServPath:
					free(path);
					path = safe_strdup(p2);
					break;
				case oAuthServLoginScriptPathFragment:
					free(loginscriptpathfragment);
					loginscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServPortalScriptPathFragment:
					free(portalscriptpathfragment);
					portalscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServMsgScriptPathFragment:
					free(msgscriptpathfragment);
					msgscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServPingScriptPathFragment:
					free(pingscriptpathfragment);
					pingscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServAuthScriptPathFragment:
					free(authscriptpathfragment);
					authscriptpathfragment = safe_strdup(p2);
					break;
				case oAuthServSSLPort:
					ssl_port = atoi(p2);
					break;
				case oAuthServHTTPPort:
					http_port = atoi(p2);
					break;
				case oAuthServSSLAvailable:
					ssl_available = parse_boolean_value(p2);
					if (ssl_available < 0)
						ssl_available = 0;
					break;
				case oBadOption:
				default:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", *linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
			}
		}
	}

	/* only proceed if we have an host and a path */
	if (host == NULL)
		return;

	debug(LOG_DEBUG, "Adding %s:%d (SSL: %d) %s to the auth server list",
			host, http_port, ssl_port, path);

	/* Allocate memory */
	new = safe_malloc(sizeof(t_auth_serv));

	/* Fill in struct */
	memset(new, 0, sizeof(t_auth_serv)); /*< Fill all with NULL */
	new->authserv_hostname = host;
	new->authserv_use_ssl = ssl_available;
	new->authserv_path = path;
	new->authserv_login_script_path_fragment = loginscriptpathfragment;
	new->authserv_portal_script_path_fragment = portalscriptpathfragment;
	new->authserv_msg_script_path_fragment = msgscriptpathfragment;
	new->authserv_ping_script_path_fragment = pingscriptpathfragment;
	new->authserv_auth_script_path_fragment = authscriptpathfragment;
	new->authserv_http_port = http_port;
	new->authserv_ssl_port = ssl_port;

	/* If it's the first, add to config, else append to last server */
	if (config.auth_servers == NULL) {
		config.auth_servers = new;
	} else {
		for (tmp = config.auth_servers; tmp->next != NULL;
				tmp = tmp->next);
		tmp->next = new;
	}

	debug(LOG_DEBUG, "Auth server added");
}

/**
Advance to the next word
@param s string to parse, this is the next_word pointer, the value of s
	 when the macro is called is the current word, after the macro
	 completes, s contains the beginning of the NEXT word, so you
	 need to save s to something else before doing TO_NEXT_WORD
@param e should be 0 when calling TO_NEXT_WORD(), it'll be changed to 1
	 if the end of the string is reached.
*/
#define TO_NEXT_WORD(s, e) do { \
	while (*s != '\0' && !isblank(*s)) { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
		while (isblank(*s)) \
			s++; \
	} else { \
		e = 1; \
	} \
} while (0)

/** @internal
Parses firewall rule set information
*/
static void
parse_firewall_ruleset(const char *ruleset, FILE *file, const char *filename, int *linenum)
{
	char		line[MAX_BUF],
			*p1,
			*p2;
	int		opcode;

	debug(LOG_DEBUG, "Adding Firewall Rule Set %s", ruleset);

	/* Parsing loop */
	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
		(*linenum)++; /* increment line counter. */

		/* skip leading blank spaces */
		for (p1 = line; isblank(*p1); p1++);

		/* End at end of line */
		if ((p2 = strchr(p1, '#')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\r')) != NULL) {
			*p2 = '\0';
		} else if ((p2 = strchr(p1, '\n')) != NULL) {
			*p2 = '\0';
		}

		/* next, we coopt the parsing of the regular config */
		if (strlen(p1) > 0) {
			p2 = p1;
			/* keep going until word boundary is found. */
			while ((*p2 != '\0') && (!isblank(*p2)))
				p2++;

			/* Terminate first word. */
			*p2 = '\0';
			p2++;

			/* skip all further blanks. */
			while (isblank(*p2))
				p2++;

			/* Get opcode */
			opcode = config_parse_token(p1, filename, *linenum);

			debug(LOG_DEBUG, "p1 = [%s]; p2 = [%s]", p1, p2);

			switch (opcode) {
				case oFirewallRule:
					_parse_firewall_rule(ruleset, p2);
					break;

				case oBadOption:
				default:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", *linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
			}
		}
	}

	debug(LOG_DEBUG, "Firewall Rule Set %s added.", ruleset);
}

/** @internal
Helper for parse_firewall_ruleset.  Parses a single rule in a ruleset
*/
static int
_parse_firewall_rule(const char *ruleset, char *leftover)
{
	int i;
	t_firewall_target target = TARGET_REJECT; /**< firewall target */
	int all_nums = 1; /**< If 0, port contained non-numerics */
	int finished = 0; /**< reached end of line */
	char *token = NULL; /**< First word */
	char *port = NULL; /**< port to open/block */
	char *protocol = NULL; /**< protocol to block, tcp/udp/icmp */
	char *mask = NULL; /**< Netmask */
	char *other_kw = NULL; /**< other key word */
	t_firewall_ruleset *tmpr;
	t_firewall_ruleset *tmpr2;
	t_firewall_rule *tmp;
	t_firewall_rule *tmp2;

	debug(LOG_DEBUG, "leftover: %s", leftover);

	/* lower case */
	for (i = 0; *(leftover + i) != '\0'
			&& (*(leftover + i) = tolower((unsigned char)*(leftover + i))); i++);

	token = leftover;
	TO_NEXT_WORD(leftover, finished);

	/* Parse token */
	if (!strcasecmp(token, "block") || finished) {
		target = TARGET_REJECT;
	} else if (!strcasecmp(token, "drop")) {
		target = TARGET_DROP;
	} else if (!strcasecmp(token, "allow")) {
		target = TARGET_ACCEPT;
	} else if (!strcasecmp(token, "log")) {
		target = TARGET_LOG;
	} else if (!strcasecmp(token, "ulog")) {
		target = TARGET_ULOG;
	} else {
		debug(LOG_ERR, "Invalid rule type %s, expecting "
				"\"block\",\"drop\",\"allow\",\"log\" or \"ulog\"", token);
		return -1;
	}

	/* Parse the remainder */
	/* Get the protocol */
	if (strncmp(leftover, "tcp", 3) == 0
			|| strncmp(leftover, "udp", 3) == 0
			|| strncmp(leftover, "icmp", 4) == 0) {
		protocol = leftover;
		TO_NEXT_WORD(leftover, finished);
	}

	/* should be exactly "port" */
	if (strncmp(leftover, "port", 4) == 0) {
		TO_NEXT_WORD(leftover, finished);
		/* Get port now */
		port = leftover;
		TO_NEXT_WORD(leftover, finished);
		for (i = 0; *(port + i) != '\0'; i++)
			if (!isdigit((unsigned char)*(port + i)))
				all_nums = 0; /*< No longer only digits */
		if (!all_nums) {
			debug(LOG_ERR, "Invalid port %s", port);
			return -3; /*< Fail */
		}
	}

	/* Now, further stuff is optional */
	if (!finished) {
		/* should be exactly "to" */
		other_kw = leftover;
		TO_NEXT_WORD(leftover, finished);
		if (strcmp(other_kw, "to") || finished) {
			debug(LOG_ERR, "Invalid or unexpected keyword %s, "
					"expecting \"to\"", other_kw);
			return -4; /*< Fail */
		}

		/* Get port now */
		mask = leftover;
		TO_NEXT_WORD(leftover, finished);
		all_nums = 1;
		for (i = 0; *(mask + i) != '\0'; i++)
			if (!isdigit((unsigned char)*(mask + i)) && (*(mask + i) != '.')
					&& (*(mask + i) != '/'))
				all_nums = 0; /*< No longer only digits */
		if (!all_nums) {
			debug(LOG_ERR, "Invalid mask %s", mask);
			return -3; /*< Fail */
		}
	}

	/* Generate rule record */
	tmp = safe_malloc(sizeof(t_firewall_rule));
	memset((void *)tmp, 0, sizeof(t_firewall_rule));
	tmp->target = target;
	if (protocol != NULL)
		tmp->protocol = safe_strdup(protocol);
	if (port != NULL)
		tmp->port = safe_strdup(port);
	if (mask == NULL)
		tmp->mask = safe_strdup("0.0.0.0/0");
	else
		tmp->mask = safe_strdup(mask);

	debug(LOG_DEBUG, "Adding Firewall Rule %s %s port %s to %s", token, tmp->protocol, tmp->port, tmp->mask);

	/* Append the rule record */
	if (config.rulesets == NULL) {
		config.rulesets = safe_malloc(sizeof(t_firewall_ruleset));
		memset(config.rulesets, 0, sizeof(t_firewall_ruleset));
		config.rulesets->name = safe_strdup(ruleset);
		tmpr = config.rulesets;
	} else {
		tmpr2 = tmpr = config.rulesets;
		while (tmpr != NULL && (strcmp(tmpr->name, ruleset) != 0)) {
			tmpr2 = tmpr;
			tmpr = tmpr->next;
		}
		if (tmpr == NULL) {
			/* Rule did not exist */
			tmpr = safe_malloc(sizeof(t_firewall_ruleset));
			memset(tmpr, 0, sizeof(t_firewall_ruleset));
			tmpr->name = safe_strdup(ruleset);
			tmpr2->next = tmpr;
		}
	}

	/* At this point, tmpr == current ruleset */
	if (tmpr->rules == NULL) {
		/* No rules... */
		tmpr->rules = tmp;
	} else {
		tmp2 = tmpr->rules;
		while (tmp2->next != NULL)
			tmp2 = tmp2->next;
		tmp2->next = tmp;
	}

	return 1;
}

t_firewall_rule *
get_ruleset(const char *ruleset)
{
	t_firewall_ruleset	*tmp;

	for (tmp = config.rulesets; tmp != NULL
			&& strcmp(tmp->name, ruleset) != 0; tmp = tmp->next);

	if (tmp == NULL)
		return NULL;

	return(tmp->rules);
}

/**
@param filename Full path of the configuration file to be read
*/
void
config_read(const char *filename)
{
	FILE *fd;
	char line[MAX_BUF], *s, *p1, *p2;
	int linenum = 0, opcode, value, len;

	debug(LOG_INFO, "Reading configuration file '%s'", filename);

	if (!(fd = fopen(filename, "r"))) {
		debug(LOG_ERR, "Could not open configuration file '%s', "
				"exiting...", filename);
		exit(1);
	}

	while (!feof(fd) && fgets(line, MAX_BUF, fd)) {
		linenum++;
		s = line;

		if (s[strlen(s) - 1] == '\n')
			s[strlen(s) - 1] = '\0';

		if ((p1 = strchr(s, ' '))) {
			p1[0] = '\0';
		} else if ((p1 = strchr(s, '\t'))) {
			p1[0] = '\0';
		}

		if (p1) {
			p1++;

			// Trim leading spaces
			len = strlen(p1);
			while (*p1 && len) {
				if (*p1 == ' ')
					p1++;
				else
					break;
				len = strlen(p1);
			}


			if ((p2 = strchr(p1, ' '))) {
				p2[0] = '\0';
			} else if ((p2 = strstr(p1, "\r\n"))) {
				p2[0] = '\0';
			} else if ((p2 = strchr(p1, '\n'))) {
				p2[0] = '\0';
			}
		}

		if (p1 && p1[0] != '\0') {
			/* Strip trailing spaces */

			if ((strncmp(s, "#", 1)) != 0) {
				debug(LOG_DEBUG, "Parsing token: %s, "
						"value: %s", s, p1);
				opcode = config_parse_token(s, filename, linenum);

				switch(opcode) {
				case oDaemon:
					if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
						config.daemon = value;
					}
					break;
				case oExternalInterface:
					config.external_interface = safe_strdup(p1);
					break;
				case oGatewayID:
					config.gw_id = safe_strdup(p1);
					break;
				case oGatewayInterface:
					config.gw_interface = safe_strdup(p1);
					break;
				case oGatewayAddress:
					config.gw_address = safe_strdup(p1);
					break;
				case oGatewayPort:
					sscanf(p1, "%d", &config.gw_port);
					break;
				case oAuthServer:
					parse_auth_server(fd, filename, &linenum);
					break;
				case oFirewallRuleSet:
					parse_firewall_ruleset(p1, fd, filename, &linenum);
					break;
				case oTrustedMACList:
					parse_trusted_mac_list(p1);
					break;
				case oHTTPDName:
					config.httpdname = safe_strdup(p1);
					break;
				case oHTTPDMaxConn:
					sscanf(p1, "%d", &config.httpdmaxconn);
					break;
				case oHTTPDRealm:
					config.httpdrealm = safe_strdup(p1);
					break;
				case oHTTPDUsername:
					config.httpdusername = safe_strdup(p1);
					break;
				case oHTTPDPassword:
					config.httpdpassword = safe_strdup(p1);
					break;
				case oBadOption:
					debug(LOG_ERR, "Bad option on line %d "
							"in %s.", linenum,
							filename);
					debug(LOG_ERR, "Exiting...");
					exit(-1);
					break;
				case oCheckInterval:
					sscanf(p1, "%d", &config.checkinterval);
					break;
				case oWdctlSocket:
					free(config.wdctl_sock);
					config.wdctl_sock = safe_strdup(p1);
					break;
				case oClientTimeout:
					sscanf(p1, "%d", &config.clienttimeout);
					break;
				case oSyslogFacility:
					sscanf(p1, "%d", &config.syslog_facility);
					break;
				case oHtmlMessageFile:
					config.htmlmsgfile = safe_strdup(p1);
					break;
				case oProxyPort:
					sscanf(p1, "%d", &config.proxy_port);
					break;

				}
			}
		}
	}

	if (config.httpdusername && !config.httpdpassword) {
		debug(LOG_ERR, "HTTPDUserName requires a HTTPDPassword to be set.");
		exit(-1);
	}

	fclose(fd);
}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
{
	if (strcasecmp(line, "yes") == 0) {
		return 1;
	}
	if (strcasecmp(line, "no") == 0) {
		return 0;
	}
	if (strcmp(line, "1") == 0) {
		return 1;
	}
	if (strcmp(line, "0") == 0) {
		return 0;
	}

	return -1;
}

void parse_trusted_mac_list(const char *ptr) {
	char *ptrcopy = NULL;
	char *possiblemac = NULL;
	char *mac = NULL;
	t_trusted_mac *p = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for trusted MAC addresses", ptr);

	mac = safe_malloc(18);

	/* strsep modifies original, so let's make a copy */
	ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", "))) {
		if (sscanf(possiblemac, " %17[A-Fa-f0-9:]", mac) == 1) {
			/* Copy mac to the list */

			debug(LOG_DEBUG, "Adding MAC address [%s] to trusted list", mac);

			if (config.trustedmaclist == NULL) {
				config.trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
				config.trustedmaclist->mac = safe_strdup(mac);
				config.trustedmaclist->next = NULL;
			}
			else {
				/* Advance to the last entry */
				for (p = config.trustedmaclist; p->next != NULL; p = p->next);
				p->next = safe_malloc(sizeof(t_trusted_mac));
				p = p->next;
				p->mac = safe_strdup(mac);
				p->next = NULL;
			}

		}
	}

	free(ptrcopy);

	free(mac);

}

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
	config_notnull(config.gw_interface, "GatewayInterface");
	config_notnull(config.auth_servers, "AuthServer");

	if (missing_parms)
	{
		debug(LOG_ERR, "Configuration is not complete, exiting...");
		exit(-1);
	}
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(const void *parm, const char *parmname)
{
	if (parm == NULL)
	{
		debug(LOG_ERR, "%s is not set", parmname);
		missing_parms = 1;
	}
}

/**
 * This function returns the current (first auth_server)
 */
t_auth_serv *
get_auth_server(void)
{
	/* This is as good as atomic */
	return config.auth_servers;
}

/**
 * This function marks the current auth_server, if it matches the argument,
 * as bad. Basically, the "bad" server becomes the last one on the list.
 */
void
mark_auth_server_bad(t_auth_serv *bad_server)
{
	t_auth_serv	*tmp;

	if (config.auth_servers == bad_server && bad_server->next != NULL)
	{
		/* Go to the last */
		for (tmp = config.auth_servers; tmp->next != NULL; tmp = tmp->next);
		/* Set bad server as last */
		tmp->next = bad_server;
		/* Remove bad server from start of list */
		config.auth_servers = bad_server->next;
		/* Set the next pointe to NULL in the last element */
		bad_server->next = NULL;
	}

}


#if 0
/**
 * 从服务器下载配置文件
 * 默认： url = CONFIGFILE_URL
 *      save_path = CONFIGFILE_FROM_SERVER
 */
int
get_config_from_server(const char* url, const char* save_path)
{
	char *purl = safe_strdup(url);
	char *p1	  = NULL;
	char *hostname = NULL;
	char *configfile_path;

	struct in_addr *host_addr;	//

	int sockfd, nfds;
	struct sockaddr_in sockaddr;
	char* request[HTTP_MAX_BUF];	// = (char*)safe_malloc(MAX_BUF*sizeof(char));

	int numbytes, totalbytes, done;
	fd_set readfds;
	struct timeval	timeout;
	FILE *stream;
//	char* tofile;
	long filesize = -1;
	char* tofile;

	if ( NULL != (p1 = strstr(purl, "http://")) )	/** 略过“http://” */
	{
		purl = p1 + 7;
	}

	if ( NULL != (p1 = strstr(purl, "/")) )		/**  */
//	if ( NULL != (p1 = strstr(purl, ":")) )
	{
		configfile_path = safe_strdup(p1);
		*p1 = '\0';
	}

	hostname = safe_strdup(purl);
	if(NULL == hostname)
	{
		debug(LOG_ERR, "safe_strdup() failed.");
		free(hostname);
		return -1;
	}
//	printf("host name: %s\n", hostname);
	debug(LOG_DEBUG, "host name: %s", hostname);

	host_addr = get_http_server_addr(hostname);
	if(NULL == host_addr)
	{
//		perror("Coundn't get server IP.");
		debug(LOG_ERR,"Coundn't get server IP.");
		free(host_addr);
		return -2;
	}
	free(hostname);
	hostname = NULL;
//	printf("Server IP: %s\n", inet_ntoa(*h_addr));
//	debug(LOG_INFO, "Server IP: %s\n", inet_ntoa(*h_addr));

	/*
	 * <此处添加下载文件的相关代码>
	 */
//	printf("Will be downloading...\n");
	debug(LOG_INFO,"Will be downloading...");

	/** socket连接信息初始化 */
	sockaddr.sin_family 	= AF_INET;
	sockaddr.sin_port		= htons(CONFIGGILE_SERVER_PORT);
	sockaddr.sin_addr		= *host_addr;
	memset(&(sockaddr.sin_zero), '\0', sizeof(sockaddr.sin_zero));
	free(host_addr);

	/** 创建socket描述符 */
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("Failed create socket.");
		return -3;
	}

	/** 连接config服务器 */
	if(connect(sockfd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr)) == -1)
	{
		perror("Failed to connect to config server.");
		close(sockfd);
		return -4;
	}

	/**
	 * <创建HTTP请求>
	 */
	/** 构建HTTP请求 */
	snprintf((char*)request,
				sizeof(request) - 1,
				"GET %s HTTP/1.0\r\n"
				"User-Agent: WiFiDog %s\r\n"
				"Host: %s\r\n"
				"\r\n",
				configfile_path,
				VERSION,
				MYNAME);

	/** 发送HTTP请求 */
	send(sockfd, request, strlen((const char*)request), 0);

//	printf("Reading response.\n");
	debug(LOG_INFO, "Reading response.");

	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 15; /* XXX magic... 15 second */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);
		if (nfds > 0)
		{
			/** We don't have to use FD_ISSET() because there was only one fd. */
			numbytes = read(sockfd, request + totalbytes, HTTP_MAX_BUF - (totalbytes + 1));
			if (numbytes < 0)
			{
				debug(LOG_ERR, "An error occurred while reading from configfile server");
				close(sockfd);
				return -5;
			}
			else if (numbytes == 0)
			{
				done = 1;
			}
			else
			{
				totalbytes += numbytes;
//				perror( "Read bytes");
				debug(LOG_INFO, "Read %d bytes", totalbytes);
			}
		}
		else if (nfds == 0)
		{
			debug(LOG_ERR, "Timed out reading data via select() from configfile server");
			close(sockfd);
			return -6;
		}
		else if (nfds < 0)
		{
			debug(LOG_ERR, "Error reading data via select() from configfile server");
			close(sockfd);
			return -7;
		}
	}while(done == 0);

	request[totalbytes] = '\0';
//	printf( "HTTP Response from Server, length: %d bytes \n[%s]\n", strlen((const char*)request), request);
//	printf( "HTTP Response from Server, length: %d bytes \n[%s]\n", totalbytes, request);
	debug(LOG_INFO, "HTTP Response from Server, length: %d bytes", totalbytes);

	if ((filesize = ret_file_size((char*)request)) < 0)
	{
		debug(LOG_ERR, "Get real size failed");
		close(sockfd);
		return -8;
	}
	tofile = (char *)request;
	tofile = tofile + totalbytes - filesize;

//	printf("file size: %d  read size: %d\n\n %s\n", filesize, strlen((const char*)request), tofile);

	/*
	 * 将服务器回复存入文件
	 */
	stream = fopen(CONFIGFILE_FROM_SERVER, "w+");
	if(NULL == stream)
	{
//		perror("Open file failed.");
		debug(LOG_ERR, "Open file failed.");
		goto clean;
	}
//	tofile = (char*)&(request[strlen((const char*)request)-852]);
	fprintf(stream, "%s", tofile);
//	fwrite(tofile, 1, strlen(tofile), stream);
//	fputs(tofile, stream);
	sync();
//	fprintf(stream, "%s", request);

clean:
	fclose(stream);
	close(sockfd);
	hostname = NULL;
	host_addr = NULL;

	return 0;
}
#endif

static long
ret_file_size(char *recv_buf)
{
	long file_size = 0;
	char *rest = NULL;
	char *line = NULL;
	char actual_size[HTTP_MAX_BUF] = {0} ;

	if( NULL == recv_buf)
	{
		debug(LOG_ERR, "recv %s is NULL\n", recv_buf);
		return -1;
	}
	if((strstr(recv_buf,"Content-Length")) == NULL)
	{
		debug(LOG_ERR, "Content-Length is NULL\n");
		return -1;
	}

	rest = strstr(recv_buf,"Content-Length:")+strlen("Content-Length: ");
	line = strstr(rest,"\r\n");
	memcpy(actual_size,rest,line-rest);
	file_size = atoi(actual_size);

	debug(LOG_INFO, "Get file size is %ld bytes.", file_size);

	return file_size;
}


/*
 * 取得HTTP服务器的地址
 * hostname： www.xxx.com
 */
static struct in_addr*
get_http_server_addr(const char *hostname)
{
	struct hostent *he = NULL;
	struct in_addr *host_addr = NULL;
	struct in_addr *in_addr_temp = NULL;

	host_addr = (struct in_addr *)safe_malloc(sizeof(struct in_addr));
	he = gethostbyname(hostname);
	if( he == NULL )
	{
		free(host_addr);
		host_addr = NULL;
		debug(LOG_ERR, "Get config server IP failed.");
		return NULL;
	}

	in_addr_temp = (struct in_addr *)he->h_addr_list[0];
	host_addr->s_addr = in_addr_temp->s_addr;

	return host_addr;
}



/**
 *  生成URL： http://servername/Path/to/file.php?id=nodeid
 *  args: id=nodeid
 */
//char  *create_request(const t_auth_serv *auth_server, const char* path, const char** args)
//{
//	char protocol[10];            /** http or https */
//	char request[MAX_BUF] = {0};
//	char tmp[MAX_BUF] 	 = {0};
//	char *ptmp 				 = tmp;
//	char *purl				 = request;
//	char **pargs			 = args;
//	size_t length			 = 0;
//	int i = 0;
//	unsigned int port = 80;	/** default 80 */
//
//	if(auth_server->authserv_use_ssl) /** https protocol */
//	{
//		length = snprintf(protocol, 9,"%s", "https://");
//		port = 443;
//		debug(LOG_DEBUG, "Use https, port %d", port);
//	}
//	else    /** http protocol */
//	{
//		length = snprintf(protocol, 8,"%s", "http://");
//		debug(LOG_DEBUG, "Use http, port %d", port);
//	}
//
//	length = snprintf(purl, strlen(protocol) + 1, "%s", protocol);
//	debug(LOG_DEBUG, "URL: %s", request);
//	purl = purl + length;
//
//	/** 此处需要判断边界 */
//	length = strlen(auth_server->authserv_hostname) + get_digits(port) + strlen(path);
//	/** http://server:port/path */
////	snprintf(purl, (size_t)length,
////				"%s:%d/%s",
////				auth_server->authserv_hostname,
////				port,
////				path);
//	/** for test */
//	length = snprintf(purl, (size_t)length + 1,
//							"%s/%s",
//							auth_server->authserv_hostname,
//							path);
//	debug(LOG_DEBUG, "Confige file server: %s", auth_server->authserv_hostname);
//	debug(LOG_DEBUG, "Confige file path: %s", path);
//	debug(LOG_DEBUG, "URL: %s", request);
//
//	if(length < 0)
//	{
//		debug(LOG_ERR, "Set url failed");
//		return NULL;
//	}
//
//	purl = purl + length;
////	debug(LOG_DEBUG, "Get url without argments:[lenght=%d] %s", length, purl);   It's a error
//	debug(LOG_DEBUG, "URL: %s", request);
//
//	if(args != NULL)
//	{
//		i = 0;
//		while((pargs[i] != NULL) && ((ptmp-tmp) < sizeof(tmp)))
//		{
//			length = snprintf(ptmp, sizeof(pargs[i]), "%s&", pargs[i]);
//			debug(LOG_DEBUG, "args: %s", ptmp);
//
//			ptmp += length;
////			snprintf(ptmp, 2, "%s", "&");
////			ptmp++;
//
//			i++;
//		}
//
//		if(*(ptmp-1) == "&")
//		{
//			*(ptmp-1) = "\0";
//		}
//
//		length = strlen(tmp);
//		length = snprintf(purl, (size_t)length + 1,
//								"?%s",
//								tmp);
//		purl = purl + length;
//		debug(LOG_DEBUG, "URL: %s", request);
//	}
//
////	*purl = "\0";
////	debug(LOG_DEBUG, "Get complete url: %s", purl); It's a error
//	debug(LOG_DEBUG, "URL: %s", request);
//
//	return safe_strdup(request);
//}


/*
 * 计算一个无符号整数的位数
 */
unsigned int
get_digits(unsigned int number)
{
	unsigned int digits = 0;

	if(number < 0)
	{
		return 0;
	}

	if(number == 0)
	{
		return 1;
	}

	while(number != 0)
	{
		number /= 10;
		digits++;
	}

	return digits;
}




int
get_config_from_server_2(const t_auth_serv *auth_server, const char* path, const char* save_path)
{
	int  done		 =  0;
	int  nfds	  	 =  0;
	int  sockfd 	 =  0;
	int  numbytes 	 =  0;
	int  totalbytes =  0;
	int  port		 = ((auth_server->authserv_use_ssl) ? (auth_server->authserv_ssl_port) : (auth_server->authserv_http_port));
	long filesize	 = -1;

	char *tofile 					= NULL;
	char *hostname 	 			= NULL;
	char *request_path 			= path;
	char request[HTTP_MAX_BUF] = {0};	// = (char*)safe_malloc(MAX_BUF*sizeof(char));

	struct timeval		 timeout;
	struct in_addr 	 *host_addr = NULL;	//
	struct sockaddr_in sockaddr;

	FILE   *stream = NULL;
	fd_set readfds;

	hostname = safe_strdup(auth_server->authserv_hostname);
	if(NULL == hostname)
	{
		debug(LOG_ERR, "safe_strdup() failed.");
		free(hostname);
		return -1;
	}
	debug(LOG_DEBUG, "host name: %s", hostname);

	host_addr = get_http_server_addr(hostname);
	if(NULL == host_addr)
	{
		debug(LOG_ERR,"Coundn't get server IP.");
		free(host_addr);
		return -2;
	}
	free(hostname);
	hostname = NULL;

	/*
	 * <此处添加下载文件的相关代码>
	 */
	debug(LOG_INFO,"Will be downloading...");

	/** socket连接信息初始化 */
	sockaddr.sin_family 	= AF_INET;
	sockaddr.sin_port		= htons(port);
	sockaddr.sin_addr		= *host_addr;
	memset(&(sockaddr.sin_zero), '\0', sizeof(sockaddr.sin_zero));
	free(host_addr);
	host_addr = NULL;

	/** 创建socket描述符 */
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		debug(LOG_ERR, "Failed create socket: %s", strerror(errno));
		return -3;
	}

	/** 连接configure file服务器 */
	if(connect(sockfd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr)) == -1)
	{
		debug(LOG_ERR, "Failed to connect to config server: %s", strerror(errno));
		close(sockfd);
		return -4;
	}

	/** <创建HTTP请求> */
	snprintf((char*)request,
				sizeof(request) - 1,
				"GET %s HTTP/1.0\r\n"
				"User-Agent: WiFiDog %s\r\n"
				"Host: %s\r\n"
				"\r\n",
				request_path,
				VERSION,
				MYNAME);

	/** 发送HTTP请求 */
	if(0 > send(sockfd, request, strlen(request), 0))
	{
		debug(LOG_ERR, "Send request to configure file server failed: %s", strerror(errno));
		close(sockfd);
		return -5;
	}

	debug(LOG_INFO, "Reading response.");

	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 15; /* XXX magic... 15 second */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);
		if (nfds > 0)
		{
			/** We don't have to use FD_ISSET() because there was only one fd. */
			numbytes = read(sockfd, request + totalbytes, HTTP_MAX_BUF - (totalbytes + 1));
			if (numbytes < 0)
			{
				debug(LOG_ERR, "An error occurred while reading from configfile server");
				close(sockfd);
				return -5;
			}
			else if (numbytes == 0)
			{
				done = 1;
			}
			else
			{
				totalbytes += numbytes;
				debug(LOG_INFO, "Read %d bytes", totalbytes);
			}
		}
		else if (nfds == 0)
		{
			debug(LOG_ERR, "Timed out reading data via select() from configfile server");
			close(sockfd);
			return -6;
		}
		else if (nfds < 0)
		{
			debug(LOG_ERR, "Error reading data via select() from configfile server");
			close(sockfd);
			return -7;
		}
	}while(done == 0);

	request[totalbytes] = '\0';
	debug(LOG_INFO, "HTTP Response from Server, length: %d bytes", totalbytes);

	if ((filesize = ret_file_size((char*)request)) <= 0)
	{
		debug(LOG_ERR, "Get real size failed");
		close(sockfd);
		return -8;
	}
	tofile = (char *)request;
	tofile += totalbytes - filesize; /** 跳过HTTP header信息 */

//	debug(LOG_DEBUG, "File size: %d, read size: %d\n File content: [%s]", filesize, strlen((const char*)request), tofile);

	/** 将服务器回复存入文件 */
	stream = fopen(save_path, "w+");
	if(NULL == stream)
	{
		debug(LOG_ERR, "Create file failed: %s", strerror(errno));
		goto clean;
	}

	fprintf(stream, "%s", tofile);
	sync();

clean:
	fclose(stream);
	close(sockfd);

	return 0;
}


/**
 * 获取本地CPU型号
 * It can not work well on my fedora20,
 * because there is no "cpu model" string.
 */
char *get_platform(void)
{
	FILE* fh;

	char cpu_model[64] = {0};
	char *platform = NULL;

	if ((fh = fopen("/proc/cpuinfo", "r")))
	{
		while (!feof(fh))
		{
			if (fscanf(fh, "cpu model : %s ", cpu_model) == 0)
			{
				while (!feof(fh) && fgetc(fh) != '\n');  /* Not on this line */
			}
			else
			{
				break;  /* Found it */
			}
		}
		fclose(fh);
	}

	debug(LOG_DEBUG, "cpu model: %s", cpu_model);

	if( strstr(cpu_model, "MIPS") != NULL )
	{
		platform = safe_strdup("MIPS");
	}
	else if( strstr(cpu_model, "X86") != NULL )
	{
		platform = safe_strdup("X86");
	}
	else
	{
		platform = safe_strdup(" ");
	}

	debug(LOG_DEBUG, "Platform: [%s]", platform);

	return platform;  /**!!! free this in caller !!!*/
}
