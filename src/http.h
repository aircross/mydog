
#ifndef _HTTP_H_
#define _HTTP_H_

#include "httpd.h"

/**@brief Callback for libhttpd, main entry point for captive portal */
void http_callback_404(httpd *webserver, request *r);
/**@brief Callback for libhttpd */
void http_callback_wifidog(httpd *webserver, request *r);
/**@brief Callback for libhttpd */
void http_callback_about(httpd *webserver, request *r);
/**@brief Callback for libhttpd */
void http_callback_status(httpd *webserver, request *r);
/**@brief Callback for libhttpd, main entry point post login for auth confirmation */
void http_callback_auth(httpd *webserver, request *r);

/** @brief Sends a HTML page to web browser */
void send_http_page(request *r, const char *title, const char* message);

/** @brief Sends a redirect to the web browser */
void http_send_redirect(request *r, const char *url, const char *text);
/** @brief Convenience function to redirect the web browser to the authe server */
void http_send_redirect_to_auth(request *r, const char *urlFragment, const char *text);
#endif /* _HTTP_H_ */
