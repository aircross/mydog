
#ifndef _PING_THREAD_H_
#define _PING_THREAD_H_

#define MINIMUM_STARTED_TIME 1041379200 /* 2003-01-01 */

/** @brief Periodically checks on the auth server to see if it's alive. */
void thread_ping(void *arg);

#endif
