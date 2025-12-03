#include "params.h"
#include <stdio.h>
#include <syslog.h>
#ifdef HAVE_LIBDMALLOC
#include <dmalloc.h>
#endif

#include "client.h"

extern t_client_opt opt;

void log_init(void)
{
	openlog("bob_client", LOG_PID, LOG_DAEMON);
}

void normal_log(const char *s)
{
    syslog(LOG_DAEMON | LOG_NOTICE, "%s", s);
}

void verbose_log(const char *s)
{
    syslog(LOG_DAEMON | LOG_INFO, "%s", s);
}

void debug_log(const char *s)
{
    syslog(LOG_DAEMON | LOG_DEBUG, "%s", s);
}

void error_log(const char *s)
{
    syslog(LOG_DAEMON | LOG_ERR, "%s", s);
}

void log_close(void)
{
	closelog();
}
