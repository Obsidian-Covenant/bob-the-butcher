#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define USER_HOST_SEP	'@'
#define BUFSIZE		1024

char *get_full_login(char *login)
{
    char    *username = NULL;
    char    hostname[BUFSIZE];
    char    *tmp = hostname;

    username = (login != NULL) ? login : getlogin();
    if (username == NULL) /* FIXME: proper error handling later */
        return strdup("unknown");

    size_t username_len = strlen(username);
    if (username_len + 1 >= BUFSIZE) {  /* +1 for '@' */
        /* Too long; just return username copy */
        return strdup(username);
    }

    memcpy(tmp, username, username_len);
    tmp += username_len;
    *tmp++ = USER_HOST_SEP;

    /* space left after "username@" */
    size_t remaining = BUFSIZE - (tmp - hostname);

    /* hostname */
    if (gethostname(tmp, remaining) != 0) {
        /* if hostname fails, just terminate after username@ */
        *tmp = '\0';
        return strdup(hostname);
    }

    /* advance tmp to end of hostname (but not beyond buffer) */
    while (*tmp && (tmp - hostname) < BUFSIZE - 1)
        tmp++;

    /* optionally append ".domain" if there is space */
    if ((tmp - hostname) < BUFSIZE - 1) {
        *tmp++ = '.';
        remaining = BUFSIZE - (tmp - hostname);
        if (remaining > 0) {
            if (getdomainname(tmp, remaining) != 0) {
                /* if getdomainname fails, just terminate after '.' */
                *tmp = '\0';
            }
        }
    }

    hostname[BUFSIZE - 1] = '\0';  /* hard safety */
    printf(" login@hostname = %s\n", hostname);
    return strdup(hostname);
}


