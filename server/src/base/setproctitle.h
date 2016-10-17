/*
 * setproctitle.h
 *
 *  Created on: 2016年4月27日
 *      Author: root
 */

#ifndef BASE_SETPROCTITLE_H_
#define BASE_SETPROCTITLE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char 			 **environ;
extern int              tt_argc;
extern char           **tt_argv;
extern char           **tt_os_argv;
static char 			 *tt_os_argv_last;

int init_setproctitle()
{
    u_char      *p;
    size_t       size;
    int   i;

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    p = (u_char*)malloc(size);
    if (p == NULL) {
        return -1;
    }

    tt_os_argv_last = tt_argv[0];

    for (i = 0; tt_os_argv[i]; i++) {
        if (tt_os_argv_last == tt_os_argv[i]) {
            tt_os_argv_last = tt_os_argv[i] + strlen(tt_os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (tt_os_argv_last == environ[i]) {

            size = strlen(environ[i]) + 1;
            tt_os_argv_last = environ[i] + size;

            tt_cpystrn(p, (u_char *) environ[i], size);
            environ[i] = (char *) p;
            p += size;
        }
    }

    tt_os_argv_last--;

    return 0;
}


void tt_setproctitle(char *title)
{
    u_char     *p;

    tt_os_argv[1] = NULL;

    p = tt_cpystrn((u_char *) tt_os_argv[0], (u_char *) "tt: ",
                    tt_os_argv_last - tt_os_argv[0]);

    p = tt_cpystrn(p, (u_char *) title, tt_os_argv_last - (char *) p);


    if (tt_os_argv_last - (char *) p) {
        memset(p, '\0', tt_os_argv_last - (char *) p);
    }
    //DEBUG("setproctitle: \"%s\"", tt_os_argv[0]);
}


#endif /* BASE_SETPROCTITLE_H_ */
