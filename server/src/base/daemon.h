#include <stdlib.h>
#include <stdio.h>
#include <util.h>

int tt_daemon()
{
    int  fd;
    int  pid;

    switch (fork()) {
    case -1:
        ERROR("fork() failed");
        return -1;

    case 0:
        break;

    default:
        exit(0);
    }

    pid = getpid();

    if (setsid() == -1) {
        FATAL("setsid() failed");
        return -1;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        FATAL("open(\"/dev/null\") failed");
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        FATAL("dup2(STDIN) failed");
        return -1;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        FATAL("dup2(STDOUT) failed");
        return -1;
    }

#if 0
    if (dup2(fd, STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "dup2(STDERR) failed");
        return NGX_ERROR;
    }
#endif

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            FATAL("close() failed");
            return -1;
        }
    }

    return 1;
}
