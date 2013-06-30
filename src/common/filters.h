/*
 * filters.h
 *
 *  Created on: 15 Jun 2013
 *     Author: cristi
 */

#ifndef FILTERS_H_
#define FILTERS_H_

#include "seccomp2.h"
#include <asm/unistd.h>
#include <seccomp.h>

int general_filter[] = {
    SCMP_SYS(access),
    SCMP_SYS(brk),
    SCMP_SYS(clock_gettime),
    SCMP_SYS(close),
    SCMP_SYS(clone),
    SCMP_SYS(epoll_create),
    SCMP_SYS(epoll_ctl),
    SCMP_SYS(epoll_wait),
    SCMP_SYS(execve),
    SCMP_SYS(fcntl64),
    SCMP_SYS(flock),
    SCMP_SYS(fstat64),
    SCMP_SYS(futex),
    SCMP_SYS(getdents64),
    SCMP_SYS(getegid32),
    SCMP_SYS(geteuid32),
    SCMP_SYS(getgid32),
    SCMP_SYS(getrlimit),
    SCMP_SYS(gettimeofday),
    SCMP_SYS(getuid32),
    SCMP_SYS(_llseek),
    SCMP_SYS(mmap2),
    SCMP_SYS(mprotect),
    SCMP_SYS(mremap),
    SCMP_SYS(munmap),
    SCMP_SYS(open),
    SCMP_SYS(openat),
    SCMP_SYS(poll),
    SCMP_SYS(prctl),
    SCMP_SYS(read),
    SCMP_SYS(rename),
    SCMP_SYS(rt_sigaction),
    SCMP_SYS(rt_sigprocmask),
    SCMP_SYS(rt_sigreturn),
    SCMP_SYS(sigreturn),
    SCMP_SYS(set_robust_list),
    SCMP_SYS(set_thread_area),
    SCMP_SYS(set_tid_address),
    SCMP_SYS(stat64),
    SCMP_SYS(time),
    SCMP_SYS(uname),
    SCMP_SYS(write),
    SCMP_SYS(exit_group),
    SCMP_SYS(exit),

    // socket syscalls
    // TODO: fails with -33 (EDOM)
//    SCMP_SYS(accept4),
    SCMP_SYS(bind),
    SCMP_SYS(connect),
    SCMP_SYS(getsockname),
    SCMP_SYS(getsockopt),
    SCMP_SYS(listen),
    SCMP_SYS(recv),
    SCMP_SYS(recvmsg),
    SCMP_SYS(send),
    SCMP_SYS(sendto),
    SCMP_SYS(setsockopt),
    SCMP_SYS(socket),
    SCMP_SYS(socketpair),

    // TODO: remove when accept4 is fixed
    SCMP_SYS(socketcall)
};

#endif /* FILTERS_H_ */

