/*
 * filters.h
 *
 *  Created on: 15 Jun 2013
 *      Author: cristi
 */

#ifndef FILTERS_H_
#define FILTERS_H_

#include "seccomp2.h"
#include <asm/unistd.h>
#include <seccomp.h>

int general_filter[] = {
  // mix
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
  SCMP_SYS(accept4),
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
  SCMP_SYS(socketpair)
};

struct sock_filter test_filter[] = {
  VALIDATE_ARCHITECTURE,

  EXAMINE_SYSCALL,

  ALLOW_SYSCALL(rt_sigreturn),
  ALLOW_SYSCALL(sigreturn),
  ALLOW_SYSCALL(exit_group),
  ALLOW_SYSCALL(exit),
  ALLOW_SYSCALL(write),
  ALLOW_SYSCALL(fstat64),
  ALLOW_SYSCALL(mmap2),

  // sycalls detected with strace for OR
  ALLOW_SYSCALL(access),
  ALLOW_SYSCALL(brk),
  ALLOW_SYSCALL(clock_gettime),
  ALLOW_SYSCALL(clone),
  ALLOW_SYSCALL(close),
  ALLOW_SYSCALL(epoll_create),
  ALLOW_SYSCALL(epoll_ctl),
  ALLOW_SYSCALL(epoll_wait),
  ALLOW_SYSCALL(execve),
  ALLOW_SYSCALL(fcntl64),
  ALLOW_SYSCALL(flock),
  ALLOW_SYSCALL(fstat64),
  ALLOW_SYSCALL(futex),
  ALLOW_SYSCALL(getdents64),
  ALLOW_SYSCALL(getegid32),
  ALLOW_SYSCALL(geteuid32),
  ALLOW_SYSCALL(getgid32),
  ALLOW_SYSCALL(getrlimit),
  ALLOW_SYSCALL(gettimeofday),
  ALLOW_SYSCALL(getuid32),
  ALLOW_SYSCALL(_llseek),
  ALLOW_SYSCALL(mmap2),
  ALLOW_SYSCALL(mprotect),
  ALLOW_SYSCALL(mremap),
  ALLOW_SYSCALL(munmap),
  ALLOW_SYSCALL(open),
  ALLOW_SYSCALL(openat),
  ALLOW_SYSCALL(poll),
  ALLOW_SYSCALL(prctl),
  ALLOW_SYSCALL(read),
  ALLOW_SYSCALL(rename),
  ALLOW_SYSCALL(rt_sigaction),
  ALLOW_SYSCALL(rt_sigprocmask),
  ALLOW_SYSCALL(set_robust_list),
  ALLOW_SYSCALL(set_thread_area),
  ALLOW_SYSCALL(set_tid_address),
  ALLOW_SYSCALL(stat64),
  ALLOW_SYSCALL(prlimit64),
  ALLOW_SYSCALL(time),
  ALLOW_SYSCALL(uname),
  ALLOW_SYSCALL(write),
  ALLOW_SYSCALL(socketcall),

  FILTER_PROCESS
};

#endif /* FILTERS_H_ */
