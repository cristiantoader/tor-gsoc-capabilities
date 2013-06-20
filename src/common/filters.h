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
