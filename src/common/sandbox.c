/*
 * sandbox.c
 *
 *  Created on: 15 Jun 2013
 *      Author: cristi
 */
#include <seccomp.h>

#include "sandbox.h"
#include "seccomp2.h"

static int general_filter[] = {
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

static int
install_glob_syscall_filter(void)
{
  int rc = 0, i, filter_size;
  scmp_filter_ctx ctx;

  ctx = seccomp_init(SCMP_ACT_TRAP);
  if (ctx == NULL) {
    rc = -1;
    goto end;
  }

  if (general_filter != NULL) {
    filter_size = sizeof(general_filter) / sizeof(general_filter[0]);
  } else {
    filter_size = 0;
  }

  // add general filters
  for (i = 0; i < filter_size; i++) {
    rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, general_filter[i], 0);
    if (rc != 0) {
      fprintf(stderr, "i=%d, rc=%d\n", i, rc);
      goto end;
    }
  }

  rc = seccomp_load(ctx);

end:
  seccomp_release(ctx);
  return (rc < 0 ? -rc : rc);
}

/**
 * Debugging function which is called when a SIGSYS caught by the application.
 * It prints the bad signal that caused the OS to issue the SIGSYS.
 */
static void
sigsys_debugging(int nr, siginfo_t *info, void *void_context)
{
  ucontext_t *ctx = (ucontext_t *) (void_context);
  int syscall;

  if (info->si_code != SYS_SECCOMP)
    return;

  if (!ctx)
    return;

  syscall = ctx->uc_mcontext.gregs[0];
  fprintf(stderr, "Syscall was intercepted: %d\n!", syscall);

  return;
}

/**
 * Function that adds a handler for SIGSYS, which is the signal thrown
 * when the application is issuing a syscall which is not allowed. The
 * Purpose of this function is to help with debugging by identifying
 * filtered syscalls.
 */
static int
install_sigsys_debugging(void)
{
  struct sigaction act;
  sigset_t mask;

  memset(&act, 0, sizeof(act));
  sigemptyset(&mask);
  sigaddset(&mask, SIGSYS);

  act.sa_sigaction = &sigsys_debugging;
  act.sa_flags = SA_SIGINFO;
  if (sigaction(SIGSYS, &act, NULL) < 0) {
    perror("sigaction");
    return -1;
  }

  if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
    perror("sigprocmask");
    return -1;
  }

  return 0;
}

/**
 * Stage 1 function that enables the global sandbox.
 */
int
tor_global_sandbox(void)
{
  int ret = 0;

  ret = install_sigsys_debugging();
  if (ret)
    return -1;

  ret = install_glob_syscall_filter();
  if (ret)
    return -1;

  return ret;
}

