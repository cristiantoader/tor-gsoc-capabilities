/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file sandbox.c
 * \brief Code to enable sandboxing.
 **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sandbox.h"
#include "torlog.h"

#define __DEBUGGING_CLOSE

/*
 * Based on the implementation and OS features, a more restrictive ifdef
 * should be defined.
 */
#if defined(__linux__)

#include <seccomp.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>

/** Variable used for storing all syscall numbers that will be allowed with the
 * stage 1 general Tor sandbox.
 */
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
    SCMP_SYS(mlockall),
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
    SCMP_SYS(socketpair),

    // TODO: remove when accept4 is fixed
    SCMP_SYS(socketcall)
};

/**
 * Function responsible for setting up and enabling a global syscall filter.
 * The function is a prototype developed for stage 1 of sandboxing Tor.
 * Returns 0 on success.
 */
static int
install_glob_syscall_filter(void)
{
  int rc = 0, i, filter_size;
  scmp_filter_ctx ctx;

  ctx = seccomp_init(SCMP_ACT_TRAP);
  if (ctx == NULL) {
    log_err(LD_BUG,"(Sandbox) failed to initialise libseccomp context");
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
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, general_filter[i], 0);
    if (rc != 0) {
      log_err(LD_BUG,"(Sandbox) failed to add syscall index %d ,"
          "received libseccomp error %d", i, rc);
      goto end;
    }
  }

  rc = seccomp_load(ctx);

 end:
  seccomp_release(ctx);
  return (rc < 0 ? -rc : rc);
}

/**
 * Function called when a SIGSYS is caught by the application. It notifies the
 * user that an error has occurred and either terminates or allows the
 * application to continue execution, based on the __DEBUGGING_CLOSE symbol.
 */
static void
sigsys_debugging(int nr, siginfo_t *info, void *void_context)
{
  ucontext_t *ctx = (ucontext_t *) (void_context);
  char message[64];
  int rv = 0, syscall, length;

  if (info->si_code != SYS_SECCOMP)
    return;

  if (!ctx)
    return;

  syscall = ctx->uc_mcontext.gregs[11];

  length = snprintf(message, 64, "(Sandbox) bad syscall (%d) was caught.\n",
      syscall);

  rv = write(STDOUT_FILENO, message, length);
  if (rv != length)
    _exit(2);

#if defined(__DEBUGGING_CLOSE)
  _exit(1);
#endif // __DEBUGGING_CLOSE
}

/**
 * Function that adds a handler for SIGSYS, which is the signal thrown
 * when the application is issuing a syscall which is not allowed. The
 * main purpose of this function is to help with debugging by identifying
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
    log_err(LD_BUG,"(Sandbox) Failed to register SIGSYS signal handler");
    return -1;
  }

  if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
    log_err(LD_BUG,"(Sandbox) Failed call to sigprocmask()");
    return -2;
  }

  return 0;
}
#endif // __linux__

#ifdef __linux__
/**
 * Initialises the syscall sandbox filter for any linux architecture, taking
 * into account various available features for different linux flavours.
 */
static int
initialise_linux_sandbox(void)
{
  if (install_sigsys_debugging())
    return -1;

  if (install_glob_syscall_filter())
    return -2;

  return 0;
}

#endif // __linux__

/**
 * Enables the stage 1 general sandbox. It applies a syscall filter which does
 * not restrict any Tor features. The filter is representative for the whole
 * application.
 */
int
tor_global_sandbox(void)
{

#if defined(__linux__)
  return initialise_linux_sandbox();

#elif defined(_WIN32)
  log_warn(LD_BUG,"Windows sandboxing is not implemented. The feature is "
      "currently disabled.");
  return 0;

#elif defined(TARGET_OS_MAC)
  log_warn(LD_BUG,"Mac OSX sandboxing is not implemented. The feature is "
      "currently disabled");
  return 0;

#endif
}

