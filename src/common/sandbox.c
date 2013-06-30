/*
 * sandbox.c
 *
 *  Created on: 15 Jun 2013
 *      Author: cristi
 */

#include "sandbox.h"
#include "seccomp2.h"
#include "filters.h"

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

  syscall = ctx->uc_mcontext.gregs[REG_SYSCALL];
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

