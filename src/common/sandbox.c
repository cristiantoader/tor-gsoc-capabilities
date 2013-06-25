/*
 * sandbox.c
 *
 *  Created on: 15 Jun 2013
 *      Author: cristi
 */

#include "sandbox.h"
#include "seccomp2.h"
#include "filters.h"

#define __LIBSECCOMP__

static int install_seccomp2(void) {
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(test_filter)/sizeof(test_filter[0])),
    .filter = test_filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    goto failed;
  }

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    perror("prctl(SECCOMP)");
    goto failed;
  }
  return 0;

  failed:
  if (errno == EINVAL)
  fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
  return 1;
}

static int install_libseccomp(void) {
  int rc = 0, i, filter_size;
  scmp_filter_ctx ctx;

  do {
    ctx = seccomp_init(SCMP_ACT_TRAP);
    if (ctx == NULL) {
      rc = -1;
      break;
    }

    if(general_filter != NULL) {
      filter_size = sizeof(general_filter) / sizeof(general_filter[0]);
    } else {
      filter_size = 0;
    }

    // TODO: precise file filters

    // add general filters
    for(i = 0; i < filter_size; i++) {
      rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, general_filter[i], 0);
      if (rc != 0) {
        break;
      }
    }

    if(rc != 0) {
      break;
    }

    rc = seccomp_load(ctx);
    if(rc != 0) {
      break;
    }

  } while(0);

  seccomp_release(ctx);

  return (rc < 0 ? -rc : rc);
}

static int install_syscall_filter(void) {
  int ret = 0;

#ifdef __LIBSECCOMP__
  ret = install_libseccomp();
#else
  ret = install_seccomp2();
#endif

  return ret;
}

static void emulator(int nr, siginfo_t *info, void *void_context) {
  ucontext_t *ctx = (ucontext_t *) (void_context);
  int syscall;
//  char *buf;
//  ssize_t bytes;
//  size_t len;

  if (info->si_code != SYS_SECCOMP)
    return;

  if (!ctx)
    return;

  syscall = ctx->uc_mcontext.gregs[REG_SYSCALL];
//  buf = (char *) ctx->uc_mcontext.gregs[REG_ARG1];
//  len = (size_t) ctx->uc_mcontext.gregs[REG_ARG2];

  fprintf(stderr, "Cought syscall %d\n", syscall);

  return;
}

static int install_emulator(void) {
  struct sigaction act;
  sigset_t mask;
  memset(&act, 0, sizeof(act));
  sigemptyset(&mask);
  sigaddset(&mask, SIGSYS);

  act.sa_sigaction = &emulator;
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

int tor_global_sandbox() {
  int ret = 0;

  install_emulator();
  ret = install_syscall_filter();

  return ret;
}
