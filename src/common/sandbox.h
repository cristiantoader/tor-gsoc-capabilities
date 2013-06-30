/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file sandbox.h
 * \brief Header file for sandbox.c.
 **/

#ifndef SANDBOX_H_
#define SANDBOX_H_

#ifndef SYS_SECCOMP

/**
 * Used by SIGSYS signal handler to check if the signal was issued due to a
 * seccomp2 filter violation.
 */
#define SYS_SECCOMP 1

#endif

int tor_global_sandbox(void);

#endif /* SANDBOX_H_ */

