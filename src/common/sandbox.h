/*
 * sandbox.h
 *
 *  Created on: 15 Jun 2013
 *      Author: cristi
 */

#ifndef SANDBOX_H_
#define SANDBOX_H_

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

int tor_global_sandbox(void);

#endif /* SANDBOX_H_ */

