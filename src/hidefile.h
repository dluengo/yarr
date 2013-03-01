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
 * @name: The path to the file.
 * @return: Zero on success or -1 if there were errors.
 */
int hideFile(const char *name);

/***
 * Stops hidding the specified file.
 *
 * @name: The path to the file.
 * @return: Zero on success or -1 if there were errors.
 */
int stopHideFile(const char *name);

/***
 * Tells whether a file is being (should be) hide or not.
 *
 * @name: The path of the file to check for.
 * @return: Zero if the file is not being hidden or non-zero elsewhere.
 */
int isFileHidden(const char *name);

#endif /* __YARR_NINJA_FILES. */

