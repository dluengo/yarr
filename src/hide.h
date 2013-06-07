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

#ifndef __YARR_WE_HIDE_AS_NINJAS_BUT_WE_ARE_STILL_PIRATES
#define __YARR_WE_HIDE_AS_NINJAS_BUT_WE_ARE_STILL_PIRATES

/***
 * Apply a variety of techniques in order to hide YARR.
 *
 * @return: Zero if sucessful or -1 if there were errors.
 */
int hideYARR(void);

/***
 * Service to ask yarr to unload itself. Since yarr won't be in the kernel
 * modules list calling sys_delete_module will fail so we have to do it
 * ourself.
 */
int unloadMe(void);

#endif /* __YARR_WE_HIDE_AS_NINJAS_BUT_WE_ARE_STILL_PIRATES. */

