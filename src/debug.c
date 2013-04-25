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

#include <asm/desc.h>
#include <asm/irq_vectors.h>
#include <asm/segment.h>
#include <linux/fs.h>

// Own libraries.
#include "debug.h"

/***
 * The core function to print debug messages (in fact any message, it
 * should be used any time you want to print something).
 *
 * The reason is that since we want yarr to be as undetectable as possible we
 * don't want it to print lots of messages in an "official release", although
 * we would like yarr to print info during the development. Using debug() when
 * we want to print something will make easy to change the behaviour of yarr,
 * we just need to compile with the DEBUG macro or not.
 */
void debug(const char *fmt, ...) {
#ifdef DEBUG
	va_list arg;

	va_start(arg, fmt);
	vprintk(fmt, arg);
	va_end(arg);
#endif
	return;
}

void printIDTEntry(gate_desc *idt_entry) {
	debug("offset low  : 0x%08x\n", idt_entry->limit0);
	debug("selector    : 0x%08x\n", idt_entry->base0);
	debug("zero        : 0x%08x\n", idt_entry->base1);
	debug("attr        : 0x%08x\n", (idt_entry->b & 0xFF00) >> 8);
	debug("offset_high : 0x%08x\n", (idt_entry->b & 0xFFFF0000) >> 16);
	return;
}

void printGDTEntry(gate_desc *gdt_entry) {
	debug("limit       : 0x%08x\n", gdt_entry->limit0);
	debug("base low    : 0x%08x\n", gdt_entry->base0);
	debug("base mid    : 0x%08x\n", gdt_entry->base1);
	debug("access      : 0x%08x\n", (gdt_entry->b & 0xFF00) >> 8);
	debug("attr        : 0x%08x\n", (gdt_entry->b & 0xFF0000) >> 16);
	debug("base high   : 0x%08x\n", gdt_entry->base2);
	return;
}

void printIDTEntryByIndex(unsigned int n) {
	struct desc_ptr idtr;
	gate_desc *entry;

	// Check we are in range.
	if (n < 0 || n >= NR_VECTORS) {
		debug("printIDTEntry(): index %d out of range.\n", n);
		return;
	}

	store_idt(&idtr);
	entry = ((gate_desc *)idtr.address) + n;
	debug("--- IDT entry %d ---\n", n);
	printIDTEntry(entry);
	return;
}

void printGDTEntryByIndex(unsigned int n) {
	struct desc_ptr gdtr;
	gate_desc *entry;

	// Check we are in range.
	if (n < 0 || n >= GDT_ENTRIES) {
		debug("printGDTEntry(): index %d out of range.\n", n);
		return;
	}

	store_gdt(&gdtr);
	entry = ((gate_desc *)gdtr.address) + n;
	debug("--- GDT entry %d ---\n", n);
	printIDTEntry(entry);
	return;
}

void printIDTR() {
	struct desc_ptr idtr;

	store_idt(&idtr);
	debug("size    : %hd\n", idtr.size);
	debug("address : 0x%lx\n", idtr.address);
	return;
}

void printGDTR() {
	struct desc_ptr gdtr;

	store_gdt(&gdtr);
	debug("size    : %hd\n", gdtr.size);
	debug("address : 0x%lx\n", gdtr.address);
	return;
}

void printIDT() {
	struct desc_ptr idtr;
	int i;

	store_idt(&idtr);
	for (i=0; i<(idtr.size+1)/8; i++)
		printIDTEntryByIndex(i);
	return;
}

void printGDT() {
	struct desc_ptr gdtr;
	int i;

	store_gdt(&gdtr);
	for (i=0; i<(gdtr.size+1)/8; i++)
		printGDTEntryByIndex(i);
	return;
}

// Some code borrowed from man getdents :).
void printDirent64(struct linux_dirent64 *dirent) {
	debug("Inode: %ld\n", dirent->d_ino);
	debug("Offset next dirent: %lld\n", dirent->d_off);
	debug("Record length: %hd\n", dirent->d_reclen);
	debug("Type: %s\n", (dirent->d_type == DT_REG) ?  "regular" :
						(dirent->d_type == DT_DIR) ?  "directory" :
						(dirent->d_type == DT_FIFO) ? "FIFO" :
						(dirent->d_type == DT_SOCK) ? "socket" :
						(dirent->d_type == DT_LNK) ?  "symlink" :
						(dirent->d_type == DT_BLK) ?  "block dev" :
						(dirent->d_type == DT_CHR) ?  "char dev" : "???");
	debug("Name: %s\n", dirent->d_name);
	return;
}

// Some code borrowed (again) from man getdents.
void printDirent64List(char *dirent, size_t len) {
	struct linux_dirent64 *d;
	int bpos;

	if (dirent == NULL)
		return;

	debug("------------------- Dentry list ----------------------\n");
	for (bpos=0; bpos<len;) {
		d = (struct linux_dirent64 *)(dirent + bpos);
		printDirent64(d);
		debug("\n");

		bpos += d->d_reclen;
	}

	debug("------------------ Dentry list end --------------------\n");
	return;
}

