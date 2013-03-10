#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include "types.h"

int main(int argc, char *argv[]) {
	syscallData data;

	data.pid = getpid();
	printf("Hi, I'm task with pid %d.\n", data.pid);
	printf("EUID before interrupt: %d.\n", geteuid());

	// BEWARE!: We are hardcoding "int $101", the interrupt vector that
	// YARR is using right now, in the future this can change. It would have
	// been much nicer include "types.h" and use YARR_IRQ macro instead, but
	// since I'm a noob with inline assembly I don't know how to specify that
	// "int" must use YARR_IRQ... I though about creating a string with
	// strcat() and all that stuff and then I decided to hardcode :D.

	// NOTE: That passing args to the interrupt handler is done through
	// registers, this is because since we are changing the privilege level
	// (from ring3 to ring0) the stack segment change from the segment of the
	// process to the segment of the kernel, so you cannot pass arguments in
	// the stack... well there are tricks that we can do, code in the interrupt
	// handler the logic to go to the process stack segment and take from there
	// the arguments... I'm lazy right now :).
	__asm__("movl %0, %%ebx\n\t"
			"movl %1, %%eax\n\t"
			"int $101"
			:
			: "r"(&data), "r"(GIVE_PRIVILEGES)
			);
	printf("EUID after interrupt: %d.\n", geteuid());
}
