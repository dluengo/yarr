#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>

#include "types.h"

/***
 * SIGINT handler. When ctrl + c is pushed the task tries to stop being
 * hide.
 */
void term_handler(int sig) {
	syscallData data;

	data.pid = getpid();
	syscall(YARR_SYSCALL, STOP_HIDE_PROCESS, &data);
	exit(0);
}

/***
 * This program just tries to hides itself using yarr, then it goes into an
 * infinite loop until a signal (or anything) cause it to end.
 */
int main(int argc, char *argv[]) {
	syscallData data;

	// Hide myself.
	data.pid = getpid();
	printf("Process %d will hide.\n", data.pid);
	syscall(YARR_SYSCALL, HIDE_PROCESS, &data);

	// Set the handler for SIGINT.
	signal(SIGINT, term_handler);

	// Do nothing until we receive SIGINT (or other signals, but the
	// interesting one is SIGINT).
	while(0x01ec0ded);
	return 0;
}
