#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "types.h"

/***
 * This program just tries to get privileges using yarr.
 */
int main(int argc, char *argv[], char *envp[]) {
	syscallData data;

	data.pid = getpid();
	printf("EUID before syscall: %d\n", geteuid());
	syscall(YARR_SYSCALL, GIVE_PRIVILEGES, &data);
	printf("EUID after syscall: %d\n", geteuid());
	return 0;
}
