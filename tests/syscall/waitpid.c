#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SECS_SLEEP (5)

int main(int argc, char *argv[]) {
	int child_pid, status;

	child_pid = fork();
	if (child_pid == -1)
		printf("Error fork().\n"), exit(-1);
	// The child sleeps a few seconds.
	else if (child_pid == 0)
		sleep(SECS_SLEEP);
	// The father waits for the child.
	else
		waitpid(child_pid, &status, 0);

	return 0;
}
