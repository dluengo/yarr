#include <unistd.h>
#include "types.h"

int main(int argc, char *argv[]) {
	syscall(YARR_SYSCALL, UNLOAD_YARR, NULL);
}

