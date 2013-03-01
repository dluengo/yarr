KERNEL_DIR := /lib/modules/`uname -r`/build
EXTRA_CFLAGS += -DDEBUG

obj-m += yarr.o
yarr-objs := debug.o funcs.o intrhandler.o interrupt.o syscall.o hide.o \
			 syscallhooks.o hook.o giveprivs.o hideproc.o hidefile.o main.o
hook-objs := syscall.o

all:
	make -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean
