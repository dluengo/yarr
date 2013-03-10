KERNEL_DIR := /lib/modules/`uname -r`/build

obj-m += print_sys_call_table.o

all:
	make -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean

