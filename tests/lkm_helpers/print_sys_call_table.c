#include <linux/module.h>

void *search_call_opcode(void *code) {
    // TODO: Hardware-dependant (x86 32 bits).
    // \xff\x14\x85 is the opcode of a call instruction on x86 systems... this
    // is not totally true, in fact it is the opcode of the instruction
    // call *<address>(,%eax,4).
    while ((*(u32 *)(code++) & 0x00ffffff ) != 0x008514ff);
    return --code;
}

unsigned long **getSyscallTable(void) {
    struct desc_ptr idtr, gdtr;
    struct desc_struct *idt_entry, *gdt_entry;
    u32 gate_offset, gate_base;
    u8 *syscall_desc, *call_offset;

    native_store_idt(&idtr);
    native_store_gdt(&gdtr);

    idt_entry = (struct desc_struct *)idtr.address + 0x80;
    gdt_entry = (struct desc_struct *)gdtr.address + gate_segment(*idt_entry);
    gate_offset = (u32)gate_offset(*idt_entry);
    gate_base = (u32)get_desc_base(gdt_entry);
    syscall_desc = (u8 *)(gate_base + gate_offset);

    call_offset = search_call_opcode(syscall_desc);
    return *(unsigned long ***)(call_offset + 3);
}

/***
 * Takes the hardcoded sys_call_table address inside system_call() and prints
 * it.
 */
static int __init loader(void) {
	unsigned long **sys_call_table;

	sys_call_table = getSyscallTable();
	printk(KERN_ALERT "sys_call_table is at %p\n", sys_call_table);
	return 0;
}

static void __exit unloader(void) {
	return;
}

module_init(loader);
module_exit(unloader);

