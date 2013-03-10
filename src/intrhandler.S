.globl yarrIntrDesc

.extern do_yarrIntrDesc

/*
 * Saves/restores the state of the processor registers.
 */
.macro SAVE_ALL
	pushl %ds
	pushl %es
	pushl %fs
	pushl %gs
	pusha
.endm

.macro RESTORE_ALL	
	popa
	popl %gs
	popl %fs
	popl %es
	popl %ds
.endm

.text

/*
 * This is were we land when a userland program executes "int $YARR_IRQ". This
 * is just a wrapper to do_yarrIntrDesc() but since we are dealing with IRQs we
 * need to code this in assembler. We prepare the stack to looks as C functions
 * wants (you know, parameters onto the stack) and then call it.
 */
yarrIntrDesc:
	cld
	SAVE_ALL

	/*
	 * TODO: This is what Linux does, we should investigate why...
	 */
	movl $0x7b, %edx
	movl %edx, %ds
	movl %edx, %es
	movl $0xd8, %edx
	movl %edx, %fs
	movl $0xe0, %edx
	movl %edx, %gs
	movl $0xffffe000,%ebp
	andl %esp,%ebp

	/*
	 * We expect the args from the program that executes "int $YARR_IRQ" to be
	 * passed in registers (eax and ebx). Since we will call do_yarrIntrDesc(),
	 * the function that makes the real work, we cannot pass those args onto the
	 * stack because we are changing level privileges (from ring3 to ring0) and
	 * therefore there will be a stack segment change.
	 */
	pushl %ebx
	pushl %eax
	call do_yarrIntrDesc
	popl %ebx
	popl %ebx

	RESTORE_ALL
	iret

