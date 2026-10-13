/* The AArch64 barebox head of ENTRY_PROC (barebox v2024.10.0
 * arch/arm/include/asm/barebox-arm64.h), image size 0x200, followed by one
 * NOP after label 2. */
	.text
	.globl start
start:
	b 2f
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	.asciz "barebox"
	.word 0xffffffff
	.word 0x200
	.rept 8
	.word 0x55555555
	.endr
	2:
	nop
