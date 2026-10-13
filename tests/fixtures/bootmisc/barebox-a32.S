/* The ARM32 barebox head (__barebox_arm_head, barebox v2024.10.0
 * arch/arm/include/asm/barebox-arm-head.h) with a text base of 0 and an
 * image size of 0x200, followed by the two NOPs after label 2. */
	.arm
	.text
	.globl start
start:
	b 2f
	1: b 1b
	1: b 1b
	1: b 1b
	1: b 1b
	1: b 1b
	1: b 1b
	1: b 1b
	.asciz "barebox"
	.word 0
	.word 0x200
	.rept 8
	.word 0x55555555
	.endr
	2:
	nop
	nop
