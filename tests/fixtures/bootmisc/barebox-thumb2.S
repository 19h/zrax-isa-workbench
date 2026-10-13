/* The ARM32 barebox head with CONFIG_THUMB2_BAREBOX (barebox v2024.10.0
 * arch/arm/include/asm/barebox-arm-head.h), text base 0, image size 0x200,
 * followed by the two Thumb NOPs after label 2. */
	.syntax unified
	.text
	.globl start
start:
	.arm
	adr r9, 1f + 1
	bx r9
	.thumb
	1:
	bl 2f
	.rept 10
	1: b 1b
	.endr
	.asciz "barebox"
	.word 0
	.word 0x200
	.rept 8
	.word 0x55555555
	.endr
	2:
	nop
	nop
