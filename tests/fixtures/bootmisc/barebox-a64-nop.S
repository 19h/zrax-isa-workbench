/* The AArch64 barebox head __barebox_arm64_head (barebox v2024.10.0
 * arch/arm/cpu/head_64.S), image size 0x200. Local labels stand in for the
 * board symbols __pbl_board_stack_top (3) and __pbl_board_entry (4). */
	.text
	.globl start
start:
	nop
	adr x9, 3f
	ldr x9, [x9]
	cbz x9, 1f
	mov sp, x9
1:
	nop
	nop
	b 4f
	.org 0x20
	.asciz "barebox"
	.word 0xffffffff
	.word 0x200
	.rept 8
	.word 0x55555555
	.endr
3:
	.quad 0
4:
	nop
