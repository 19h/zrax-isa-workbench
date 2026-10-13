; Synthetic El Torito no-emulation boot image for the ISO 9660 fixtures.
; The BIOS loads it at 0x07C0:0000 (El Torito 1.0, 4.3); it prints a line
; through the BIOS teletype service (INT 10h, AH 0Eh) and halts. Assembled
; with `nasm -f bin`; padded to one 2048-byte CD sector.

bits 16
org 0x7c00

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    sti
    cld
    mov si, message
.print:
    lodsb
    test al, al
    jz .halt
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    jmp .print
.halt:
    hlt
    jmp .halt

message:
    db "zrax iso9660 fixture boot image", 13, 10, 0

    times 2048 - ($ - $$) db 0
