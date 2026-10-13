; Synthetic 16-bit real-mode code for the PC/GEOS geode tests. The tests
; place it in a geode code resource. The routines are written in the style
; of PC/GEOS library code: register saves, far calls with zero targets (glue
; leaves call sites unrelocated and lists them in the relocation table),
; string and arithmetic loops, and far returns. Nothing here is copied from
; PC/GEOS.

bits 16

; Save registers, call a library routine and store its result in dgroup.
store_result:
        push    cx
        push    dx
        push    bx
        push    bp
        push    si
        push    di
        push    es
        push    ds
        mov     bx, 1
        call    0:0
        mov     [0x0006], ax
        cmp     word [0x0006], 0
        jne     .stored
        mov     [0x0006], ax
.stored:
        pop     ds
        pop     es
        pop     di
        pop     si
        pop     bp
        pop     bx
        pop     dx
        pop     cx
        retf

; Copy a zero-terminated string from ds:si to es:di; returns the length in
; cx.
copy_string:
        push    ax
        push    si
        push    di
        xor     cx, cx
        cld
.next:
        lodsb
        stosb
        inc     cx
        test    al, al
        jnz     .next
        dec     cx
        pop     di
        pop     si
        pop     ax
        retf

; Sum cx words at ds:si into dx:ax.
sum_words:
        push    bp
        mov     bp, sp
        push    si
        push    cx
        xor     ax, ax
        xor     dx, dx
        jcxz    .done
.loop:
        add     ax, [si]
        adc     dx, 0
        add     si, 2
        loop    .loop
.done:
        pop     cx
        pop     si
        mov     sp, bp
        pop     bp
        retf

; Compare cx bytes at ds:si and es:di; carry set when they differ.
compare_bytes:
        push    si
        push    di
        push    cx
        repe    cmpsb
        je      .equal
        stc
        jmp     .out
.equal:
        clc
.out:
        pop     cx
        pop     di
        pop     si
        retf

; A frame-based routine as a C compiler emits it: arguments at [bp+6] and
; [bp+8], a local at [bp-2].
scale_value:
        push    bp
        mov     bp, sp
        sub     sp, 2
        push    si
        mov     ax, [bp+6]
        mov     si, [bp+8]
        mov     [bp-2], ax
        shl     ax, 1
        add     ax, [bp-2]
        mul     si
        mov     cx, 10
        div     cx
        pop     si
        mov     sp, bp
        pop     bp
        retf    4

; Lock a block, fill it and unlock it, through library far calls.
fill_block:
        push    ax
        push    bx
        push    cx
        push    di
        push    es
        mov     bx, dx
        call    0:0
        mov     es, ax
        xor     di, di
        mov     cx, 0x0080
        mov     ax, 0x2020
        rep     stosw
        call    0:0
        pop     es
        pop     di
        pop     cx
        pop     bx
        pop     ax
        retf

; Dispatch on a function number in di through a near jump table.
dispatch:
        cmp     di, 4
        jae     .bad
        shl     di, 1
        jmp     [cs:di + .table]
.bad:
        stc
        retf
.table:
        dw      .init, .exit, .suspend, .unsuspend
.init:
        mov     ax, 1
        clc
        retf
.exit:
        xor     ax, ax
        clc
        retf
.suspend:
        mov     ax, 2
        clc
        retf
.unsuspend:
        mov     ax, 3
        clc
        retf
