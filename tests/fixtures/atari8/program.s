; Synthetic Atari 8-bit program for the zrax binary load fixture.
; An init routine sets the playfield 2 color; the main program sets the
; border color and loops. Encodings are the NMOS 6502 opcodes.

        .export init, start

COLOR2  = $02C6         ; playfield 2 color shadow ("Mapping the Atari", 710)
COLOR4  = $02C8         ; border color shadow ("Mapping the Atari", 712)

        .segment "INIT"
init:   lda #$94        ; A9 94     LDA #imm
        sta COLOR2      ; 8D C6 02  STA abs
        rts             ; 60        RTS

        .segment "CODE"
start:  lda #$46        ; A9 46     LDA #imm
        sta COLOR4      ; 8D C8 02  STA abs
loop:   jmp loop        ; 4C 05 2E  JMP abs (to itself at $2E05)
