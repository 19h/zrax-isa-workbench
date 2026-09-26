#pragma once
typedef long jmp_buf[64]; int setjmp(jmp_buf); void longjmp(jmp_buf, int);
