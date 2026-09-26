#pragma once
void __assert_fail(const char*, const char*, int);
#define assert(x) ((x) ? (void)0 : __assert_fail(#x, __FILE__, __LINE__))
