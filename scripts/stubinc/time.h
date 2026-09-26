#pragma once
#include <stddef.h>
typedef long time_t; typedef long clock_t; time_t time(time_t *); clock_t clock(void);
#define CLOCKS_PER_SEC 1000000
