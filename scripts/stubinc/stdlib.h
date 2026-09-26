#pragma once
#include <stddef.h>
void *malloc(size_t); void *calloc(size_t, size_t); void *realloc(void *, size_t); void free(void *);
void abort(void); void exit(int); int atoi(const char *); long atol(const char *); long strtol(const char *, char **, int);
unsigned long strtoul(const char *, char **, int); double strtod(const char *, char **); double atof(const char*);
void qsort(void *, size_t, size_t, int (*)(const void *, const void *)); int rand(void); void srand(unsigned);
int abs(int); long labs(long); char *getenv(const char *);
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define RAND_MAX 2147483647
