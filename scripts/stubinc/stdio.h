#pragma once
#include <stddef.h>
#include <stdarg.h>
typedef struct _FILE FILE; extern FILE *stdout, *stderr, *stdin;
int printf(const char *, ...); int fprintf(FILE *, const char *, ...); int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...); int vsnprintf(char *, size_t, const char *, va_list); int vprintf(const char*, va_list);
int puts(const char *); int putchar(int); int fputs(const char *, FILE *); int fputc(int, FILE *); int getchar(void);
FILE *fopen(const char *, const char *); int fclose(FILE *); size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *); int fflush(FILE *); int fgetc(FILE*); char *fgets(char*, int, FILE*);
int sscanf(const char*, const char*, ...); int scanf(const char*, ...); void perror(const char*);
#define EOF (-1)
