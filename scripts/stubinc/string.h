#pragma once
#include <stddef.h>
void *memcpy(void *, const void *, size_t); void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t); int memcmp(const void *, const void *, size_t);
void *memchr(const void *, int, size_t);
size_t strlen(const char *); int strcmp(const char *, const char *); int strncmp(const char *, const char *, size_t);
char *strcpy(char *, const char *); char *strncpy(char *, const char *, size_t); char *strcat(char *, const char *);
char *strchr(const char *, int); char *strrchr(const char *, int); char *strstr(const char *, const char *);
char *strdup(const char *); char *strtok(char *, const char *); size_t strspn(const char*, const char*); size_t strcspn(const char*, const char*);
