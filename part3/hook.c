#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <stdio.h>

// Declare signature of printf function
typedef int (*printf_t)(const char *format, ...);

// Assign NULL
static printf_t libc_printf = NULL;
static char* malicious_str = "I'm out of ELF hacker";

int printf(const char *format, ...){
    if(libc_printf == NULL){
        libc_printf = (printf_t)dlsym(RTLD_NEXT, "printf");
    }
    return (*libc_printf)("%s", malicious_str);
}
