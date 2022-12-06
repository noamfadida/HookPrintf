#define stdout 1

#define SYSCALL_EXIT 60
#define SYSCALL_WRITE 1

void sys_exit(int error_code)
{
    asm volatile
    (
        "syscall"
        : 
        : "a"(SYSCALL_EXIT), "D"(error_code)
        : "rcx", "r11", "memory"
    );
}

int sys_write(unsigned fd, const char *buf, unsigned count)
{
    unsigned ret;

    asm volatile
    (
        "syscall"
        : "=a"(ret)
        : "a"(SYSCALL_WRITE), "D"(fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    
    return ret;
}

int fake_printf(const char *format, ...){
    char malicious_str[] = "I'm hacker";
    sys_write(stdout, malicious_str, sizeof(malicious_str));
    sys_exit(12);
}

// int main(){
//     fake_printf("Hey");
//     return 0;
// }