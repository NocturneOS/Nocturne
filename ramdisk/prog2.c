#if defined __x86_64__
typedef unsigned long long size_t;
#else 
typedef unsigned int size_t;
#endif

#if defined __x86_64__
size_t _syscall5(size_t num, size_t p1, size_t p2, size_t p3, size_t p4, size_t p5) {
    register size_t rax __asm__("rax") = num;
    register size_t rdi __asm__("rdi") = p1;
    register size_t rsi __asm__("rsi") = p2;
    register size_t rdx __asm__("rdx") = p3;
    register size_t r10 __asm__("r10") = p4;
    register size_t r8  __asm__("r8")  = p5;
    
    __asm__ volatile(
        "syscall"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory"
    );
    return rax;
}
#else
size_t _syscall5(size_t num, size_t p1, size_t p2, size_t p3, size_t p4, size_t p5) {
  size_t result;
  __asm__ volatile("int $0x80"
               : "=a"(result)
               : "a"(num),
                 "b"(p1),
                 "c"(p2),
                 "d"(p3),
                 "S"(p4),
                 "D"(p5) : "memory");
  return result;
}
#endif

int strlen(const char* str) {
  if(str == 0) {
        return 0;
    }

    size_t len = 0;
    while (str[len] != 0){
        len++;
    }
    return len;
}

int main(int argc, char** argv) {
  _syscall5(1, (size_t)argc, (size_t)argv, 0, 0, 0);
  for(size_t i = 0; i < argc; i++) {
    int size = strlen(argv[i]);

    //_syscall5(1, (size_t)argc, (size_t)argv, (size_t)argv[i], 0, 0);
    _syscall5(0, (size_t)argv[i], size, 0, 0, 0);
  }

  return 0;
}

#if defined __x86_64__
__attribute__((naked)) void _start() {
  __asm__ volatile(
      //"pop %esi\n"
      //"pop %edi\n"
      "call main\n"

      "mov %rax, %rbx\n"
      "mov $3, %rax\n"
      "xor %edi, %edi\n"
      "syscall\n"
      ".a: jmp .a"
  );
}
#else
__attribute__((naked)) void _start() {
  __asm__ volatile(
      //"pop %esi\n"
      //"pop %edi\n"
      "call main\n"

      "mov %eax, %ebx\n"
      "mov $3, %eax\n"
      "int $0x80"
  );
}
#endif
