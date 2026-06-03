#if defined __x86_64__
typedef unsigned long long size_t;
#else 
typedef unsigned int size_t;
#endif

size_t _syscall5(size_t num, size_t p1, size_t p2, size_t p3, size_t p4, size_t p5) {
  size_t result = 0;
  __asm__ volatile("int $0x80"
               : "=a"(result)
               : "a"(num),
                 "b"(p1),
                 "c"(p2),
                 "d"(p3),
                 "S"(p4),
                 "D"(p5));
  return result;
}

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
  for(int i = 0; i < argc; i++) {
    int size = strlen(argv[i]);

    //_syscall5(1, (size_t)argc, (size_t)argv, (size_t)argv[i], 0, 0);
    _syscall5(0, (size_t)argv[i], size, 0, 0, 0);
  }

  return 0;
}

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
