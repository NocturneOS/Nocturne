const char* message = "Hello, world!";

extern void _start() {
  __asm__ volatile("int $0x80" :: "a"(0x00), "b"(message), "c"(13));

  while(1) {
    __asm__ volatile("nop");
  }
}
