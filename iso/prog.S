.text
.global _start
_start:
  mov $1, %eax
  mov message, %ebx
  int $0x80

.rodata
message: .asciz "Hello, world!"
