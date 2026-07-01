.code64
.section .text
.globl _start
_start:
  mov $6, %rax
  mov $msg, %rdi
  mov $11, %rsi

  syscall

  mov $3, %rax
  mov $1, %rdi

  syscall

.section .rodata
msg: .asciz "Oh my god!\n"
