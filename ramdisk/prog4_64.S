.code64
.section .text
.globl _start
_start:
  mov $10, %rax
  mov $1, %rdi
  mov $msg, %rsi
  mov $11, %rdx

  syscall

  mov $3, %rax
  mov $1, %rdi

  syscall

.section .rodata
msg: .asciz "Oh my god!\n"
