.code64

.section .text
.globl _start
_start:
  movq $1, %rax   # Syscall nr.

  mov $0x0123456789ABCDEF, %rdi   # Argument 1
  mov $0x0123456789ABCDEF, %rsi   # Argument 2
  mov $0x0123456789ABCDEF, %rdx   # Argument 3
  mov $0x0123456789ABCDEF, %r10   # Argument 4
  mov $0x0123456789ABCDEF, %r8    # Argument 5
  mov $0x0123456789ABCDEF, %r9    # Argument 6
  syscall

  nop

  .a: jmp .a
