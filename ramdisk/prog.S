.code32

.section .data
message: .asciz "Hello, world!"

.section .text
.global _start
_start:
  movl $1, %eax
  movl $message, %ebx
  movl $13, %ecx

  pop %esi  // argv
  pop %edi  // argc

  int $0x80

  .loop: jmp .loop
