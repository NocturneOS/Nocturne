.code32

.section .data
message: .asciz "Hello, world!"

.section .text
.global _start
_start:
  movl $1, %eax  // Register debug
  movl $message, %ebx   // Some data
  movl $13, %ecx  // Some data

  pop %esi  // argv
  pop %edi  // argc

  int $0x80

  movl $2, %eax     // EXIT
  movl $67, %ebx    // Exitcode

  int $0x80

  // THIS BLOCK IS NEVER REACHED
  movl $1, %eax
  int $0x80

  .loop: jmp .loop
