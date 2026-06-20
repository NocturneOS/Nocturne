.code64

.extern syscall_handler

.section .text
.align 16
.global __syscall_handler64
__syscall_handler64:
    swapgs

    push $0x23
    push $0
    push %r11
    push $0x1b
    push %rcx

    push %rax

    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %rax
    push %r8
    push %r9
    push %r10
    push %r11
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    xor %rbp, %rbp
    mov %rsp, %rdi

    call syscall_handler

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rax
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi

    pop %rax

    pop %rcx

    add $8, %rsp
    pop %r11
    pop %rsp

    swapgs

    sysretq