.code64

.extern syscall_handler

.section .bss
.align 4096
syscall_stack_bottom:
    .skip 16384
syscall_stack_top:

.section .data
.align 16
__user_stack_address: .long 0

.section .text
.align 16
.global __syscall_handler64
__syscall_handler64:
    swapgs

    mov %rsp, __user_stack_address
    mov $syscall_stack_top, %rsp

    pushq $0x23
    pushq __user_stack_address
    pushq %r11
    pushq $0x1b
    pushq %rcx

    # Imitate CPURegisters layout (on IRQ) - push error code and interrupt number
    push $0       # Error code
    push $0x80    # Interrupt code

    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rsp
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
    push $0      # Original DS, not restored

    xor %rbp, %rbp
    mov %rsp, %rdi

    cld
    call syscall_handler

    add $8, %rsp

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rsp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax

    add $16, %rsp
 
    pop %rcx

    add $8, %rsp
    pop %r11
    pop %rsp

    swapgs

    sysretq
