.code64
.global __context_switch
__context_switch:
    pushfq

    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15

    # RDI = THIS PROCESS
    # RSI = THIS THREAD
    # RDX = NEXT PROCESS
    # RCX = NEXT THREAD

    # Save stack pointer (0x20 = Thread::ThreadStack::stack_pointer)
    mov %rsp, 0x20(%rsi)

    # Save SIMD context (0x20 = Thread::arch_specific_region)
    mov 0x40(%rsi), %rax
    fxsave (%rax)

    # Load next stack
    mov 0x20(%rcx), %rsp

    # Restore SIMD context
    mov 0x40(%rcx), %rax
    fxrstor (%rax)

    # TODO: TSS

    # Get current process' root page directory (RPD)
    mov 0x8(%rdi), %rax   # RPD of current process
    mov 0x8(%rdx), %rbx   # RPD of next process

    cmp %rax, %rbx
    je .done

    mov %rbx, %cr3

.done:

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax

    popfq

    ret
