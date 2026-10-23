.set ASP_BASE, 0x58
.set ASP_BASE_FXSAVE, (ASP_BASE)
.set ASP_BASE_TSS_KSTACK, (ASP_BASE + 8)

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
    mov ASP_BASE_FXSAVE(%rsi), %rax
    fxsave (%rax)

    # Load next stack
    mov 0x20(%rcx), %rsp

    # Restore SIMD context
    mov ASP_BASE_FXSAVE(%rcx), %rax
    fxrstor (%rax)

    # TODO: TSS

    # Load kernel stack top to TSS::RSP0
    # 0x48 = Thread::ArchitectureSpecificRegion::tss_kernel_stack
    mov ASP_BASE_TSS_KSTACK(%rcx), %rax
    mov $BSP_TSS, %rbx
    # 0x04 = TSSEntry::rsp0
    mov %rax, 4(%rbx)

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
