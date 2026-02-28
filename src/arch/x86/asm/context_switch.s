.extern BSP_TSS
.global __context_switch
__context_switch:
    pushf

    push %eax
    push %ebx
    push %ecx
    push %edx
    push %esi
    push %edi
    push %ebp

    # ESP + 36 -> current process
    # ESP + 40 -> current thread
    # ESP + 44 -> next process
    # ESP + 48 -> next thread

    mov 36(%esp), %esi  # Current process
    mov 44(%esp), %edi  # Next process

    mov 40(%esp), %eax  # Current thread
    mov 48(%esp), %ebx  # Next thread

    # Save stack (0x10 = Thread::ThreadStack::stack_pointer)
    mov %esp, 0x10(%eax)

    # Save SIMD context (0x20 = Thread::arch_specific_region)
    mov 0x20(%eax), %ecx
    fxsave (%ecx)

    # Load stack
    mov 0x10(%ebx), %esp

    # Restore SIMD context
    mov 0x20(%ebx), %edx
    fxrstor (%edx)

    # Load kernel stack top to TSS::ESP0
    # 0x24 = Thread::ArchitectureSpecificRegion::tss_kernel_stack
    mov 0x24(%eax), %ecx
    mov $BSP_TSS, %edx
    # 0x04 = TSSEntry::esp0
    mov %eax, 4(%edx)

    # Get current process' PD
    mov 0x4(%esi), %ecx   # PD of current process
    mov 0x4(%edi), %edx   # PD of next process

    cmp %ecx, %edx
    je .done

    mov %edx, %cr3

    .done:

    pop %ebp
    pop %edi
    pop %esi
    pop %edx
    pop %ecx
    pop %ebx
    pop %eax

    popf

    ret
