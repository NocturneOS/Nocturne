.code64

.global idt_flush
idt_flush:
    lidt    (%rdi)
    ret

.extern     isr_handler
.extern     irq_handler

.macro ISR_NOERRCODE isr_num
    .global	isr\isr_num
isr\isr_num:
    cli
    push	$0
    push	$\isr_num
    jmp	isr_common_stub_noerr
.endm

.macro ISR_ERRCODE isr_num
    .global	isr\isr_num
isr\isr_num:
    cli
    push	$\isr_num
    jmp	isr_common_stub_err
.endm

.macro IRQ irq_num, isr_num
    .global irq\irq_num
irq\irq_num:
    cli
    push	$0
    push	$\isr_num
    jmp	irq_common_stub
.endm

.macro PUSHA64
    push  %rax
    push  %rbx
    push  %rcx
    push  %rdx
    push  %rsi
    push  %rdi
    push  %rsp
    push  %rbp
    push  %r8
    push  %r9
    push  %r10
    push  %r11
    push  %r12
    push  %r13
    push  %r14
    push  %r15
.endm

.macro POPA64
    pop  %r15
    pop  %r14
    pop  %r13
    pop  %r12
    pop  %r11
    pop  %r10
    pop  %r9
    pop  %r8
    pop  %rbp
    add $8, %rsp
    pop  %rdi
    pop  %rsi
    pop  %rdx
    pop  %rcx
    pop  %rbx
    pop  %rax
.endm

/* Обработчики прерываний */
ISR_NOERRCODE 0
ISR_NOERRCODE 1
ISR_NOERRCODE 2
ISR_NOERRCODE 3
ISR_NOERRCODE 4
ISR_NOERRCODE 5
ISR_NOERRCODE 6
ISR_NOERRCODE 7
ISR_ERRCODE   8
ISR_NOERRCODE 9
ISR_ERRCODE   10
ISR_ERRCODE   11
ISR_ERRCODE   12
ISR_ERRCODE   13
ISR_ERRCODE   14
ISR_NOERRCODE 15
ISR_NOERRCODE 16
ISR_NOERRCODE 17
ISR_NOERRCODE 18
ISR_NOERRCODE 19
ISR_NOERRCODE 20
ISR_NOERRCODE 21
ISR_NOERRCODE 22
ISR_NOERRCODE 23
ISR_NOERRCODE 24
ISR_NOERRCODE 25
ISR_NOERRCODE 26
ISR_NOERRCODE 27
ISR_NOERRCODE 28
ISR_NOERRCODE 29
ISR_NOERRCODE 30
ISR_NOERRCODE 31

/* IRQs */
IRQ 0,  32
IRQ 1,  33
IRQ 2,  34
IRQ 3,  35
IRQ 4,  36
IRQ 5,  37
IRQ 6,  38
IRQ 7,  39
IRQ 8,  40
IRQ 9,  41
IRQ 10, 42
IRQ 11, 43
IRQ 12, 44
IRQ 13, 45
IRQ 14, 46
IRQ 15, 47

# OS service call
.global isr80
isr80:
    push  $0
    push  $0x80

    PUSHA64

    mov %ds, %rbp
    push %rbp

    mov %rsp, %rax
    add $192, %rax

    mov $0x10, %rbp
    mov %rbp, %ds

    # I don't know anything about SMAP, so I am so unsure about their placement here.

    # clac

    # RAX = first argument
    cld
    call  isr_handler

    # stac

    pop %rbp
    mov %rbp, %ds

    POPA64

    add   $(2 * 8), %rsp
    iretq

isr_common_stub_err:
    PUSHA64

    mov %ds, %rbp
    push %rbp

    mov %rsp, %rax
    add $192, %rax

    mov $0x10, %rbp
    mov %rbp, %ds

    # clac

    call isr_handler

    # stac

    pop %rbp
    mov %rbp, %ds

    POPA64

    add   $(2 * 8), %rsp
    iretq

isr_common_stub_noerr:
    PUSHA64

    mov %ds, %rbp
    push %rbp

    mov %rsp, %rax
    add $192, %rax

    mov $0x10, %rbp
    mov %rbp, %ds

    # clac

    cld
    call isr_handler

    # stac

    pop %rbp
    mov %rbp, %ds

    POPA64

    add   $(2 * 8), %rsp
    iretq

/* IRQ common stub */
irq_common_stub:
    PUSHA64

    # Push DS (will be first field in CPURegisters structure)
    mov %ds, %rdx
    push %rdx

    # Make RAX point to the to the beginning of stack frame (CPURegisters)
    mov %rsp, %rax
    add $144, %rax

    # Load kernel DS
    mov $0x10, %rdx
    mov %rdx, %ds

    # clac

    # SysV thing?
    cld
    call irq_handler

    # stac

    # Restore DS
    pop %rdx
    mov %rdx, %ds

    POPA64

    # Push out interrupt number and errcode (IRQ handlers push 0 as error code)
    add   $(2 * 8), %rsp
    iretq
