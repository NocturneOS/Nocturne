.extern     isr_handler
.extern     irq_handler

/* Макрос для обработчика без возврата кода ошибки */
.macro ISR_NOERRCODE isr_num
    .global	isr\isr_num
    .align 4
isr\isr_num:
    cli

    push	$0
    push	$\isr_num
    jmp	isr_common_stub_noerr
.endm

/* Макрос для обработчика прерывания с возвратом кода ошибки */
.macro ISR_ERRCODE isr_num
    .global	isr\isr_num
    .align 4
isr\isr_num:
    cli
    
    push	$\isr_num
    jmp	isr_common_stub_err
.endm

/* Макрос для враппера обработчика прерывания */
.macro IRQ irq_num, isr_num
    .global irq\irq_num
    .align 4
irq\irq_num:
    cli

    push	$0
    push	$\isr_num
    jmp	irq_common_stub
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

.global isr80
isr80:
    # No `cli` here. This will allow programs to run without `yield()`
    
    push  $0
    push  $0x80

    pusha

    mov %ds, %ax
    push %eax
    
    mov   $0x10, %ax
    mov   %ax, %ds
    mov   %ax, %es
    mov   %ax, %fs
    mov   %ax, %gs

    cld
    # Why isr_handler? Because irq_handler sends EOI to (A)PIC, but isr_handler not.
    # We are in syscall that user causes with `int` instruction which doesn't need any PIC.
    call  isr_handler
    
    pop   %ebx
    mov %bx, %ds
    mov %bx, %es
    mov %bx, %fs
    mov %bx, %gs

    popa
    
    add   $8, %esp
    
    iret

isr_common_stub_err:
    pusha
    
    push  %ds
    
    mov   $0x10, %ax
    mov   %ax, %ds
    mov   %ax, %es
    mov   %ax, %fs
    mov   %ax, %gs
    
    cld
    call  isr_handler
    
    pop   %eax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    
    popa
    
    add   $8, %esp
    
    sti

    iret

isr_common_stub_noerr:
    pusha
    
    push  %ds
    
    mov   $0x10, %ax
    mov   %ax, %ds
    mov   %ax, %es
    mov   %ax, %fs
    mov   %ax, %gs
    
    cld
    call  isr_handler
    
    pop   %eax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    
    popa
    
    add   $8, %esp
    
    sti

    iret

irq_common_stub:
    pusha

    mov %ds, %ax
    push  %eax

    mov   $0x10, %ax
    mov   %ax, %ds
    mov   %ax, %es
    mov   %ax, %fs
    mov   %ax, %gs
    
    cld
    call  irq_handler

    pop   %ebx
    mov %bx, %ds
    mov %bx, %es
    mov %bx, %fs
    mov %bx, %gs

    popa
    
    add   $8, %esp
    
    sti

    iret
