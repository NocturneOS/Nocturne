.code64
.section .text
.global gdt_flush
gdt_flush:
    # Load GDT
    lgdt   (%rdi)

    lea (.flush), %rax

    push $0x08
    push %rax

    retfq

.flush:
    # Reload segments
    mov	   $0x10, %ax
    mov	   %ax, %ds
    mov	   %ax, %es
    mov	   %ax, %fs
    mov	   %ax, %gs
    mov	   %ax, %ss

    ret
