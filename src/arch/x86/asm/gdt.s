.global gdt_flush
gdt_flush:
    # Load GDT
    mov    4(%esp), %eax
    lgdt   (%eax)
    
    # Reload segments
    mov	   $0x10, %ax
    mov	   %ax, %ds
    mov	   %ax, %es
    mov	   %ax, %fs
    mov	   %ax, %gs
    mov	   %ax, %ss
    ljmp   $0x08, $flush
flush:
    ret
