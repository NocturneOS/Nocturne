// NocturneOS - kernel initialization code for x86 platforms.

.code32

.include "./common.s"

.section .multiboot_header, "a"
.align 4
.int INIT_MBOOT_HEADER_MAGIC
.int INIT_MBOOT_HEADER_FLAGS
.int INIT_MBOOT_CHECKSUM

.section .bootstrap_stack, "aw", @nobits
    .global stack_bottom
    .align 16
	stack_bottom:
		.skip STACK_SIZE
	stack_top:

.section .bootstrap_paging, "aw", @nobits
    .align 4096
    .global boot_pml4
    boot_pml4t:
        .skip 4096
    boot_pdpt:
        .skip 4096
    boot_pdt:
        .skip 4096

.section .rodata
.align 8
conword:
    .word 0x37f

.section .text
.global __pre_init
__pre_init:
    cli
    cld

    # init FPU
    #fninit
    #finit
    #fldcw (conword)

    #mov %cr4, %eax
    #or $0x200, %eax
    #mov %eax, %cr4

    // Load stack
    mov $(stack_top - 0xC0000000), %esp

    // Save multiboot header address on stack
    push $0
    push %ebx

    # Zero out the PML4T
    mov $1024, %ecx
    xor %eax, %eax
    mov $(boot_pml4t - 0xC0000000), %edi
    rep stosl
 
    # Zero out PDPT
    mov $1024, %ecx
    mov $(boot_pdpt - 0xC0000000), %edi
    rep stosl

    # Zero out PDT
    mov $1024, %ecx
    mov $(boot_pdt - 0xC0000000), %edi
    rep stosl

    // Setup paging hierarchy
    // PML4T
    mov $(boot_pml4t - 0xC0000000), %edi
    mov $(boot_pdpt - 0xC0000000), %esi
    or $(1 << 0 | 1 << 1), %esi  # Present + Writeable

    # Identity mapping V0x0 = P0x0, we will unmap it later
    mov %esi, (%edi)

    // Recursive paging
    mov $(boot_pml4t - 0xC0000000), %esi
    or $(1 << 0 | 1 << 1), %esi
    mov %esi, (4096 - 8)(%edi)
    
    // PDPTE
    mov $(boot_pdpt - 0xC0000000), %edi
    mov $(boot_pdt - 0xC0000000), %esi
    or $(1 << 0 | 1 << 1), %esi

    # V0x0 = P0x0
    mov %esi, (%edi)
    # V0xC000_0000 = P0x0
    mov %esi, (3 * 8)(%edi)

    // Recursive paging
    mov $(boot_pdpt - 0xC0000000), %esi
    or $(1 << 0 | 1 << 1), %esi
    mov %esi, (4096 - 8)(%edi)

    // Map first 4 MB by using large pages
    mov $(boot_pdt - 0xC0000000), %edi
    mov $0, %esi
    or $(1 << 0 | 1 << 1 | 1 << 7), %esi
    mov %esi, (%edi)

    # Map 2 more megabytes
    add $0x200000, %esi
    mov %esi, 8(%edi)

    // Now, load PML4T to CR3
    mov $(boot_pml4t - 0xC0000000), %eax
    mov %eax, %cr3

    // Enable PAE
    mov %cr4, %eax
    or $(1 << 5 | 1 << 4), %eax
    mov %eax, %cr4

    // 0xC000_0080 is a IA32_EFER (Extended Feature Enable Register)
    // Bit 8 is Long Mode
    mov $0xC0000080, %ecx
    rdmsr
    or $(1 << 8), %eax
    wrmsr

    // Protection Enable (1 << 0) and Paging (1 << 31)
    mov %cr0, %eax
    or $(1 << 0 | 1 << 31), %eax
    mov %eax, %cr0

    lgdt gdtr
    ljmp $0x08, $go64

.code64
go64:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    add $0xC0000000, %esp

    xor %rax, %rax

    # PDP[0] is an entry that identity maps 0x0, but we are in "higher-half" addressing, so we can unmap 0x0 without any pain.
    mov %rax, boot_pdpt - 0xC0000000


    # init SSE

    mov %cr0, %rax
    and $~0x04, %ax
    or $0x2, %ax
    mov %rax, %cr0

    mov %cr4, %rax
    or $(3 << 9), %ax
    mov %rax, %cr4

    pop %rdi

    xor %rbp, %rbp

    callq __arch_init

    cli
    hlt

    .lp: jmp .lp


# Simplest GDT here just to initialize the kernel, we will complete initialization in Rust code.

.section .data
.align 8
gdtr:
    .word gdt_end - gdt_base
    .quad gdt_base

.align 8
gdt_base:
    // 0x00 - Null segment descriptor
    .quad 0
    
    // 0x08 - Kernel code segment descriptor
    .word 0xffff
    .word 0
    .byte 0
    .byte 0x9a
    .byte 0xaf
    .byte 0

    // 0x10 - Kernel data segment descriptor
    .word 0xffff
    .word 0
    .byte 0
    .byte 0x92
    .byte 0xcf
    .byte 0
gdt_end:
