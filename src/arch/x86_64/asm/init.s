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
.type __pre_init, %function
.global __pre_init
__pre_init:
    cli
    cld

    # init FPU
    fninit
    finit
    # Use RIP-relative addressing for conword access
    fldcw conword - 0xFFFFFFFF80000000

    mov %cr4, %eax
    or $0x200, %eax
    mov %eax, %cr4

    // Load stack - use physical address
    lea (stack_top), %esp

    // Save multiboot header address on stack
    push $0
    push %ebx

    # Zero out the PML4T
    mov $1024, %ecx
    xor %eax, %eax
    lea (boot_pml4t), %edi
    rep stosl
 
    # Zero out PDPT
    mov $1024, %ecx
    lea (boot_pdpt), %edi
    rep stosl

    # Zero out PDT
    mov $1024, %ecx
    lea (boot_pdt), %edi
    rep stosl

    // Setup paging hierarchy
    // PML4T
    lea (boot_pml4t), %edi
    lea (boot_pdpt), %esi
    or $(1 << 0 | 1 << 1), %esi  # Present + Writeable

    # Identity mapping V0x0 = P0x0, we will unmap it later
    mov %esi, (%edi)

    // Higher half mapping - entry 511 (0xFFFF_FFFF_8000_0000)
    lea (boot_pdpt), %esi
    or $(1 << 0 | 1 << 1), %esi
    mov %esi, (511 * 8)(%edi)

    // Recursive paging at entry 510
    lea (boot_pml4t), %esi
    or $(1 << 0 | 1 << 1), %esi
    mov %esi, (510 * 8)(%edi)
    
    // PDPTE
    lea (boot_pdpt), %edi
    lea (boot_pdt), %esi
    or $(1 << 0 | 1 << 1), %esi

    # V0x0 = P0x0 (identity mapping)
    mov %esi, (%edi)
    
    # Higher half mapping - entry 510 for 0xFFFFFFFF80000000
    mov %esi, (510 * 8)(%edi)

    # Recursive paging
    lea (boot_pdpt), %esi
    or $(1 << 0 | 1 << 1), %esi
    mov %esi, (511 * 8)(%edi)

    # Map first 8 MB by using large pages (2MB pages)
    lea (boot_pdt), %edi
    mov $0, %esi
    or $(1 << 0 | 1 << 1 | 1 << 7), %esi  # Present + Writable + Page Size
    mov %esi, (%edi)

    add $0x200000, %esi
    mov %esi, 8(%edi)

    add $0x200000, %esi
    mov %esi, 16(%edi)

    add $0x200000, %esi
    mov %esi, 24(%edi)

    # Now, load PML4T to CR3
    lea (boot_pml4t), %eax
    mov %eax, %cr3

    # Enable PAE
    mov %cr4, %eax
    or $(1 << 5 | 1 << 4), %eax  # PAE + PSE
    mov %eax, %cr4

    # 0xC000_0080 is IA32_EFER (Extended Feature Enable Register)
    # Bit 8 is Long Mode Enable
    mov $0xC0000080, %ecx
    rdmsr
    or $(1 << 8), %eax  # LME
    wrmsr

    # Protection Enable (1 << 0) and Paging (1 << 31)
    mov %cr0, %eax
    or $(1 << 0 | 1 << 31), %eax
    mov %eax, %cr0

    # Load GDT (physical address)
    lgdt (gdtr - 0xFFFFFFFF80000000)
    
    # Jump to 64-bit code (physical address of go64)
    lea (go64_p1 - 0xFFFFFFFF80000000), %eax

    push $0x08
    push %eax
    
    retf

    #ljmp $0x08, $go64

.code64
.section .text
go64_p1:
    lea (go64_p2), %rax

    push $0x08
    push %rax

    retfq

go64_p2:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    add $0xFFFFFFFF80000000, %rsp

    xor %rax, %rax

    # PDP[0] is an entry that identity maps 0x0, but we are in "higher-half" addressing, so we can unmap 0x0 without any pain.
    lea (boot_pdpt + 0xffffffff80000000), %rax
    movq $0, (%rax)

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
    .quad gdt_base - 0xFFFFFFFF80000000

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
