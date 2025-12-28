// NocturneOS - kernel initialization code for x86 platforms.

.code32
.set ALIGN,    1 << 0      # Alignment of loaded modules by page boundaries
.set MEMINFO,  1 << 1      # Request to provide memory map
.set INIT_MBOOT_HEADER_MAGIC,           0x1BADB002
.set INIT_MBOOT_HEADER_FLAGS,           ALIGN | MEMINFO
.set INIT_MBOOT_CHECKSUM,               0x00000000 - (INIT_MBOOT_HEADER_MAGIC + INIT_MBOOT_HEADER_FLAGS)

.set STACK_SIZE, 1024 * 32  # 32 KB

.extern kmain

.section .multiboot_header, "a"
.align 4
.int INIT_MBOOT_HEADER_MAGIC
.int INIT_MBOOT_HEADER_FLAGS
.int INIT_MBOOT_CHECKSUM

.section .bootstrap_stack, "aw", @nobits
    .global stack_bottom
    .align 4096
	stack_bottom:
		.skip STACK_SIZE
	stack_top:

# Our page directory and page table
.section .bootstrap_paging, "aw", @nobits
    .align 4096
    .global boot_page_directory
    boot_page_directory:
        .skip 4096
    .global boot_page_table
    boot_page_table:
        .skip 4096

.extern IMAGE_PHYS_START
.extern IMAGE_PHYS_END

.section .text
.global __pre_init
__pre_init:
    cli

    movl $(boot_page_table - 0xC0000000), %eax
    orl $0b11, %eax

    # Map the same PT to both lower and higher half.
    # We will unmap the lower one soon.
    movl %eax, boot_page_directory - 0xC0000000
    movl %eax, boot_page_directory - 0xC0000000 + (768 * 4)

    movl $0b11, %eax

    movl $(boot_page_table - 0xC0000000), %edx
    movl $1024, %ecx

.loop:
    mov %eax, (%edx)

    add $4, %edx
    add $0x1000, %eax

    sub $1, %ecx

    jnz .loop

.next:
    movl $(boot_page_directory - 0xC0000000), %eax
    orl $0b11, %eax

    mov %eax, boot_page_directory - 0xC0000000 + 1023 * 4

    movl $(boot_page_directory - 0xC0000000), %eax
	movl %eax, %cr3

    # Enable PSE
    mov %cr4, %eax
    or $(1 << 4), %eax
    mov %eax, %cr4

	# Enable paging and the Write-protect bit.
	movl %cr0, %eax
	orl $0x80010000, %eax
	movl %eax, %cr0

    lea __init, %ecx
    jmp *%ecx

__init:
    mov $stack_top, %esp

    # init FPU
    fninit
    finit
    fldcw (conword)

    mov %cr4, %eax
    or $0x200, %eax
    mov %eax, %cr4

    # init SSE

    mov %cr0, %eax
    and $~0x04, %ax
    or $0x2, %ax
    mov %eax, %cr0

    mov %cr4, %eax
    or $(3 << 9), %ax
    mov %eax, %cr4

    push	%esp
    push	%ebx

    xor %ebp, %ebp

    call	kmain

    cli
    hlt

conword:
    .word 0x37f
