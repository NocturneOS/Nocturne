// NocturneOS - kernel initialization code for x86 platforms.

.code32

.include "./common.s"

.section .multiboot_header, "a", @progbits
.align 4
.int INIT_MBOOT_HEADER_MAGIC
.int INIT_MBOOT_HEADER_FLAGS
.int INIT_MBOOT_CHECKSUM
.long 0, 0, 0, 0, 0     # Unused
.long 0                 # 0 - graphical mode
.long 800, 600, 32      # Width, height, depth

.section .bootstrap_stack, "aw", @nobits
    .global stack_bottom
    .align 16
	stack_bottom:
		.skip STACK_SIZE
	stack_top:

# Our page directory and page table
.section .bootstrap_paging, "aw", @nobits
    .align 4096
    .global boot_page_directory
    boot_page_directory:
        .skip 4096

.extern IMAGE_PHYS_START
.extern IMAGE_PHYS_END

.section .text
.global __pre_init
__pre_init:
    cli

    # FIXME: Move this logic to x86_preinit.rs

    # Extended (1 << 7) | Writeable (1 << 1) | Present (1 << 0)
    movl $0x83, %eax

    # Map the same PT to both lower and higher half.
    # We will unmap the lower one soon.
    movl %eax, boot_page_directory - 0xC0000000
    movl %eax, boot_page_directory - 0xC0000000 + (768 * 4)

    addl $0x400000, %eax

    movl %eax, boot_page_directory - 0xC0000000 + 4
    movl %eax, boot_page_directory - 0xC0000000 + (769 * 4)

    # Recursive paging
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
    # Unmap lower part of memory
    xor %eax, %eax
    
    movl %eax, boot_page_directory + 4
    movl %eax, boot_page_directory

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

    push	%ebx

    xor %ebp, %ebp

    call	__arch_init

    cli
    hlt

conword:
    .word 0x37f
