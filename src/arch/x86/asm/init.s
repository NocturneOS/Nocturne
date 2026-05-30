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

.section .data
.align 4
fpu_control_word:
    .word 0x37f

.align 4
bootstrap_page_count:
    .int 0

.section .text
.global __pre_init
__pre_init:
    cli

    # Compute the size of the kernel image.

    movl $(IMAGE_PHYS_START), %ecx
    movl $(IMAGE_PHYS_END), %eax

    sub %eax, %ecx

    # kernel_size / 0x400000   (0x400000 is 4 MB - the size of one extended page)
    xor %edx, %edx
    mov $0x400000, %ecx
    div %ecx

    # Do `div_ceil` - if there's non-zero remainder (which is likely), increment page count.
    test %edx, %edx
    jz .no_remainder

    inc %eax

    .no_remainder: # ...

    mov %eax, bootstrap_page_count - 0xC0000000

    # Now EAX contains number of extended (4 MB) pages that kernel needs at least run all of its code.
    # Let's map them

    # do { ...
    .map_iteration:
        # Map the same EP to both lower and higher half.
        # Lower halves will be unmapped soon.

        movl $(boot_page_directory - 0xC0000000), %edi

        push %eax

        # Pages are zero-indexed, so decrement EAX to make it a PT index
        dec %eax

        # Each PTE is 4 bytes.
        # EAX = EAX * 4
        mov $4, %ecx
        mul %ecx

        # EDI += EAX
        add %eax, %edi

        # Get back counter.
        pop %eax
        push %eax
        
        # Now make an address -> EAX = (i * 0x400000) | 0x83
        dec %eax
        mov $0x400000, %ecx
        mul %ecx

        # Extended (1 << 7) | Writeable (1 << 1) | Present (1 << 0)
        or $0x83, %eax
        
        # Lower-half - map as is.
        mov %eax, (%edi)

        # Add 768 more entries to get to the higher-half.
        add $(768 * 4), %edi

        # Higher-half.
        mov %eax, (%edi)

        pop %eax

        # i--
        dec %eax

        # ... } while(EAX != 0);
        test %eax, %eax
        jnz .map_iteration

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
    fldcw (fpu_control_word)

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
