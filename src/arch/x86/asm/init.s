// NocturneOS - kernel initialization code for x86 platforms.

.code32

.include "./common.s"

.section .multiboot_header, "a", @progbits
.align 8
mb2_header:
    .int MBOOT2_HEADER_MAGIC
    .int MBOOT2_ARCH
    .int MBOOT2_HEADER_LENGTH
    .int MBOOT2_CHECKSUM

    # Information request tag
    .align 8
    .short 1  # Type: Information request
    .short 0  # Flags: None
    .int 24  # Size: 20 bytes
    .int 4   # Request memory information
    .int 6   # Request boot loader name
    .int 8   # Request BIOS boot device
    .int 9   # Request memory map

   # Address tag
    .align 8
    .short 2  # Type: Address
    .short 0  # Flags: None
    .int 24  # Size: 24 bytes
    .int mb2_header        # Header address
    .int IMAGE_PHYS_START  # Load address
    .int BSS_phys_start    # Load end address
    .int BSS_phys_end      # BSS end address

    # Entry address tag
    .align 8
    .short 3  # Type: Entry address
    .short 0  # Flags: None
    .int 12  # Size: 12 bytes
    .int __pre_init - 0xC0000000  # Entry point address

    # Framebuffer tag
    .align 8
    .short 5  # Type: Framebuffer
    .short 0  # Flags: None
    .int 20  # Size: 20 bytes
    .int 1280  # Width
    .int 720   # Height
    .int 32    # Depth

    # Module page-alignment tag
    .align 8
    .short 6
    .short 0
    .int 8

    # End tag
    .align 8
    .short 0  # Type: End
    .short 0  # Flags: None
    .int 8   # Size: 8 bytes
mb2_header_end:

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
    # EAX = Magic
    # EBX = Multiboot2 info structure

    cli

    # Compute the size of the kernel image starting from the memory beginning.
    # P(0x0000_0000..=kernel end) = V(0xC000_0000..=kernel end)

    movl $(IMAGE_PHYS_END), %eax

    # image end = max(mb2 header address, actually image end);
    # Because Multiboot2 info structure address can be placed after image end, and we need to map it too.

    cmp %eax, %ebx
    jbe .multiboot_header_is_within_kernel

    # Image end = Multiboot2 info structure address
    mov %ebx, %eax

    # Round up address to next extended page boundary (4 MB)
    add $0x3FFFFF, %eax
    and $0xFFC00000, %eax

    .multiboot_header_is_within_kernel:

    # kernel_size / 0x400000   (0x400000 is 4 MB - the size of one extended page)
    xor %edx, %edx
    mov $0x400000, %ecx
    div %ecx

    # Do `div_ceil` - if there's non-zero remainder (which is likely), increment page count.
    test %edx, %edx
    jz .no_remainder

    inc %eax

    .no_remainder: # ...

    # Store this count in the variable for now.
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
    lea boot_page_directory - 0xC0000000, %eax
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
            
    mov bootstrap_page_count, %ecx

    lea boot_page_directory, %edi

    .unmap_loop:
        movl $0, (%edi)

        add $4, %edi

        dec %ecx

        test %ecx, %ecx
        jnz .unmap_loop

    .continue:

    xor %al, %al
    lea stack_bottom, %edi
    mov $STACK_SIZE, %ecx
    cld
    rep stosb

    mov $stack_top, %esp

    # init FPU

    # fninit
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

    # GRUB's Multiboot2 info structure address is physical. Add kernel base to the that address to make it virtual.
    add $0xC0000000, %ebx

    push	%ebx

    xor %ebp, %ebp

    call	__arch_init

    cli
    hlt
