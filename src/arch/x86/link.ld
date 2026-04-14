ENTRY (__pre_init);

SECTIONS {
    . = 0x00100000;

    IMAGE_PHYS_START = .;
    IMAGE_VIRT_START = . + 0xC0000000;

    .multiboot_header : {
        *(.multiboot_header*)
    }

    . += 0xC0000000;

    .text ALIGN (4K) : AT(ADDR (.text) - 0xC0000000) {
        PROVIDE(CODE_start = .);

        *(.text*)

        PROVIDE(CODE_end = .);
    }

    .data ALIGN (4K) : AT(ADDR (.data) - 0xC0000000) {
        PROVIDE(DATA_start = .);

        *(.data*)

        PROVIDE(DATA_end = .);
    }

    .rodata ALIGN (4K) : AT(ADDR (.rodata) - 0xC0000000) {
        PROVIDE(RODATA_start = .);
        
        *(.ctors)
        *(.init_array)

        *(.rodata*)

        PROVIDE(RODATA_end = .);
    }

    .bootstrap_stack : {
        *(.bootstrap_stack*)
    }

    .bootstrap_paging : {
        *(.bootstrap_paging*)
    }

    .bss ALIGN (4K) : AT(ADDR (.bss) - 0xC0000000) {
        *(COMMON)

        PROVIDE(BSS_start = .);

        *(.bss*)

        PROVIDE(BSS_end = .);
    }

    .debug_symbols ALIGN(4K) : {
        *(.debug_symbols*)
    }

    /DISCARD/ : {
        *(.note.gnu.property)
        *(.debug_gdb_scripts)
    }
    
    . = ALIGN(4K);
    
    IMAGE_PHYS_END = . - 0xC0000000;
    IMAGE_VIRT_END = .;
}
