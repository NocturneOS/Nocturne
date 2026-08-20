ENTRY (__pre_init);

SECTIONS {
    . = 0x00100000;

    IMAGE_PHYS_START = .;
    IMAGE_VIRT_START = . + 0xC0000000;

    .multiboot_header ALIGN(8) : {
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

        *(.bootstrap_paging*)

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

    .debug_symbols ALIGN (4K) : AT(ADDR (.debug_symbols) - 0xC0000000) {
        *(.debug_symbols*)
    }

    .bss ALIGN (4K) : AT(ADDR (.bss) - 0xC0000000) {
        PROVIDE(BSS_start = .);
        PROVIDE(BSS_phys_start = . - 0xC0000000);

        *(.bootstrap_stack*)

        *(COMMON)

        *(.bss*)

        PROVIDE(BSS_end = .);
        PROVIDE(BSS_phys_end = . - 0xC0000000);
    }

    /DISCARD/ : {
        *(.note.gnu.property)
        *(.eh_frame)
        *(.note.gnu.build-id)
        *(.debug_gdb_scripts)
    }
    
    . = ALIGN(4K);
    
    IMAGE_PHYS_END = . - 0xC0000000;
    IMAGE_VIRT_END = .;
}
