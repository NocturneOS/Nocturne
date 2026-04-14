ENTRY (__pre_init)

SECTIONS {
    . = 0x00100000;

    IMAGE_PHYS_START = .;

    /* Bootstrap sections that need physical addressing */
    .multiboot_header : {
        *(.multiboot_header*)
    }

    .bootstrap_stack : {
        *(.bootstrap_stack*)
    }

    .bootstrap_paging : {
        *(.bootstrap_paging*)
    }

    /* Store physical end of bootstrap sections */
    BOOTSTRAP_PHYS_END = .;

    /* Now move to higher half for the rest */
    . += 0xFFFFFFFF80000000;
    
    IMAGE_VIRT_START = .;

    .text ALIGN (4K) : AT(ADDR (.text) - 0xFFFFFFFF80000000) {
        PROVIDE(CODE_start = .);

        *(.ltext*)
        *(.text*)

        PROVIDE(CODE_end = .);
    }

    .rodata ALIGN (4K) : AT(ADDR (.rodata) - 0xFFFFFFFF80000000) {
        PROVIDE(RODATA_start = .);
        
        *(.ctors)
        *(.init_array)

        *(.lrodata*)
        *(.rodata*)

        PROVIDE(RODATA_end = .);
    }

    .data ALIGN (4K) : AT(ADDR (.data) - 0xFFFFFFFF80000000) {
        PROVIDE(DATA_start = .);

        *(.ldata*)
        *(.data*)

        PROVIDE(DATA_end = .);
    }

    .bss ALIGN (4K) : AT(ADDR (.bss) - 0xFFFFFFFF80000000) {
        *(COMMON)

        PROVIDE(BSS_start = .);

        *(.lbss*)
        *(.bss*)

        PROVIDE(BSS_end = .);
    }

    .debug_symbols ALIGN(4K) : AT(ADDR (.debug_symbols) - 0xFFFFFFFF80000000) {
        *(.debug_symbols*)
    }

    /DISCARD/ : {
        *(.note.gnu.property)
        *(.debug_gdb_scripts)
        *(.eh_frame)
    }

    . = ALIGN(4K);
    
    IMAGE_PHYS_END = . - 0xFFFFFFFF80000000;
    IMAGE_VIRT_END = .;
}