ENTRY (__pre_init)

SECTIONS {
    . = 0x00100000;

    IMAGE_PHYS_START = .;

    /* Bootstrap sections that need physical addressing */
    .multiboot_header : {
        *(.multiboot_header*)
    }

    .bootstrap_paging ALIGN(4K) : {
        *(.bootstrap_paging*)
    }

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

    .debug_symbols ALIGN(4K) : AT(ADDR (.debug_symbols) - 0xFFFFFFFF80000000) {
        *(.debug_symbols*)
    }

    /* TEMPLATE for PerCPU */
    .percpu ALIGN(4K) : AT(ADDR(.percpu)) {
        _percpu_start = .;
        
        *(.percpu .percpu.*)
 
        _percpu_end = .;
    }

    .bss ALIGN (4K) : AT(ADDR (.bss) - 0xFFFFFFFF80000000) {
        PROVIDE(BSS_start = .);
        PROVIDE(BSS_phys_start = . - 0xFFFFFFFF80000000);

        *(COMMON)
        
        *(.lbss*)
        *(.bss*)

        *(.bootstrap_stack*)

        PROVIDE(BSS_end = .);
        PROVIDE(BSS_phys_end = . - 0xFFFFFFFF80000000);
    }

    /DISCARD/ : {
        *(.eh_frame)
        *(.note.gnu.property)
        *(.debug_gdb_scripts)
        *(.note.gnu.build-id)
    }

    . = ALIGN(4K);
    
    IMAGE_PHYS_END = . - 0xFFFFFFFF80000000;
    IMAGE_VIRT_END = .;
}