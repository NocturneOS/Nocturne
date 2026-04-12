.set ALIGN,    1 << 0      # Alignment of loaded modules by page boundaries
.set MEMINFO,  1 << 1      # Request to provide memory map
.set VBE_MODE, 1 << 2      # VBE mode flag. GRUB will set it for us and provide info about it.
.set INIT_MBOOT_HEADER_MAGIC,           0x1BADB002
.set INIT_MBOOT_HEADER_FLAGS,           ALIGN | MEMINFO | VBE_MODE
.set INIT_MBOOT_CHECKSUM,               0x00000000 - (INIT_MBOOT_HEADER_MAGIC + INIT_MBOOT_HEADER_FLAGS)

.set STACK_SIZE, 64 * 1024  # 64 KB
