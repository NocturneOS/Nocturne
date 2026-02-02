.set ALIGN,    1 << 0      # Alignment of loaded modules by page boundaries
.set MEMINFO,  1 << 1      # Request to provide memory map
.set INIT_MBOOT_HEADER_MAGIC,           0x1BADB002
.set INIT_MBOOT_HEADER_FLAGS,           ALIGN | MEMINFO
.set INIT_MBOOT_CHECKSUM,               0x00000000 - (INIT_MBOOT_HEADER_MAGIC + INIT_MBOOT_HEADER_FLAGS)

.set STACK_SIZE, 1024 * 64  # 64 KB