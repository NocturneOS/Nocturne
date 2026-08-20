.extern IMAGE_PHYS_START
.extern IMAGE_VIRT_START

.extern IMAGE_PHYS_END
.extern IMAGE_VIRT_END

.extern .BSS_start
.extern .BSS_end

.extern .BSS_phys_start
.extern .BSS_phys_end

# https://github.com/CIS-osdev/kernel/blob/ff134e1768febeb626ede12f2823afe3477ed1f8/kernel/arch/amd64/boot.s#L8

.set MBOOT2_HEADER_MAGIC,      0xE85250D6
.set MBOOT2_ARCH,              0    # I386
.set MBOOT2_HEADER_LENGTH,     (mb2_header_end - mb2_header)
.set MBOOT2_CHECKSUM,          -(MBOOT2_HEADER_MAGIC + MBOOT2_ARCH + MBOOT2_HEADER_LENGTH)

.set STACK_SIZE, 128 * 1024  # 128 KB
