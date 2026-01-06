cmake_minimum_required(VERSION 3.21)

project(NocturneOS VERSION 0.4.3)
enable_language(C ASM)

# Options

set(CMAKE_CONFIGURATION_TYPES "Debug;Dev;Release;ReleaseOptimized;OptSym" CACHE STRING "Available configurations" FORCE)

set(VALID_ARCHITECTURES "x86" "armv7" "x86_64")
set(SUPPORTED_ARMV7_BOARDS "opi-lite")

if(NOT NOCTURNE_ARCH)
  set(NOCTURNE_ARCH "x86")
endif()

list(FIND VALID_ARCHITECTURES "${NOCTURNE_ARCH}" __INDEX)
if(__INDEX EQUAL -1)
  message(FATAL_ERROR "Invalid architecture: ${NOCTURNE_ARCH}. Accepted values are: ${VALID_ARCHITECTURES}")
endif()

if(NOCTURNE_ARCH STREQUAL "armv7" AND NOT NOCTURNE_BOARD)
	message(WARNING "Board not selected. Select an ARM board you want compile for: ${SUPPORTED_ARMV7_BOARDS}")
	message(FATAL_ERROR "Read the warning above. When you're ready, add this to your CMake command: `-DNOCTURNE_BOARD=<myboard>`")
endif()

if(NOCTURNE_ARCH STREQUAL "armv7")
	list(FIND SUPPORTED_ARMV7_BOARDS "${NOCTURNE_BOARD}" __INDEX)
	if(__INDEX EQUAL -1)
		message(WARNING "Invalid board selected. Select an ARM board you want compile for: ${SUPPORTED_ARMV7_BOARDS}")
		message(FATAL_ERROR "Read the warning above. When you're ready, add this to your CMake command: `-DNOCTURNE_BOARD=<myboard>`")
	endif()
endif()

option(NOCTURNE_USE_CLANG "Use Clang compiler for building" OFF)
option(NOCTURNE_USE_SSE2 "Use SSE2 instructuions" ON)

if(NOCTURNE_USE_SSE2)
	message("SSE2 enabled for this build")
endif()

set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "LANG=en_US.UTF-8 ${COMMAND}")

if(NOCTURNE_ARCH STREQUAL "x86")
	set(CLANG_ARCHITECTURE_TRIPLE "i386-pc-none")
	set(RUST_TARGET_TRIPLE "i686-unknown-none")
elseif(NOCTURNE_ARCH STREQUAL "armv7")

	set(CLANG_ARCHITECTURE_TRIPLE "armv7-unknown-none")
	set(RUST_TARGET_TRIPLE "armv7-unknown-none")
elseif(NOCTURNE_ARCH STREQUAL "x86_64")
	set(CLANG_ARCHITECTURE_TRIPLE "x86_64-pc-none")
	set(RUST_TARGET_TRIPLE "x86_64-unknown-none")
endif()

set(ISO_DIR "${CMAKE_SOURCE_DIR}/iso/")
set(KERNEL kernel.elf)

set(C_INCLUDES "-I${CMAKE_SOURCE_DIR}/kernel/include/ -I${CMAKE_SOURCE_DIR}/kernel/src/lib/libvector/include")

if(NOCTURNE_ARCH STREQUAL "x86")
	set(CMAKE_ASM_FLAGS "-m32 -g")
elseif(NOCTURNE_ARCH STREQUAL "x86_64")
	set(CMAKE_ASM_FLAGS "-m64 -g")
endif()

set(CMAKE_C_FLAGS "-pipe -fno-pic -ffreestanding -static -nostdlib -fno-stack-protector -Wall -Wextra -fdiagnostics-color ${C_INCLUDES} -std=c11 -Werror=return-type -Wno-address-of-packed-member -Wno-cast-function-type -DNOCTURNE_ARCH_STRING='\"${NOCTURNE_ARCH}\"'")

if(NOCTURNE_USE_CLANG)
    message("Using Clang compiler!")
    set(CMAKE_C_COMPILER "clang")
    set(CMAKE_C_FLAGS "-target ${CLANG_ARCHITECTURE_TRIPLE} ${CMAKE_C_FLAGS}")
    set(CMAKE_ASM_COMPILER "clang")
    set(CMAKE_ASM_FLAGS "-target ${CLANG_ARCHITECTURE_TRIPLE} ${CMAKE_ASM_FLAGS}")
else()
    message("Using GCC compiler!")
    set(CMAKE_C_COMPILER "gcc")
	
	if(NOCTURNE_ARCH STREQUAL "armv7")
		set(CMAKE_C_COMPILER "arm-none-eabi-gcc")
        set(CMAKE_ASM_COMPILER "arm-none-eabi-as")
	endif()
	
    set(CMAKE_C_FLAGS "-fuse-ld=lld ${CMAKE_C_FLAGS} -Wl,--build-id=none")
endif()

if(NOCTURNE_ARCH STREQUAL "x86")
    set(CMAKE_EXE_LINKER_FLAGS "-T ${CMAKE_SOURCE_DIR}/kernel/src/arch/x86/link.ld -static -z noexecstack -Wl,--gc-sections")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mno-red-zone -m32 -march=i386 -DNOCTURNE_X86")
	
	if(NOCTURNE_USE_SSE2)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse2")
	else()
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mno-sse2")
	endif()
elseif(NOCTURNE_ARCH STREQUAL "armv7")
	set(CMAKE_EXE_LINKER_FLAGS "-T ${CMAKE_SOURCE_DIR}/kernel/src/arch/armv7/link.ld -static -z noexecstack")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNOCTURNE_ARMV7")
elseif(NOCTURNE_ARCH STREQUAL "x86_64")
    set(CMAKE_EXE_LINKER_FLAGS "-T ${CMAKE_SOURCE_DIR}/kernel/src/arch/x86_64/link.ld -static -z noexecstack")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mno-red-zone -m64 -DNOCTURNE_X86_64")

	if(NOCTURNE_USE_SSE2)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse2")
		else()
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mno-sse2")
	endif()
endif()

if(NOT CMAKE_BUILD_TYPE)
    message(WARNING
            "No build configuration selected! Please specify one of the following:\n"
            "  -DCMAKE_BUILD_TYPE=Debug\n"
            "  -DCMAKE_BUILD_TYPE=Release\n"
            "  -DCMAKE_BUILD_TYPE=ReleaseOptimized\n"
            "Defaulting to: Debug"
    )
    set(CMAKE_BUILD_TYPE "Debug")
endif()

set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -O0" CACHE STRING "Flags for Debug" FORCE)
set(CMAKE_C_FLAGS_DEV "-O0" CACHE STRING "Flags for Dev" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-DRELEASE -O0" CACHE STRING "Flags for Release" FORCE)
set(CMAKE_C_FLAGS_RELEASEOPTIMIZED "-DRELEASE -O2" CACHE STRING "Flags for ReleaseOptimized" FORCE)
set(CMAKE_C_FLAGS_OPTSYM "-DRELEASE -O2 -ggdb3" CACHE STRING "Flags for OptSym" FORCE)

set(ISO_FILE "NocturneOS_${NOCTURNE_ARCH}_${CMAKE_BUILD_TYPE}.iso")

set(QEMU_MEMORY_SIZE 256M)

if(NOCTURNE_ARCH STREQUAL "x86_64")
	set(QEMU "qemu-system-x86_64")
elseif(NOCTURNE_ARCH STREQUAL "x86")
    set(QEMU "qemu-system-i386")
	#set(QEMU_FLAGS ${QEMU_FLAGS} -cpu pentium)
elseif(NOCTURNE_ARCH STREQUAL "armv7")
	set(QEMU "qemu-system-arm")

    if(NOCTURNE_BOARD STREQUAL "opi-lite")
        set(NOCTURNE_ARM_MACHINE "orangepi-pc")
    else()
        message(FATAL_ERROR "Could not determine QEMU machine name for target ${NOCTURNE_BOARD}. Check and update CMakeLists.txt for this board.")
    endif()

    set(QEMU_FLAGS -M ${NOCTURNE_ARM_MACHINE} )
endif()

set(QEMU_FLAGS ${QEMU_ADDITIONAL_FLAGS} -m ${QEMU_MEMORY_SIZE} -cdrom ${CMAKE_CURRENT_BINARY_DIR}/${ISO_FILE} -d int,cpu_reset,guest_errors,invalid_mem -serial mon:stdio -rtc base=localtime -boot d -usb -audiodev pa,id=audiopa -device ac97,audiodev=audiopa -netdev user,id=net0,net=192.168.111.0,dhcpstart=192.168.111.128,hostfwd=tcp::9999-:9999 -device rtl8139,netdev=net0,id=mydev0 -object filter-dump,id=dump0,netdev=net0,file=netdump.pcap -trace "*ac97*")

set(MKRESCUE grub-mkrescue)
set(MKRESCUE_FLAGS -o "${CMAKE_CURRENT_BINARY_DIR}/${ISO_FILE}" ${ISO_DIR} --locales="" -V NocturneOS --themes="" --fonts="ascii")

# Sources

set(COMMON_C_SRC
	kernel/src/io/logging.c 
	kernel/src/lib/string.c 
	kernel/src/sys/logo.c 
	kernel/src/lib/math/math.c 
	kernel/src/mem/pmm.c
	kernel/src/mem/vmm.c	
	kernel/src/lib/stdio.c
	kernel/src/io/screen.c 
	kernel/src/io/tty.c 
	kernel/src/fs/fsm.c 
	kernel/src/lib/time_conversion.c 
	kernel/src/fs/nvfs.c 
  #kernel/src/fs/tempfs.c 
	kernel/src/sys/scheduler/scheduler.c
	kernel/src/sys/scheduler/thread.c
	kernel/src/lib/php/pathinfo.c 
	kernel/src/drv/psf.c 
	kernel/src/sys/unwind.c 
	kernel/src/drv/disk/initrd.c 
	kernel/src/lib/list.c 
	kernel/src/lib/fileio.c 
	kernel/src/sys/sync.c 
	kernel/src/gui/basics.c 
	kernel/src/lib/pixel.c 
	kernel/src/sys/bootscreen.c 
	kernel/src/debug/hexview.c 
	# kernel/src/drv/video/vbe.c 
	kernel/src/sys/syscalls.c 
	kernel/src/lib/rand.c 
	kernel/src/drv/beeper.c 
	kernel/src/user/env.c
	kernel/src/gui/line.c 
	kernel/src/gui/circle.c 
	kernel/src/lib/math/exp.c 
	kernel/src/lib/math/log.c 
	kernel/src/lib/math/pow.c 
	kernel/src/lib/math/acos.c 
	kernel/src/lib/math/asin.c 
	kernel/src/lib/math/atan.c 
	kernel/src/lib/math/modf.c 
	kernel/src/lib/math/sin.c 
	kernel/src/lib/math/cos.c 
	kernel/src/lib/math/tan.c 
	kernel/src/lib/math/sqrt.c 
	kernel/src/lib/math/cbrt.c 	
	kernel/src/drv/disk/memdisk.c 
	kernel/src/net/endianess.c 
	kernel/src/net/cards.c 
	kernel/src/net/ethernet.c 
	kernel/src/net/arp.c 
	kernel/src/net/ipv4.c 
	kernel/src/net/udp.c 
	kernel/src/net/dhcp.c 
	kernel/src/net/icmp.c 
	kernel/src/io/status_sounds.c 
	kernel/src/io/status_loggers.c 
	# kernel/src/drv/network/virtio_network.c 
	kernel/src/lib/asprintf.c
	kernel/src/lib/sprintf.c
  # kernel/src/drv/disk/floppy.c
	kernel/src/sys/elf.c
	kernel/src/toys/mala.c 
	kernel/src/drv/disk/ahci.c 
	kernel/src/drv/disk/ata_pio.c 
	kernel/src/lib/utf_conversion.c 
	kernel/src/sys/file_descriptors.c 
	kernel/src/net/tcp.c 
	kernel/src/net/stack.c 
	kernel/src/sys/grub_modules.c 
    kernel/src/lib/vector.c
    # kernel/src/lib/intrin.c
	kernel/src/io/keyboard.c
	kernel/src/drv/disk/media_notifier.c
	kernel/src/kernel.c 
)

if(NOCTURNE_ARCH STREQUAL "x86")
	set(ASM_SRC
		kernel/src/arch/x86/asm/init.s
		kernel/src/arch/x86/asm/interrupt.s
		kernel/src/arch/x86/asm/sse.s
		kernel/src/arch/x86/asm/gdt.s
		kernel/src/arch/x86/asm/paging.s
		kernel/src/arch/x86/asm/regs.s 
		kernel/src/lib/setjmp.s 
		kernel/src/arch/x86/asm/switch_task.s
	)

	set(C_SRC
		kernel/src/arch/x86/init.c
		kernel/src/arch/x86/gdt.c
		kernel/src/arch/x86/tss.c
		kernel/src/arch/x86/idt.c
        kernel/src/arch/x86/cpu_isr.c 
        kernel/src/arch/x86/isr.c 
		kernel/src/arch/x86/mtrr.c 	
		kernel/src/arch/x86/cpuinfo.c
		kernel/src/arch/x86/cpuvendor.c
		kernel/src/arch/x86/cputemp.c	
		kernel/src/arch/x86/fxsave_region.c 
		kernel/src/arch/x86/pit.c
		kernel/src/arch/x86/pic.c
		kernel/src/arch/x86/power.c
		kernel/src/arch/x86/serial_port.c
        kernel/src/arch/x86/mem/paging_common.c

		kernel/src/arch/x86/mem/paging.c
		
		kernel/src/sys/acpi.c
		kernel/src/sys/apic/apic.c
		kernel/src/sys/apic/ioapic.c
		kernel/src/sys/apic/lapic_timer.c
		
		kernel/src/drv/cmos.c
		kernel/src/drv/input/ps2_mouse.c
		kernel/src/drv/video/intel.c

		kernel/src/drv/network/rtl8139.c 
		kernel/src/drv/disk/ata_dma.c
		kernel/src/drv/audio/ac97.c
		kernel/src/drv/audio/hda.c	
		kernel/src/drv/disk/ata.c 
		kernel/src/drv/disk/atapi.c 
	)

    set(C_SRC ${C_SRC} ${COMMON_C_SRC})
elseif(NOCTURNE_ARCH STREQUAL "armv7")
	set(ASM_SRC
		kernel/src/arch/armv7/boards/${NOCTURNE_BOARD}/init.s
	)

	set(C_SRC
		kernel/src/arch/armv7/init.c
		kernel/src/arch/armv7/boards/${NOCTURNE_BOARD}/init.c
	)
elseif(NOCTURNE_ARCH STREQUAL "x86_64")
	set(ASM_SRC
		kernel/src/arch/x86_64/asm/init.s
		kernel/src/arch/x86_64/asm/interrupt.s
		kernel/src/arch/x86_64/asm/regs64.s
		kernel/src/arch/x86_64/asm/sse.s
		kernel/src/arch/x86_64/mem/paging.s
	)

	set(C_SRC 
		kernel/src/arch/x86_64/init.c
		kernel/src/arch/x86_64/idt64.c
        kernel/src/arch/x86_64/cpu_isr.c 
        kernel/src/arch/x86_64/mem/paging.c
        kernel/src/arch/x86/mem/paging_common.c
		kernel/src/arch/x86/serial_port.c
		kernel/src/arch/x86/pic.c
		kernel/src/arch/x86/pit.c
		kernel/src/arch/x86/isr.c
		kernel/src/lib/math/math.c
		kernel/src/io/logging.c
		kernel/src/mem/pmm.c
		kernel/src/sys/acpi.c
		kernel/src/sys/apic/apic.c
		kernel/src/sys/apic/ioapic.c
		kernel/src/drv/cmos.c
		kernel/src/sys/grub_modules.c
		kernel/src/mem/vmm.c
		kernel/src/lib/string.c
		kernel/src/lib/sprintf.c
		kernel/src/lib/asprintf.c
		# kernel/src/lib/stdio.c
		# kernel/src/io/screen.c
		# kernel/src/sys/unwind.c
		# kernel/src/sys/sync.c
		# kernel/src/drv/disk/memdisk.c
		# kernel/src/drv/disk/initrd.c
		# kernel/src/fs/fsm.c
		# kernel/src/fs/nvfs.c
		# kernel/src/lib/libvector/src/vector.c
	)

    # set(C_SRC ${C_SRC} ${COMMON_C_SRC})
endif()

# set(C_SRC ${C_SRC} ${COMMON_C_SRC})


set(SRC ${ASM_SRC} ${C_SRC})

add_executable(${KERNEL} ${SRC})


# Rust

include(cmake/Rust.cmake)

if(NOT (NOCTURNE_ARCH STREQUAL "x86_64"))
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		add_rust_integration("debug")
	elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
		add_rust_integration("release_no_opt")
	else()
		add_rust_integration("release")
	endif()
endif()

# Targets

add_custom_command(
	TARGET ${KERNEL}
	COMMAND ${CMAKE_SOURCE_DIR}/utils/chen/target/release/chen ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL}
	COMMENT "Adding symbols..."
	POST_BUILD
)

add_custom_target(
	copy_symbols
	COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL}.map ${ISO_DIR}/${KERNEL}.map
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	DEPENDS ${KERNEL}
	COMMENT "Copying files..."
)

if(
	(NOT (${CMAKE_BUILD_TYPE} STREQUAL "Debug"))
	AND
	(NOT (${CMAKE_BUILD_TYPE} STREQUAL "Dev"))
    AND
	(NOT (${CMAKE_BUILD_TYPE} STREQUAL "OptSym"))
	)
    
	add_custom_target(
			strip_down
            COMMAND strip -s ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL}
            COMMENT "Copying files..."
			DEPENDS copy_symbols
    )

    add_custom_target(
            copy_kernel
            COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL} ${ISO_DIR}/${KERNEL}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            DEPENDS strip_down
            COMMENT "Copying files..."
    )
else()
    add_custom_target(
            copy_kernel
            COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL} ${ISO_DIR}/${KERNEL}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            DEPENDS copy_symbols
            COMMENT "Copying files..."
    )
endif()

add_custom_target(
	clippy
    COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} clippy --target ${RUST_TARGET} ${RUST_FLAGS}
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/rust
	USES_TERMINAL
	VERBATIM
)

add_custom_target(
	clippy-fix
  COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} clippy --fix --target ${RUST_TARGET} ${RUST_FLAGS}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/rust
	USES_TERMINAL
	VERBATIM
)

add_custom_target(
	fmt
	COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} fmt
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/rust
	USES_TERMINAL
	VERBATIM
)

add_custom_target(
	check
	COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} check
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/rust
	USES_TERMINAL
	VERBATIM
)

add_custom_target(
	doc
	COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} doc --target ${RUST_TARGET} ${RUST_FLAGS} --open
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/rust
	USES_TERMINAL
	VERBATIM
)

add_custom_target(
	tree
	COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} tree
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/rust
	USES_TERMINAL
	VERBATIM
)

add_custom_target(
    ramdisk
    COMMAND tar cvf ${ISO_DIR}/ramdisk -C ramdisk/ .
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS copy_kernel
)

add_custom_target(
	iso
	COMMAND ${MKRESCUE} ${MKRESCUE_FLAGS}
	DEPENDS ramdisk
)

add_custom_target(
	run
	COMMAND ${QEMU} -accel kvm ${QEMU_FLAGS}
	USES_TERMINAL
	DEPENDS iso
)

add_custom_target(
	run_with_disk
	COMMAND ${QEMU} -accel kvm ${QEMU_FLAGS} -hda ${CMAKE_SOURCE_DIR}/test_disk.img
	USES_TERMINAL
	DEPENDS iso
)

add_custom_target(
	run_with_disk_ahci
    COMMAND ${QEMU} -accel kvm ${QEMU_FLAGS} -device ahci,id=ahci -drive id=thatdisk,file=${CMAKE_SOURCE_DIR}/test_disk.img,if=none -device ide-hd,drive=thatdisk,bus=ahci.1 -drive id=thatcdrom,file=${CMAKE_SOURCE_DIR}/test_iso.iso,if=none -device ide-cd,drive=thatcdrom,bus=ahci.0
    USES_TERMINAL
    DEPENDS iso
)

# add_custom_target(
# 	run_with_disk_ahci
# 	COMMAND ${QEMU} -accel kvm ${QEMU_FLAGS} -device ahci,id=ahci -drive id=thatdisk,file=${CMAKE_SOURCE_DIR}/test_iso.iso,if=none -device ide-hd,drive=thatdisk,bus=ahci.0 
#     USES_TERMINAL
# 	DEPENDS iso
# )

add_custom_target(
	run_with_hda
    COMMAND ${QEMU} -accel kvm ${QEMU_FLAGS} -device ich9-intel-hda -device hda-output,audiodev=audiopa,debug=1
    USES_TERMINAL
    DEPENDS iso
)

add_custom_target(
	debug
    COMMAND ${QEMU} -accel kvm ${QEMU_FLAGS} -s -S
    USES_TERMINAL
    DEPENDS iso
)
