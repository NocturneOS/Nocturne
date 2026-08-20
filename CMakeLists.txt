cmake_minimum_required(VERSION 4.2.1)

project(NocturneOS VERSION 0.4.3)
enable_language(ASM)

set(CMAKE_CONFIGURATION_TYPES "Debug;Release;ReleaseSym;ReleaseOptimized;ReleaseOptSym" CACHE STRING "Available configurations" FORCE)

if(NOT CMAKE_BUILD_TYPE)
	message(WARNING
												"No build configuration selected! Please specify one of the following:\n"
												"  -DCMAKE_BUILD_TYPE=Debug\n"
												"  -DCMAKE_BUILD_TYPE=Release\n"
												"  -DCMAKE_BUILD_TYPE=ReleaseSym\n"
												"  -DCMAKE_BUILD_TYPE=ReleaseOptimized\n"
												"  -DCMAKE_BUILD_TYPE=ReleaseOptSym\n"
												"Defaulting to: Debug"
				)
	set(CMAKE_BUILD_TYPE "Debug")
endif()

set(VALID_ARCHITECTURES "x86" "x86_64")

if(NOT NOCTURNE_ARCH)
	set(NOCTURNE_ARCH "x86")
endif()

list(FIND VALID_ARCHITECTURES "${NOCTURNE_ARCH}" __INDEX)
if(__INDEX EQUAL -1)
	message(FATAL_ERROR "Invalid architecture: ${NOCTURNE_ARCH}. Accepted values are: ${VALID_ARCHITECTURES}")
endif()

if(NOCTURNE_ARCH STREQUAL "x86")
	set(CMAKE_ASM_FLAGS "-m32 -mcmodel=kernel -fno-pic -static -g -I${CMAKE_SOURCE_DIR}/src/arch/x86/asm")
elseif(NOCTURNE_ARCH STREQUAL "x86_64")
	set(CMAKE_ASM_FLAGS "-m64 -mcmodel=kernel -fno-pic -static -g -I${CMAKE_SOURCE_DIR}/src/arch/x86/asm -I${CMAKE_SOURCE_DIR}/src/arch/x86_64/asm")
endif()

if(NOCTURNE_ARCH STREQUAL "x86")
	set(RUST_TARGET_TRIPLE "i686-unknown-none")
elseif(NOCTURNE_ARCH STREQUAL "x86_64")
	set(RUST_TARGET_TRIPLE "x86_64-unknown-none")
endif()

set(ISO_DIR "${CMAKE_SOURCE_DIR}/iso/")
set(KERNEL nocturne.elf)


if(NOCTURNE_ARCH STREQUAL "x86")
	set(LINKER_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/src/arch/x86/link.ld")
	set(CMAKE_EXE_LINKER_FLAGS "-Wl,-T${LINKER_SCRIPT_FILE} -nostdlib -fno-pic -static -Wl,-znoexecstack -Wl,--stats -Wl,-zmax-page-size=4096")
elseif(NOCTURNE_ARCH STREQUAL "x86_64")
	set(LINKER_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/src/arch/x86_64/link.ld")
	set(CMAKE_EXE_LINKER_FLAGS "-Wl,-T${LINKER_SCRIPT_FILE} -nostdlib -fno-pic -static -Wl,-znoexecstack -Wl,--stats -Wl,-zmax-page-size=4096")
endif()

set(ISO_FILE "NocturneOS_${NOCTURNE_ARCH}_${CMAKE_BUILD_TYPE}.iso")

# Emulator

set(QEMU_MEMORY_SIZE 128M)

if(NOCTURNE_ARCH STREQUAL "x86_64")
	set(QEMU "qemu-system-x86_64")
elseif(NOCTURNE_ARCH STREQUAL "x86")
	set(QEMU "qemu-system-i386")
endif()

if(NOCTURNE_ARCH STREQUAL "x86_64")
	set(QEMU_FLAGS -no-reboot -no-shutdown ${QEMU_ADDITIONAL_FLAGS} -m ${QEMU_MEMORY_SIZE} -cdrom ${CMAKE_CURRENT_BINARY_DIR}/${ISO_FILE} -d int,cpu_reset,guest_errors,invalid_mem -serial mon:stdio -rtc base=localtime -boot d -usb -audiodev pa,id=audiopa -device ac97,audiodev=audiopa -netdev user,id=net0,net=192.168.111.0,dhcpstart=192.168.111.128,hostfwd=tcp::9999-:9999 -device rtl8139,netdev=net0,id=mydev0 -object filter-dump,id=dump0,netdev=net0,file=netdump.pcap -trace "*ac97*")
else()
	set(QEMU_FLAGS -no-reboot -no-shutdown ${QEMU_ADDITIONAL_FLAGS} -m ${QEMU_MEMORY_SIZE} -cdrom ${CMAKE_CURRENT_BINARY_DIR}/${ISO_FILE} -d int,cpu_reset,guest_errors,invalid_mem -serial mon:stdio -rtc base=localtime -boot d -usb -audiodev pa,id=audiopa -device ac97,audiodev=audiopa -netdev user,id=net0,net=192.168.111.0,dhcpstart=192.168.111.128,hostfwd=tcp::9999-:9999 -device rtl8139,netdev=net0,id=mydev0 -object filter-dump,id=dump0,netdev=net0,file=netdump.pcap -trace "*ac97*")
endif()

set(MKRESCUE grub-mkrescue)
set(MKRESCUE_FLAGS -o "${CMAKE_CURRENT_BINARY_DIR}/${ISO_FILE}" ${ISO_DIR} --locales="" -V NocturneOS --themes="" --fonts="ascii")

if(NOCTURNE_ARCH STREQUAL "x86")
	set(ASM_SRC
		src/arch/x86/asm/init.s
		src/arch/x86/asm/gdt.s
		src/arch/x86/asm/context_switch.s
		src/arch/x86/asm/interrupt.s
	)
elseif(NOCTURNE_ARCH STREQUAL "x86_64")
	set(ASM_SRC
		src/arch/x86_64/asm/init.s
		src/arch/x86_64/asm/gdt.s
		src/arch/x86_64/asm/interrupt.s
		src/arch/x86_64/asm/context_switch.s
		src/arch/x86_64/asm/syscall.s
	)
endif()

add_executable(${KERNEL} ${ASM_SRC})

set_property(TARGET ${KERNEL} PROPERTY
				LINK_DEPENDS "${LINKER_SCRIPT_FILE}"
)

# Rust

include(cmake/Rust.cmake)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_rust_integration("debug")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
	add_rust_integration("release_no_opt")
elseif(CMAKE_BUILD_TYPE STREQUAL "ReleaseSym")
	add_rust_integration("release_no_opt_sym")
elseif(CMAKE_BUILD_TYPE STREQUAL "OptSym")
	add_rust_integration("release_opt_sym")
else()
	add_rust_integration("release")
endif()

# Targets

add_custom_command(
	TARGET ${KERNEL}
	COMMAND ${CMAKE_SOURCE_DIR}/utils/chen/target/release/chen ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL}
	COMMENT "Adding symbols..."
	POST_BUILD
)

add_custom_target(
	check_mb2
	COMMAND grub-file --is-x86-multiboot2 ${KERNEL}
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	DEPENDS ${KERNEL}
	COMMENT "Checking Multiboot2 header..."
)

add_custom_target(
	copy_symbols
	COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL}.map ${ISO_DIR}/${KERNEL}.map
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	DEPENDS check_mb2
	COMMENT "Copying files..."
)

if(
	(${CMAKE_BUILD_TYPE} STREQUAL "Release")
	OR (${CMAKE_BUILD_TYPE} STREQUAL "ReleaseOptimized")
)

	add_custom_target(
		strip_down
		COMMAND strip -s ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL}
		COMMENT "Stripping binary..."
		DEPENDS copy_symbols
	)

	add_custom_target(
		copy_kernel
		COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL} ${ISO_DIR}/${KERNEL}
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
		DEPENDS strip_down
		COMMENT "Copying kernel to iso..."
	)
else()
	add_custom_target(
		copy_kernel
		COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL} ${ISO_DIR}/${KERNEL}
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
		DEPENDS copy_symbols
		COMMENT "Copying kernel to iso..."
	)
endif()

add_custom_target(
	clippy
	COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} clippy --target ${RUST_TARGET} ${RUST_FLAGS}
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	USES_TERMINAL
	VERBATIM
)

add_custom_target(
	fmt
	COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} fmt
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	USES_TERMINAL
	VERBATIM
)

add_custom_target(
	check
	COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} check
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	USES_TERMINAL
	VERBATIM
)

add_custom_target(
	doc
	COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} doc --target ${RUST_TARGET} ${RUST_FLAGS} --open
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
	USES_TERMINAL
	VERBATIM
)

add_custom_target(
	tree
	COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} tree
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
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

add_custom_command(
	OUTPUT "${CMAKE_SOURCE_DIR}/test_disk.img"
	COMMAND dd if=/dev/zero of=${CMAKE_SOURCE_DIR}/test_disk.img bs=1K count=64000
	COMMENT "Making disk..."
	VERBATIM
)

add_custom_target(create_disk DEPENDS ${CMAKE_SOURCE_DIR}/test_disk.img)

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
	DEPENDS iso create_disk
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

add_custom_target(
	debug_with_disk
				COMMAND ${QEMU} -accel kvm ${QEMU_FLAGS} -s -S -hda ${CMAKE_SOURCE_DIR}/test_disk.img
				USES_TERMINAL
				DEPENDS iso
)
