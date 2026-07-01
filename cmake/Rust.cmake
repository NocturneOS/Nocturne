#set(RUST_TARGET "${CMAKE_SOURCE_DIR}/src/arch/${NOCTURNE_ARCH}/${RUST_TARGET_TRIPLE}.json")
set(RUST_COMPILER_TOOLCHAIN "nightly-2026-06-01")
set(RUST_FLAGS
	-Zbuild-std=core,compiler_builtins,alloc
	-Znext-lockfile-bump
	--
	-C code-model=kernel
	-C relocation-model=static
)
if(RUST_TARGET_TRIPLE STREQUAL "i686-unknown-none")
  set(RUST_TARGET "${CMAKE_SOURCE_DIR}/src/arch/${NOCTURNE_ARCH}/${RUST_TARGET_TRIPLE}.json")
  set(RUST_FLAGS -Zjson-target-spec ${RUST_FLAGS})
else()
  set(RUST_TARGET ${RUST_TARGET_TRIPLE})
endif()

set(RUST_TOOLCHAIN_FULLNAME "${RUST_COMPILER_TOOLCHAIN}-x86_64-unknown-none")  
set(RUST_CARGO_PATH "~/.rustup/toolchains/${RUST_TOOLCHAIN_FULLNAME}/bin/src/cargo")

add_custom_command(
	OUTPUT "${CMAKE_SOURCE_DIR}/utils/chen/target/release/chen" ".fake"
	COMMAND cargo build --release
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/utils/chen
	COMMENT "Building Chen utility..."
	DEPENDS "${CMAKE_SOURCE_DIR}/utils/chen/src"
	DEPENDS "${CMAKE_SOURCE_DIR}/utils/chen/Cargo.toml"
	USES_TERMINAL
	VERBATIM
)

add_custom_target(chen ALL DEPENDS "${CMAKE_SOURCE_DIR}/utils/chen/target/release/chen")
add_dependencies(${KERNEL} chen)

function(add_rust_integration build_type)
	if(${build_type} STREQUAL "debug")
		set(rust_profile "dev")
	else()
		set(rust_profile ${build_type})
	endif()

	add_custom_command(
		OUTPUT "${CMAKE_SOURCE_DIR}/target/${RUST_TARGET_TRIPLE}/${build_type}/libnocturne.a" "fake.a"
		COMMAND cargo +${RUST_COMPILER_TOOLCHAIN} rustc --target ${RUST_TARGET} --profile ${rust_profile} ${RUST_FLAGS}
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
		COMMENT "Building Rust files..."
		DEPENDS "${CMAKE_SOURCE_DIR}/src"
		DEPENDS "${CMAKE_SOURCE_DIR}/Cargo.toml"
		USES_TERMINAL
		VERBATIM
	)

	add_custom_target(rs ALL DEPENDS "${CMAKE_SOURCE_DIR}/target/${RUST_TARGET_TRIPLE}/${build_type}/libnocturne.a")
	add_dependencies(${KERNEL} rs)

	target_link_libraries(${KERNEL} "${CMAKE_SOURCE_DIR}/target/${RUST_TARGET_TRIPLE}/${build_type}/libnocturne.a")

	message("Added Rust: ${RUST_TARGET_TRIPLE}/${build_type}")
endfunction()
