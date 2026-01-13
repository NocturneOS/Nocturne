![NocturneOS](static/NocturneOS.png)

# NocturneOS

NocturneOS is a SayoriOS fork.

![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
![Rust](https://img.shields.io/badge/rust-%239A0000.svg?style=for-the-badge&logo=rust&logoColor=white)


![Workflow](https://github.com/NDRAEY/NocturneOS-base/actions/workflows/Nocturne-Auto.yml/badge.svg)
![Warnings](https://badgen.net/https/nocturneos.github.io/Nocturne/warning_count.txt?cache=3600)

It's a simple operating system for x86-based computers.
Written in C, Rust and x86 Assembly.

* [NocturneOS updates channel (IN RUSSIAN!)](https://t.me/ndraey_ch)

## Targets

* Be minimal.
* Be useful.
* Be convinient to use.
* Be versatile.

## Why?

ACHTUNG: This project DOESN'T approach to replace existing OSes IN ANY WAY.

This project is created for:

- Learning low-level programming and OSDEV.
- Just for fun, why not?
- Experiments

## Screenshots

Coming soon :)

## System requirements

- Processor: Any 32-bit or 64-bit x86 processor
- RAM: 64 MB
- HDD and other drives: not necessary
- Video: any video adapter

## Components

- Kernel
  - Physical memory manager and kernel heap
  - CMOS clock
  - Multitasking
  - PCI
- Drivers (built into kernel)
  - PS/2 keyboard and mouse
  - PC Speaker
  - Realek RTL-8139 network card
  - ATA drives (PIO + DMA; HD + Optical)
  - AHCI drives (HD + Optical)
- Filesystems (built into kernel)
  - TarFS
  - NoctFS
  - FAT32 (Read-Only)
- Network protocols (built into kernel)
  - ARP
  - UDP
  - DHCP
- Other (built into kernel)
  - ELF32 executable support
  - Processor info
  - FPU
  - UEFI support (Not tested yet!)

## Build

If you want to just write/port some software for NocturneOS, you'll have to download NocturneSDK: https://github.com/NocturneOS/NocturneSDK

Supported host systems are Linux or Windows with WSL.

Make sure you have build tools installed:
```bash
sudo apt-get install python3 gcc cmake ninja-build xorriso mtools grub-pc-bin
```

NocturneOS has modules written in Rust programming language, so you'll have to install it too:
```bash
curl https://sh.rustup.rs -sSf | sh
```

Run this script to get needed nightly compiler and std sources:
```bash
bash tools/rust.sh
```

If you plan to run NocturneOS in QEMU, make sure you installed it too:
```bash
sudo apt-get install qemu-system-x86 qemu-tools
```

Then finally clone the repo:
```bash
git clone https://github.com/NocturneOS/Nocturne NocturneOS
```

Enter the directory:
```bash
cd NocturneOS
```

Let's make a build with default configuration:
```bash
cmake -B cmake-build-debug -G Ninja . -DCMAKE_BUILD_TYPE=Debug
```

Compile the build and run in QEMU
```bash
cmake --build cmake-build-debug/ -j$(nproc) -- run
```

NOTE: Replace `run` with `iso` to just make an ISO file. It will be placed in the build folder (`cmake-build-debug/` in our case).

## Contribution

NocturneOS Team always welcomes new developers, testers and users!

Here's some instructions:

### If you're a developer

If you want to help this project you can do following things:

- Clone NocturneOS sources.
- Create a separate branch (`git checkout -b ...`) for your changes
- Make your changes, commit them and push to your repo.
- Make a pull request

Your contribution is very appreciated!

### If you're a tester

You can build OS from sources as described in `Build` section or download a `latest-unstable` .iso release from the [Releases](https://github.com/pimnik98/SayoriOS/releases) page for testing.

If you found a bug or other mistake in the project, create a new issue in the `Issues` tab.
Describe the problem in details so we can help you.

## Legal info

### Denial of responsibility

NocturneOS IS NOT a Linux distribution. It's a brand-new project that is not linked to some company or organization that can guarantee its stability.

The NocturneOS kernel is open-source and you can ensure that there's no built-in malware by looking through the code.

When using the materials, you agree to respect the copyright.

The project contributors are not responsible for any damage caused as a result of using the project. Use it at your own risk.

## Special thanks

* [Nikita Piminov](https://github.com/pimnik98) (The SayoriOS creator)
* [Michael Glukhov](https://github.com/rigidus) (Russian README version)
