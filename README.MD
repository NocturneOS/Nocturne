![NocturneOS](static/NocturneOS.png)

# NocturneOS

NocturneOS is a SayoriOS fork.

![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
![Rust](https://img.shields.io/badge/rust-%239A0000.svg?style=for-the-badge&logo=rust&logoColor=white)


![Workflow](https://github.com/NDRAEY/NocturneOS-base/actions/workflows/Nocturne-Auto.yml/badge.svg)
![Warnings](https://badgen.net/https/nocturneos.github.io/Nocturne/warning_count.txt?cache=3600)

It's a simple operating system for x86-based computers.
It's written in C, Rust and x86 Assembly.

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

NocturneOS Team welcomes new developers, testers and users!

### If you're a developer

If you want to help this project you can do following things:

- Clone NocturneOS sources.
- Create a separate branch (`git checkout -b ...`) for your changes
- Make your changes and commit them
- Make a pull request

Your contribution is very appreciated!

### <a id="testers">Если вы тестировщик</a>

Если вы нашли ошибку в проекте или у вас есть предложения по улучшению, пожалуйста, создайте новый Issue в репозитории проекта. Опишите проблему или предложение подробно, чтобы мы могли понять и рассмотреть их.

Еще одним способом помочь проекту является тестирование. Вы можете протестировать новые функции, исправления ошибок и сообщить о найденных проблемах.

Последний релиз: https://github.com/pimnik98/SayoriOS/releases

### <a id="adv">Пиар</a>

Если вы готовы сделать обзор ОС или написать о ней где-нибудь, пожалуйста свяжитесь с координационной группой проекта.

## <a id="legalinfo">Правовая информаиция<a/>

### <a id="denialofresponsibility">Отказ от отвественности</a>

NocturneOS это не дистрибутив Linux, это совершенно-новый проект который не имеет за собой компании или организации которая могла бы дать гарантий.

Ядро NocturneOS имеет открытый исходный код, вы можете сами удостовериться в отсутствии вредоносного ПО изучая файлы этого репозитория.

При использовании материалов вы обязуетесь соблюдать авторские права.

Участники проекта не несут ответственности за причиненный ущерб возникший в результате использования проекта. Используйте на свой страх и риск.

Запуск ядра возможен на реальном оборудовании, были тесты и на некоторых устройствах оно реально запустилось, хоть и с ограничениями

## <a id="contributors">Благодарности</a>

* [Никита Пиминов](https://github.com/pimnik98) (Создатель SayoriOS)
* [Михаил Глухов](https://github.com/rigidus) (README)
