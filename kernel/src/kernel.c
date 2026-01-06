/**
 * @file kernel.c
 * @author Пиминов Никита (nikita.piminoff@yandex.ru), NDRAEY >_ (pikachu_andrey@vk.com)
 * @brief Основная точка входа в ядро
 * @version 0.4.3
 * @date 2022-11-01
 * @copyright Copyright SayoriOS Team (c) 2022-2026
 */

#include "kernel.h"

#include <stdint.h>
#include <sys/unwind.h>

#include "arch/x86/mem/paging.h"
#include "arch/x86/mem/paging_common.h"
#include "arch/x86/pic.h"
#include "arch/x86/registers.h"
#include "drv/cmos.h"
#include "io/logging.h"
#include "io/ports.h"
#include "io/tty.h"
#include "mem/pmm.h"
#include "mem/vmm.h"
#include "drv/audio/ac97.h"
#include "sys/cpuid.h"
#include "sys/scheduler/scheduler.h"
#include "sys/scheduler/thread.h"
#include "lib/vector.h"

#ifdef NOCTURNE_X86
#include "arch/x86/msr.h"
#include "arch/x86/mtrr.h"
#include "arch/x86/cputemp.h"
#include <arch/x86/gdt.h>
#include <arch/x86/idt.h>
#include <arch/x86/sse.h>
#include <arch/x86/serial_port.h>
#include "sys/apic.h"
#endif

#include "net/ipv4.h"

#include "net/stack.h"
#include "drv/audio/hda.h"
#include "sys/grub_modules.h"
#include "sys/file_descriptors.h"
#include "drv/ps2.h"
#include "net/dhcp.h"
#include "gfx/intel.h"

#include <drv/disk/media_notifier.h>

#include <lib/pixel.h>
#include <net/socket.h>

#include <generated/input.h>

#include <user/env.h>
#include <arch/init.h>

size_t VERSION_MAJOR = 0;      /// Мажор
size_t VERSION_MINOR = 4;      /// Минор
size_t VERSION_PATCH = 3;      /// Патч

char* OS_ARCH = "i386";        /// Архитектура
char* VERSION_NAME = "Leap";   /// Имя версии (изменяется вместе с патчем)

extern bool ps2_channel2_okay;

bool test_network = true;
size_t kernel_start_time = 0;

/**
 * @brief Точка входа в ядро
 *
 * @param multiboot_header_t mboot - Информация MultiBoot
 * @param initial_esp -  Точка входа
 */

extern size_t CODE_start;
extern size_t CODE_end;
extern size_t DATA_start;
extern size_t DATA_end;
extern size_t RODATA_start;
extern size_t RODATA_end;
extern size_t BSS_start;
extern size_t BSS_end;

extern void rust_main();
extern void ipc_init();

extern void fpu_save();

void new_nsh();

extern size_t KERNEL_BASE_pos;
extern size_t KERNEL_END_pos;


void task01() {
    for(int i = 0; i < 5; i++) {
        qemu_log("Task A");
        sleep_ms(100);
    }

    // Exit
}

/*
  Спаси да сохрани этот кусок кода
  Да на все твое кодерская воля
  Да прибудет с тобой, священный код
  Я тебя благославляю
*/
__attribute__((aligned(0x1000)))
void __attribute__((noreturn)) kmain(const multiboot_header_t *mboot)
{
    drawASCIILogo(0);

    qemu_log("SayoriOS v%d.%d.%d\nBuilt: %s",
             VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, // Версия ядра
             __TIMESTAMP__                                // Время окончания компиляции ядра
    );

    qemu_log("Bootloader header at: %x", (size_t)mboot);

    qemu_log("SSE: %s", sse_check() ? "Supported" : "Not supported");

    qemu_log("Initializing GDT and IDT...");
    init_gdt();

    pic_init();
    init_idt();
    
    qemu_log("Setting `ISR`...");
    isr_init();

    qemu_log("Checking RAM...");
    check_memory_map((memory_map_entry_t *)mboot->mmap_addr, mboot->mmap_length);
    qemu_log("Memory summary:");
    qemu_log("    Code: %x - %x", (size_t)&CODE_start, (size_t)&CODE_end);
    qemu_log("    Data: %x - %x", (size_t)&DATA_start, (size_t)&DATA_end);
    qemu_log("    Read-only data: %x - %x", (size_t)&RODATA_start, (size_t)&RODATA_end);
    qemu_log("    BSS: %x - %x", (size_t)&BSS_start, (size_t)&BSS_end);
    qemu_log("Memory manager initialization...");

    grub_modules_prescan(mboot);

    init_pmm(mboot);
    init_paging(mboot);

    mark_reserved_memory_as_used((memory_map_entry_t *)mboot->mmap_addr, mboot->mmap_length);

    qemu_ok("PMM Ok!");

    vmm_init();
    qemu_ok("VMM OK!");

    mtrr_init();

    __asm__ volatile("cli");
    
    init_timer(CLOCK_FREQ);
    
    apic_init();
    
    __asm__ volatile("sti");

    // while(1) {
    //     sayori_time_t time = get_time();

    //     qemu_log("Crazy! (%02d:%02d:%02d)", time.hours, time.minutes, time.seconds);

    //     sleep_ms(1000);
    // }
    
    init_syscalls();
    
    keyboard_buffer_init();
    
    ps2_init();
    ps2_keyboard_init();

    if (ps2_channel2_okay)
    {
        mouse_install();
    }

    ps2_keyboard_install_irq();
    ps2_mouse_install_irq();

    cpu_get_info(&boot_cpu_info);
    qemu_log("Boot CPU: %s (%s)", boot_cpu_info.model_string, boot_cpu_info.brand_string);
    
    // kHandlerCMD((char *)mboot->cmdline);
    
    qemu_log("Initializing Task Manager...");
    init_task_manager();

    // thread_create(get_current_proc(), task01, 0x100, THREAD_KERNEL, NULL, 0);

    // while(1)
    //     ;

    ipc_init();

    // drv_vbe_init(mboot);

    qemu_log("Audio system init");
    audio_system_init();

    qemu_log("FSM Init");
    fsm_init();

    qemu_log("Registration of file system drivers...");
    fs_tarfs_register();    
    fs_fatfs_init();  
    fs_iso9660_init();
    fs_noctfs_init();
    
    grub_modules_init(mboot);

    // TarFS registered by grub_modules_init will always have the name `rd0`.
    fsm_dpm_update("rd0");

    kernel_start_time = getTicks();

    qemu_log("Initializing the virtual video memory manager...");
    init_vbe(mboot);

    psf_init("rd0:/Sayori/Fonts/UniCyrX-ibm-8x16.psf");

    qemu_log("Initalizing fonts...");
    tty_init();

    clean_screen();

    // tty_puts("ABCDEFGHIJKLMNOPQRSTUVWXYZ\n");
    // tty_puts("abcdefghijklmnopqrstuvwxyz\n");
    // tty_puts("0123456789\n");
    // tty_puts("!@#$%^&*()\n");
    // tty_puts("`~\n");
    // tty_puts("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ\n");
    // tty_puts("абвгдеёжзийклмнопрстуфхцчшщъыьэюя\n");

    // while(1)
    //     ;

    bootScreenInit(15);
    bootScreenLazy(true);

    bootScreenPaint("PCI Setup...");
    pci_scan_everything();

    bootScreenPaint("Инициализация ATA...");
    ata_init();
    ata_dma_init();
    
    bootScreenPaint("Калибровка датчика температуры процессора...");
    cputemp_calibrate();

    file_descriptors_init();

    configure_env();

    netcards_list_init();

    bootScreenPaint("Инициализация сетевого стека...");
    netstack_init();

    bootScreenPaint("Инициализация ARP...");
    arp_init();

    bootScreenPaint("Инициализация RTL8139...");
    rtl8139_init();

    bootScreenPaint("Инициализация DHCP...");
    dhcp_init_all_cards();

    bootScreenPaint("Готово...");
    bootScreenClose(0x000000, 0xFFFFFF);
    tty_set_bgcolor(COLOR_BG);

    tty_printf("NocturneOS v%d.%d.%d '%s' for %s\nДата компиляции: %s\n",
               VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, // Версия ядра
               VERSION_NAME,
               NOCTURNE_ARCH_STRING,
               __TIMESTAMP__                                // Время окончания компиляции ядра
    );

    tty_printf("\nВлюбиться можно в красоту, но полюбить - лишь только душу.\n(c) Уильям Шекспир\n");

    tty_printf("\nCPU: %s (%s)\n", boot_cpu_info.model_string, boot_cpu_info.brand_string);
    
    ahci_init();

    sayori_time_t time = get_time();
    tty_printf("\nВремя: %02d:%02d:%02d\n", time.hours, time.minutes, time.seconds);

    tty_printf("Listing ATA disks:\n");

    ata_list();

    tty_taskInit();

    {
        RSDPDescriptor *rsdp = acpi_rsdp_find();
        qemu_log("RSDP at: %p", rsdp);

        if (rsdp)
        {
            acpi_scan_all_tables(rsdp->RSDTaddress);

            acpi_find_facp(rsdp->RSDTaddress);
        }
        else
        {
            tty_printf("ACPI not supported! (Are you running in UEFI mode?)\n");
            qemu_err("ACPI not supported! (Are you running in UEFI mode?)");
        }
    }

    //tty_printf("Processors: %d\n", system_processors_found);

    if (test_network)
    {
        tty_printf("Listing network cards:\n");

        uint8_t mac_buffer[6] = {0};

        for (size_t i = 0; i < netcards_get_count(); i++)
        {
            netcard_entry_t *entry = netcard_get(i);

            tty_printf("\tName: %s\n", entry->name);
            entry->get_mac_addr(mac_buffer);

            tty_printf("\tMAC address: %x:%x:%x:%x:%x:%x\n",
                        mac_buffer[0],
                        mac_buffer[1],
                        mac_buffer[2],
                        mac_buffer[3],
                        mac_buffer[4],
                        mac_buffer[5]);
        }
    }

    ac97_init();
    // hda_init();

    /// Обновим данные обо всех дисках
    fsm_dpm_update(NULL);

    igfx_init();

    rust_main();

    qemu_log("System initialized everything at: %f seconds.", (double)(getTicks() - kernel_start_time) / getFrequency());
    tty_printf("System initialized everything at: %.2f seconds.\n", (double)(getTicks() - kernel_start_time) / getFrequency());

    launch_media_notifier();

    // net_test();

    // spawn_prog("rd0:/clihlt", 0, NULL);

    new_nsh();

    while (1)
        ;
}

// TODO: The following code is a sketch of future socket system. It may change, may not.

// void net_test() {
//     socket_address_t server_addr = {
//         .address = {192, 168, 1, 128},
//         .port = 9999
//     };

//     char data[32] = {0};

//     socket_t* srv_sock = socket_new(&server_addr, PROTO_TCP);
//     socket_t* client_sock = socket_listen(srv_sock);

//     if(client_sock) {
//         socket_read_until_newline(client_sock, data);

//         socket_close(client_sock);
//     }

//     int length = strlen(data);

//     qemu_note("Received %d bytes with data: `%s`", length, data);
//     socket_close(srv_sock);
// }
