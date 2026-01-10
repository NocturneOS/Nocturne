/**
 * @file sys/elf.c
 * @author Пиминов Никита (nikita.piminoff@yandex.ru), NDRAEY >_ (pikachu_andrey@vk.com)
 * @brief Загрузщик ELF
 * @version 0.4.3
 * @date 2022-10-20
 * @copyright Copyright SayoriOS Team (c) 2022-2026
*/

#include <mem/pmm.h>
#include <elf/elf.h>
#include <io/logging.h>
#include <lib/stdio.h>
#include <lib/math.h>
#include "sys/scheduler/scheduler.h"

elf_t* load_elf(const char* name){
	/* Allocate ELF file structure */
	elf_t* elf = kmalloc_common(sizeof(elf_t), 4);
    memset(elf, 0, sizeof(elf_t));

	/* Open ELF file */
	FILE *file_elf = fopen(name, O_READ);

	if (file_elf->err) {
		qemu_err("Failed to open ELF file: %s / %d", name, file_elf->err);
		return nullptr;
	}

	/* Read ELF header */
	fread(file_elf, 1, sizeof(Elf32_Ehdr), &elf->elf_header);

	/* Read program header */
	const Elf32_Half proc_entries = elf->elf_header.e_phnum;
	const uint32_t proc_size = elf->elf_header.e_phentsize;

	elf->p_header = (Elf32_Phdr*)kcalloc(proc_size, proc_entries);

	fseek(file_elf, (ssize_t)elf->elf_header.e_phoff, SEEK_SET);

	fread(file_elf, proc_entries, proc_size, elf->p_header);

	/* Read ELF sections */
	Elf32_Half sec_entries = elf->elf_header.e_shnum;

	elf->section = (Elf32_Shdr*)kcalloc(sizeof(Elf32_Shdr), sec_entries);

	fseek(file_elf, (ssize_t)elf->elf_header.e_shoff, SEEK_SET);

	fread(file_elf, sec_entries, sizeof(Elf32_Shdr), elf->section);

	elf->file = file_elf;

	return elf;
}

void unload_elf(elf_t* elf) {
	kfree(elf->p_header);
	kfree(elf->section);
	fclose(elf->file);

	kfree(elf);
}

atomic_flag elf_loader_mutex = ATOMIC_FLAG_INIT;

int32_t spawn_prog(const char *name, int argc, const char* const* eargv) {
    elf_t* elf_file = load_elf(name);

    if (elf_file == nullptr) {
        qemu_err("[DBG] Error opening file %s\n", name);
        return -1;
    }

    spinlock_get(&elf_loader_mutex);

    extern volatile uint32_t next_pid;

    process_t* proc = allocate_one(process_t);

    proc->pid = next_pid++;
    proc->list_item.list = nullptr;  // No nested processes hehe :)
    proc->threads_count = 0;

    proc->name = strdynamize(name);

    for (int32_t i = 0; i < elf_file->elf_header.e_phnum; i++) {
        Elf32_Phdr *phdr = elf_file->p_header + i;

        if (phdr->p_type != PT_LOAD)
            continue;

        size_t pagecount = MAX((ALIGN(phdr->p_memsz, PAGE_SIZE) / PAGE_SIZE), 1u);

        physical_addr_t addrto = phys_alloc_multi_pages(pagecount);

        map_pages(
                get_kernel_page_directory(),
                addrto,
                phdr->p_vaddr,
                pagecount * PAGE_SIZE,
                (PAGE_USER | PAGE_WRITEABLE)
        );

        memset((void*)phdr->p_vaddr, 0, phdr->p_memsz);
        qemu_log("Set %x - %x to zero.", (int)((void*)phdr->p_vaddr), (int)((void*)phdr->p_vaddr) + phdr->p_memsz);

        fseek(elf_file->file, (ssize_t)phdr->p_offset, SEEK_SET);
        fread(elf_file->file, phdr->p_filesz, 1, (char *) phdr->p_vaddr);

        qemu_log("Loaded");
    }

    int(*entry_point)(int argc, char* eargv[]) = (int(*)(int, char**))elf_file->elf_header.e_entry;
    qemu_log("ELF entry point: %x", elf_file->elf_header.e_entry);
    
    proc->program = elf_file;
    
    process_add_prepared(proc);

    thread_t* thread = _thread_create_unwrapped(
        proc,
        entry_point,
        DEFAULT_STACK_SIZE,
        0,
        (size_t*)eargv,
        argc
    );

    // Update process data after adding it
    void* virt = clone_kernel_page_directory((size_t*)proc->page_tables_virts);
    uint32_t phys = virt2phys(get_kernel_page_directory(), (virtual_addr_t) virt);

    proc->page_dir = phys;
    proc->page_dir_virt = (virtual_addr_t)virt;

    qemu_log("PROCESS CREATED, CLEANING KERNEL PD");

    for (int32_t i = 0; i < elf_file->elf_header.e_phnum; i++) {
        Elf32_Phdr *phdr = elf_file->p_header + i;

        if(phdr->p_type != PT_LOAD)
            continue;

        size_t pagecount = MAX((ALIGN(phdr->p_memsz, PAGE_SIZE) / PAGE_SIZE), 1u);

        qemu_log("\t- Cleaning %d: %x [%d]", i, phdr->p_vaddr, pagecount * PAGE_SIZE);

        for(size_t x = 0; x < pagecount; x++) {
            unmap_single_page(
                get_kernel_page_directory(),
                phdr->p_vaddr + (x * PAGE_SIZE)
            );
        }
    }

    qemu_log("CLEANED %d pages",  elf_file->elf_header.e_phnum);

    qemu_log("RESUMING...");

    spinlock_release(&elf_loader_mutex);

    thread->state = CREATED;

    return proc->pid;
}
