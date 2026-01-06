/**
 * @file drv/fs/fsm.c
 * @author Пиминов Никита (nikita.piminoff@yandex.ru), Павленко Андрей (pikachu_andrey@vk.com)
 * @brief File System Manager (Менеджер файловых систем)
 * @version 0.4.3
 * @date 2023-10-16
 * @copyright Copyright SayoriOS & NocturneOS Team (c) 2022-2026
*/

#include <io/logging.h>
#include <fs/fsm.h>
#include <lib/php/pathinfo.h>
#include "mem/vmm.h"

#include <lib/vector.h>

#include "generated/diskman.h"
#include "generated/diskman_commands.h"

static vector_t* registered_filesystems = NULL;
static vector_t* registered_disks = NULL;

static bool fsm_debug = false;

void fsm_init() {
    registered_filesystems = vector_new();
    registered_disks = vector_new();
}

int fsm_getIDbyName(const char* Name) {
	for (size_t i = 0; i < registered_filesystems->size; i++) {
        vector_result_t res = vector_get(registered_filesystems, i);
        FilesystemHandler* fsm = (FilesystemHandler*)res.element;

        // qemu_note("`%s` =? `%s`", fsm->Name, Name);

		if (strcmp(fsm->Name, Name) != 0) {
            continue;
        }

		return i;
	}

	return -1;
}

#ifndef RELEASE
void fsm_dump(FSM_FILE file) {
	qemu_log("  |--- Ready  : %d",file.Ready);
	qemu_log("  |--- Name   : %s",file.Name);
	qemu_log("  |--- Path   : %s",file.Path);
	qemu_log("  |--- Mode   : %d",file.Mode);
	qemu_log("  |--- Size   : %d",file.Size);
	qemu_log("  |--- Type   : %d",file.Type);
	qemu_log("  |--- Date   : %d",file.LastTime.year);
}
#endif

size_t fsm_read(int FIndex, const char* disk_name, const char* Name, size_t Offset, size_t Count, void* Buffer){
    if (fsm_debug) {
        qemu_log("[FSM] [READ] F:%d | D:`%s` | N:`%s` | O:%d | C:%d",FIndex,disk_name,Name,Offset,Count);
    }
    
    vector_result_t res = vector_get(registered_filesystems, FIndex);

	if (res.error) {
        return 0;
    }

    if (fsm_debug) {
        qemu_log("[FSM] [READ] GO TO DRIVER");
    }
    
    FilesystemHandler* fsm = (FilesystemHandler*)res.element;
	
    return fsm->Read(disk_name, Name, Offset, Count, Buffer);
}


int fsm_create(int FIndex, const char* disk_name, const char* Name, int Mode) {
    vector_result_t res = vector_get(registered_filesystems, FIndex);

	if (res.error) {
        return 0;
    }

    FilesystemHandler* fsm = (FilesystemHandler*)res.element;

	return fsm->Create(disk_name,Name,Mode);
}

int fsm_delete(int FIndex, const char* disk_name, const char* Name, int Mode) {
    vector_result_t res = vector_get(registered_filesystems, FIndex);

	if (res.error) {
		return 0;
    }

    FilesystemHandler* fsm = (FilesystemHandler*)res.element;

	return fsm->Delete(disk_name, Name, Mode);
}

size_t fsm_write(int FIndex, const char* disk_name, const char* Name, size_t Offset, size_t Count, const void* Buffer){
    vector_result_t res = vector_get(registered_filesystems, FIndex);
	
    if (res.error) {
		return 0;
    }

    FilesystemHandler* fsm = (FilesystemHandler*)res.element;

	return fsm->Write(disk_name,Name,Offset, Count, Buffer);
}

FSM_FILE fsm_info(int FIndex,const char* disk_name, const char* Name){
    if (fsm_debug) {
        qemu_log("[FSM] [INFO] FS ID: %d; Disk name: `%s`; Name: `%s`",FIndex,disk_name,Name);
    }

    vector_result_t res = vector_get(registered_filesystems, FIndex);

	if (res.error) {
        // if (fsm_debug) {
            qemu_log("[FSM] [INFO] READY == 0");
        // }
		return (FSM_FILE){};
	}
    
    FilesystemHandler* fsm = (FilesystemHandler*)res.element;
	
    return fsm->Info(disk_name,Name);
}

void fsm_dir(int FIndex, const char* disk_name, const char* Name, FSM_DIR* out) {
    if (fsm_debug) {
        qemu_log("[FSM] [DIR] F:%d | D:`%s` | N:%s",FIndex,disk_name,Name);
    }

    vector_result_t res = vector_get(registered_filesystems, FIndex);

	if (res.error) {
        if (fsm_debug) {
            qemu_log("[FSM] %d not ready", FIndex);
        }

		memset(out, 0, sizeof(FSM_DIR));
	}

    FilesystemHandler* fsm = (FilesystemHandler*)res.element;

    fsm->Dir(disk_name, Name, out);
}

void fsm_reg(const char* Name,fsm_cmd_read_t Read, fsm_cmd_write_t Write, fsm_cmd_info_t Info, fsm_cmd_create_t Create, fsm_cmd_delete_t Delete, fsm_cmd_dir_t Dir, fsm_cmd_label_t Label, fsm_cmd_detect_t Detect) {
    FilesystemHandler* fsm = kcalloc(sizeof(FilesystemHandler), 1);
    fsm->Ready = 1;
	fsm->Read = Read;
	fsm->Write = Write;
	fsm->Info = Info;
	fsm->Create = Create;
	fsm->Delete = Delete;
	fsm->Dir = Dir;
	fsm->Label = Label;
	fsm->Detect = Detect;

	fsm->Name = strdynamize(Name);

    vector_push_back(registered_filesystems, (size_t)fsm);

    qemu_ok("Registered filesystem: `%s`", Name);
}

const char* fsm_get_disk_filesystem(const char* disk_id) {
    for(size_t dx = 0; dx < registered_disks->size; dx++) {
        FSM_Mount* mount = (FSM_Mount*)vector_get(registered_disks, dx).element;

        if(strcmp(mount->diskman_disk_id, disk_id) == 0) {
            return mount->filesystem_name;
        }
    }

    return 0;
}

void fsm_detach_fs(const char* disk_id) {
    // Remove all mountpoints for `disk_id`
    for(size_t dx = 0; dx < registered_disks->size; dx++) {
        FSM_Mount* mount = (FSM_Mount*)vector_get(registered_disks, dx).element;

        if(strcmp(mount->diskman_disk_id, disk_id) == 0) {
            kfree(mount);
            vector_erase_nth(registered_disks, dx);

            dx--;
            continue;
        }
    }
}

void fsm_scan_for_filesystem(const char* disk_id) {
    // Remove all previous mountpoints
    for(size_t dx = 0; dx < registered_disks->size; dx++) {
        FSM_Mount* mount = (FSM_Mount*)vector_get(registered_disks, dx).element;

        if(strcmp(mount->diskman_disk_id, disk_id) == 0) {
            kfree(mount);
            vector_erase_nth(registered_disks, dx);

            dx--;
            continue;
        }
    }

    for(size_t f = 0; f < registered_filesystems->size; f++) {
        FilesystemHandler* fsm = (FilesystemHandler*)vector_get(registered_filesystems, f).element;

        qemu_note("[FSM] [DPM] Disk `%s`: Testing filesystem `%s`", disk_id, fsm->Name);

        int detect = fsm->Detect(disk_id);

        if (detect == 1) {
            FSM_Mount* mount = allocate_one(FSM_Mount);
            mount->diskman_disk_id = strdynamize(disk_id);
            mount->filesystem_name = strdynamize(fsm->Name);

            vector_push_back(registered_disks, (size_t)mount);

            qemu_note("Success: `%s` is on `%s`", fsm->Name, disk_id);

            break;
        }
    }
}

void fsm_scan_all_disks() {
    for(size_t i = 0; i < registered_disks->size; i++) {
        kfree((FSM_Mount*)vector_get(registered_disks, i).element);
    }

    vector_erase_all(registered_disks);

    size_t disk_count = diskman_get_registered_disk_count();

    for(size_t i = 0; i < disk_count; i++) {
        char* disk_id = diskman_get_disk_id_by_index(i);

        fsm_scan_for_filesystem(disk_id);

        kfree(disk_id);
    }
}

void fsm_dpm_update(const char* disk_id) {
    if(disk_id == NULL) {
        fsm_scan_all_disks();
    } else {
        fsm_scan_for_filesystem(disk_id);
    }
}

void fsm_file_close(FSM_FILE* file) {
    kfree(file->Name);
    kfree(file->Path);
}