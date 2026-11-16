#pragma once

#include <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <libkern/OSCacheControl.h>
#include <string.h>
#include <stdio.h>

// Базовые инструкции ARM64
#define ARM64_NOP 0xD503201F
#define ARM64_RET 0xD65F03C0

class AnogsBypass {
public:
    static void Apply() {
        // Ищем базовый адрес libanogs.dylib
        uintptr_t base = get_anogs_base();
        if (!base) {
            NSLog(@"[AnogsBypass] libanogs.dylib not found in memory!");
            return;
        }
        
        NSLog(@"[AnogsBypass] libanogs.dylib base: 0x%lx", base);

        // --- ПАТЧ 1: Отключаем логирование ошибок потоков (ms_scan, ms_send) ---
        // Заменяем TBNZ на NOP, чтобы обойти блок с ошибкой
        patch_memory(base + 0x1139DC, ARM64_NOP); // Case 15: fc_thread
        patch_memory(base + 0x113A2C, ARM64_NOP); // Case 16: ms_scan_start
        patch_memory(base + 0x113A7C, ARM64_NOP); // Case 17: ms_scan
        patch_memory(base + 0x113ACC, ARM64_NOP); // Case 18: ms_send_start

        // --- ПАТЧ 2: Отключаем отправку отчетов на сервер ---
        // Заменяем начало функции сбора данных на RET
        patch_memory(base + 0x0FF3DC, ARM64_RET); // _AnoSDKGetReportData

        NSLog(@"[AnogsBypass] Memory patches applied successfully.");
    }

private:
    // Функция поиска базы библиотеки в памяти
    static uintptr_t get_anogs_base() {
        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "anogs")) {
                return (uintptr_t)_dyld_get_image_header(i);
            }
        }
        return 0;
    }

    // Безопасный патчинг памяти на iOS (Copy-on-Write + RWX)
    static bool patch_memory(uintptr_t address, uint32_t instruction) {
        if (!address) return false;

        kern_return_t err;
        mach_port_t port = mach_task_self();
        vm_size_t page_size = PAGE_SIZE;
        
        uintptr_t page_start = address & ~(page_size - 1);

        // Разрешаем Чтение, Запись и Исполнение (RWX) + Copy-on-Write
        err = vm_protect(port, (mach_vm_address_t)page_start, page_size, false, 
                         VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE | VM_PROT_COPY);
        if (err != KERN_SUCCESS) {
            NSLog(@"[AnogsBypass] vm_protect (rwx) failed: %d", err);
            return false;
        }

        // Записываем инструкцию
        err = vm_write(port, (mach_vm_address_t)address, (vm_offset_t)&instruction, sizeof(instruction));
        if (err != KERN_SUCCESS) {
            NSLog(@"[AnogsBypass] vm_write failed: %d", err);
            return false;
        }

        // КРИТИЧЕСКИ ВАЖНО: Сбрасываем кэш инструкций процессора!
        sys_icache_invalidate((void*)address, sizeof(instruction));

        return true;
    }
};