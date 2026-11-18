#pragma once
#include <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <string.h>
#include <stdint.h>

class BypassChecker {
public:
    static bool IsAnogsPatched() {
        uintptr_t base = get_base("anogs");
        if (!base) return false;

        // Проверяем 4 патча NOP
        bool nop1 = (*(uint32_t*)(base + 0x1139DC) == 0xD503201F);
        bool nop2 = (*(uint32_t*)(base + 0x113A2C) == 0xD503201F);
        bool nop3 = (*(uint32_t*)(base + 0x113A7C) == 0xD503201F);
        bool nop4 = (*(uint32_t*)(base + 0x113ACC) == 0xD503201F);
        
        // Проверяем RET
        bool ret1 = (*(uint32_t*)(base + 0x0FF3DC) == 0xD65F03C0);

        return (nop1 && nop2 && nop3 && nop4 && ret1);
    }

private:
    static uintptr_t get_base(const char* module_name) {
        uint32_t count = _dyld_image_count();
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, module_name)) {
                return (uintptr_t)_dyld_get_image_header(i);
            }
        }
        return 0;
    }
};
