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

    static const uintptr_t kTargets[] = {
        0xFF3DC, 0x3DE48, 0xA6D8, 0x8CF3C, 0x7A0C8, 0x3D140, 0x12FEC,
        0x13148, 0x134D8, 0x9834, 0x13238, 0x13284, 0x14D88, 0x13BB0, 0x9DB0
    };

    int ok = 0;
    for (uintptr_t off : kTargets)
        if (*(uint32_t *)(base + off) == 0x52800000) ok++;

    return ok == (int)(sizeof(kTargets) / sizeof(kTargets[0]));
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
