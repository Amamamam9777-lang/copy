#pragma once
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#import <Foundation/Foundation.h>

namespace Scan {

static const size_t kCap = 200u * 1024 * 1024;

static bool TextRange(uintptr_t base, uintptr_t *lo, uintptr_t *hi) {
    auto *mh = (mach_header_64 *)base;
    if (mh->magic != MH_MAGIC_64) return false;
    uint8_t *p = (uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        auto *lc = (load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            auto *sg = (segment_command_64 *)lc;
            if (!strcmp(sg->segname, "__TEXT")) {
                *lo = base + sg->vmaddr;
                *hi = *lo + sg->vmsize;
                return sg->vmsize > 0x1000;
            }
        }
        p += lc->cmdsize;
    }
    return false;
}

static uintptr_t ImageBase(const char *needle) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        if (!n) continue;
        const char *b = strrchr(n, '/'); b = b ? b + 1 : n;
        if (!strncmp(b, needle, strlen(needle)))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

// true — страница читаема; иначе *next = конец региона
static bool PageReadable(uintptr_t a, uintptr_t *next) {
    vm_address_t q = a & ~(uintptr_t)(vm_page_size - 1);
    vm_size_t s = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t c = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &q, &s, VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info, &c, &obj);
    if (obj) mach_port_deallocate(mach_task_self(), obj);
    if (kr != KERN_SUCCESS) { *next = q + vm_page_size; return false; }
    *next = q + s;
    return (info.protection & VM_PROT_READ) != 0;
}

static uintptr_t PageEnd(uintptr_t a) {
    return (a & ~(uintptr_t)(vm_page_size - 1)) + vm_page_size;
}

static uintptr_t FuncStart(uintptr_t hit, uintptr_t lo) {
    for (int i = 1; i <= 128; i++) {
        if (hit < (uintptr_t)i * 4) break;
        uintptr_t a = hit - (uintptr_t)i * 4;
        if (a < lo) break;
        uint32_t w = *(uint32_t *)a;
        if (w == 0xD65F03C0 || w == 0xD503201F) {
            uint32_t nx = *(uint32_t *)(a + 4);
            if ((nx & 0xFFC07FFF) == 0xA9807BFD) return a + 4;
            if ((nx & 0xFFC003FF) == 0xD10003FF) return a + 4;
            if (nx == 0xD503237F)                return a + 4;
        }
    }
    return 0;
}

// ===================== anogs =====================
static void Anogs(FILE *f) {
    static const struct { int id; const char *name; } kT[] = {
        {9231,  "root: jailbroken_detector2"},
        {2400,  "frida"},
        {27629, "port 27042"},
        {27645, "auth reject"},
        {17206, "verdict white_mode2"},
        {36707, "force_anti_debugger"},
        {12381, "scan_loop2"},
        {12245, "ScanRoot"},
        {12259, "ScanCert"},
        {27909, "frida-server path"},
        {51815, "report Version"},
        {31433, "ioctl EnableGameReport"},
    };

    uintptr_t base = ImageBase("anogs");
    if (!base) { fprintf(f, "anogs: not loaded\n"); return; }

    uintptr_t lo = 0, hi = 0;
    if (!TextRange(base, &lo, &hi)) { fprintf(f, "anogs: no __TEXT\n"); return; }

    fprintf(f, "anogs base %p  __TEXT %p..%p\n\n", (void *)base, (void *)lo, (void *)hi);

    for (auto &t : kT) {
        int found = 0;
        for (uintptr_t a = lo; a + 12 < hi; ) {
            uintptr_t next = 0;
            if (!PageReadable(a, &next)) { a = next; continue; }
            uintptr_t pe = PageEnd(a);

            for (; a + 12 < hi && a < pe; a += 4) {
                uint32_t w = *(uint32_t *)a;
                if ((w & 0xFFE0001F) != 0x52800000) continue;
                if ((int)((w >> 5) & 0xFFFF) != t.id) continue;

                uint32_t n1 = *(uint32_t *)(a + 4);
                uint32_t n2 = *(uint32_t *)(a + 8);
                if ((n1 & 0xFC000000) != 0x94000000 &&
                    (n2 & 0xFC000000) != 0x94000000) continue;

                uintptr_t fn = FuncStart(a, lo);
                fprintf(f, "%-30s call %06lx  %s\n", t.name, a - base,
                        fn ? "func:" : "func not found");
                if (fn) fprintf(f, "    func_off = %06lx\n", fn - base);
                found++;
                if (found > 3) break;
            }
            if (found > 3) break;
        }
        if (!found) fprintf(f, "%-30s NOT FOUND\n", t.name);
    }
}

// ===================== game =====================
static void GameStr(FILE *f, const char *needle) {
    uintptr_t base = ImageBase("ShadowTrackerExtra");
    if (!base) { fprintf(f, "game: not loaded\n"); return; }

    uintptr_t lo = 0, hi = 0;
    if (!TextRange(base, &lo, &hi)) { fprintf(f, "game: no __TEXT\n"); return; }

    size_t n = strlen(needle);
    uintptr_t lit = 0;
    size_t scanned = 0;

    for (uintptr_t a = lo; a + n < hi && scanned < kCap; ) {
        uintptr_t next = 0;
        if (!PageReadable(a, &next)) { a = next; continue; }
        uintptr_t pe = PageEnd(a);

        for (; a + n < hi && a < pe && scanned < kCap; a++, scanned++)
            if (!memcmp((void *)a, needle, n)) { lit = a; break; }
        if (lit) break;
    }

    if (!lit) { fprintf(f, "  %-22s literal NOT FOUND\n", needle); return; }
    fprintf(f, "  %-22s literal %06lx\n", needle, lit - base);

    for (uintptr_t a = lo; a + 8 < hi; ) {
        uintptr_t next = 0;
        if (!PageReadable(a, &next)) { a = next; continue; }
        uintptr_t pe = PageEnd(a);

        for (; a + 8 < hi && a < pe; a += 4) {
            uint32_t w1 = *(uint32_t *)a;
            if ((w1 & 0x9F00001F) != 0x90000000) continue;
            uint32_t w2 = *(uint32_t *)(a + 4);
            if ((w2 & 0xFFC00000) != 0x91000000) continue;
            if (((w1 ^ w2) & 0x1F) != 0) continue;

            int64_t immlo = (w1 >> 29) & 3;
            int64_t immhi = (w1 >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1);
            uintptr_t tgt = (a & ~0xFFFULL) + (uintptr_t)(imm << 12) + ((w2 >> 10) & 0xFFF);
            if (tgt != lit) continue;

            uintptr_t fn = FuncStart(a, lo);
            fprintf(f, "      ref %06lx  %s\n", a - base, fn ? "func:" : "func not found");
            if (fn) fprintf(f, "          func_off = %06lx\n", fn - base);
        }
    }
}

static void Run() {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/bypass_scan.txt"];
    FILE *f = fopen(p.UTF8String, "w");
    if (!f) return;

    fprintf(f, "=== anogs ===\n");
    Anogs(f);

    fprintf(f, "\n=== game ===\n");
    static const char *kS[] = { "shootcheck", "WeaponAntiCheatComp",
                                "RealtimeMoveSpeedCheck", "AntiCheatDetailData" };
    for (const char *s : kS) GameStr(f, s);

    fclose(f);
    NSLog(@"[scan] done -> %@", p);
}

} 