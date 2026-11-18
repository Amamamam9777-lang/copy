#pragma once
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

namespace Scan {

struct Hit { uintptr_t call, func; int id; const char *name; };

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

// шаг назад до пролога, ограниченно
static uintptr_t FuncStart(uintptr_t hit, uintptr_t lo) {
    for (int i = 1; i <= 128; i++) {
        uintptr_t a = hit - (uintptr_t)i * 4;
        if (a < lo) break;
        uint32_t w = *(uint32_t *)a;
        if (w == 0xD65F03C0 || w == 0xD503201F) {
            uint32_t nx = *(uint32_t *)(a + 4);
            if ((nx & 0xFFC07FFF) == 0xA9807BFD) return a + 4;  // stp x29,x30,[sp,#-n]!
            if ((nx & 0xFFC003FF) == 0xD10003FF) return a + 4;  // sub sp,sp,#n
            if (nx == 0xD503237F)                return a + 4;  // pacibsp
        }
    }
    return 0;
}

// 1) anogs: поиск по номерам строк
static void Anogs(FILE *f) {
    static const struct { int id; const char *name; } kT[] = {
        {9231,  "root: jailbroken_detector2"}, {12085, "root: dopamine_jb"},
        {12245, "scan: ScanRoot"},             {12259, "scan: ScanCert"},
        {51815, "report: Version"},            {31433, "ioctl: EnableGameReport"},
        {30107, "anti: frida"},
    };

    uintptr_t base = ImageBase("anogs");
    if (!base) { fprintf(f, "anogs: not loaded\n"); return; }

    uintptr_t lo = 0, hi = 0;
    if (!TextRange(base, &lo, &hi)) { fprintf(f, "anogs: no __TEXT\n"); return; }

    fprintf(f, "anogs base %p  __TEXT %p..%p\n", (void *)base, (void *)lo, (void *)hi);

    for (auto &t : kT) {
        int found = 0;
        for (uintptr_t a = lo; a + 12 < hi; a += 4) {
            uint32_t w = *(uint32_t *)a;
            if ((w & 0xFFE0001F) != 0x52800000) continue;      // не movz wN
            if ((int)((w >> 5) & 0xFFFF) != t.id) continue;

            uint32_t n1 = *(uint32_t *)(a + 4);
            uint32_t n2 = *(uint32_t *)(a + 8);
            bool bl = (n1 & 0xFC000000) == 0x94000000 ||
                      (n2 & 0xFC000000) == 0x94000000;
            if (!bl) continue;

            uintptr_t fn = FuncStart(a, lo);
            fprintf(f, "  %-32s call %06lx func %s\n", t.name, a - base,
                    fn ? "найден" : "не найден");
            if (fn) fprintf(f, "      func_off = %06lx\n", fn - base);
            found++;
            if (found > 4) break;
        }
        if (!found) fprintf(f, "  %-32s НЕ НАЙДЕНО\n", t.name);
    }
}

// 2) игра: поиск ссылок adrp+add на литерал
static void GameStr(FILE *f, const char *needle) {
    uintptr_t base = ImageBase("ShadowTrackerExtra");
    if (!base) { fprintf(f, "game: not loaded\n"); return; }

    uintptr_t lo = 0, hi = 0;
    if (!TextRange(base, &lo, &hi)) { fprintf(f, "game: no __TEXT\n"); return; }

    // литерал ищем по всему __TEXT (включая __cstring)
    uintptr_t lit = 0;
    size_t n = strlen(needle);
    for (uintptr_t a = lo; a + n < hi; a++)
        if (!memcmp((void *)a, needle, n)) { lit = a; break; }
    if (!lit) { fprintf(f, "  %-20s литерал не найден\n", needle); return; }

    fprintf(f, "  %-20s литерал %06lx\n", needle, lit - base);

    for (uintptr_t a = lo; a + 8 < hi; a += 4) {
        uint32_t w1 = *(uint32_t *)a;
        if ((w1 & 0x9F00001F) != 0x90000000) continue;         // adrp
        uint32_t w2 = *(uint32_t *)(a + 4);
        if ((w2 & 0xFFC00000) != 0x91000000) continue;         // add imm
        if (((w1 ^ w2) & 0x1F) != 0) continue;                 // один регистр

        int64_t immlo = (w1 >> 29) & 3;
        int64_t immhi = (w1 >> 5) & 0x7FFFF;
        int64_t imm = ((immhi << 2) | immlo);
        if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1);
        uintptr_t target = (a & ~0xFFFULL) + (uintptr_t)(imm << 12);
        target += (w2 >> 10) & 0xFFF;

        if (target != lit) continue;
        uintptr_t fn = FuncStart(a, lo);
        fprintf(f, "      ref %06lx func %s\n", a - base, fn ? "найден" : "не найден");
        if (fn) fprintf(f, "          func_off = %06lx\n", fn - base);
    }
}

static void Run() {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/bypass_scan.txt"];
    FILE *f = fopen(p.UTF8String, "w");
    if (!f) return;

    fprintf(f, "=== anogs ===\n");
    Anogs(f);

    fprintf(f, "\n=== game strings ===\n");
    static const char *kS[] = { "shootcheck", "WeaponAntiCheatComp",
                                "RealtimeMoveSpeedCheck", "AntiCheatDetailData" };
    for (const char *s : kS) GameStr(f, s);

    fclose(f);
    NSLog(@"[scan] -> %@", p);
}

} 