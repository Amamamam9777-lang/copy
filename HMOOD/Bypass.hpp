#pragma once
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>

// --- внешние зависимости проекта ---
extern bool WriteAddr(void *addr, void *value, size_t size);
extern void hook(uint64_t address, void *hookfn, void **orig);

namespace Bypass {

// ===================== константы =====================
inline constexpr uint32_t kNop     = 0xD503201F;
inline constexpr uint32_t kRet     = 0xD65F03C0;
inline constexpr uint32_t kMovW0_0 = 0x52800000;   // mov w0, #0
inline constexpr uint32_t kMovW0_1 = 0x52800020;   // mov w0, #1
inline constexpr uint32_t kStub    = 0x58000050;   // ldr x16, #8 — начало стаба hook()

// запасной офсет геттера, если dlsym не найдёт экспорт
inline constexpr uintptr_t kReportFallback = 0xFF3DC;

// имя своего образа для фильтра модулей
inline const char *g_self = "HideFunsion";
inline void SetSelfName(const char *n) { if (n) g_self = n; }

enum Status : int { NotLoaded = 0, Unpatched, Partial, Patched, WrongVersion };

// ===================== состояние =====================
inline uintptr_t g_base      = 0;
inline Status    g_status    = NotLoaded;
inline bool      g_applied   = false;
inline bool      g_installed = false;

struct Patch { uintptr_t off; uint32_t want; int wide; };

inline const Patch kReport = { kReportFallback, kMovW0_0, 1 };

// четыре сканера; wide=0 -> NOP либо RET, решается по прологу
inline const uintptr_t kScanOffs[4] = { 0x1139DC, 0x113A2C, 0x113A7C, 0x113ACC };

// ===================== утилиты =====================
inline bool IsPrologue(uint32_t ins) {
    if ((ins & 0xFFC07FFF) == 0xA9807BFD) return true;  // stp x29,x30,[sp,#-n]!
    if ((ins & 0xFFC003FF) == 0xD10003FF) return true;  // sub sp,sp,#n
    if (ins == 0xD503237F)                return true;  // pacibsp
    return false;
}

inline bool InText(uintptr_t base, uintptr_t off) {
    if (!base) return false;
    auto *mh = (mach_header_64 *)base;
    if (mh->magic != MH_MAGIC_64) return false;
    uint8_t *p = (uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        auto *lc = (load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            auto *sg = (segment_command_64 *)lc;
            if (!strcmp(sg->segname, "__TEXT")) return off + 8 < sg->vmsize;
        }
        p += lc->cmdsize;
    }
    return false;
}

inline uintptr_t Find() {
    if (g_base) return g_base;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *n = _dyld_get_image_name(i);
        if (!n) continue;
        const char *b = strrchr(n, '/');
        b = b ? b + 1 : n;
        if (!strncmp(b, "anogs", 5)) {
            g_base = (uintptr_t)_dyld_get_image_header(i);
            break;
        }
    }
    return g_base;
}

// адрес экспорта, только если он реально внутри __TEXT нашего образа
inline uintptr_t Export(const char *name) {
    uintptr_t b = Find();
    if (!b || !name) return 0;
    uintptr_t a = (uintptr_t)dlsym(RTLD_DEFAULT, name);
    if (!a || a < b || !InText(b, a - b)) return 0;
    return a;
}

inline bool Already(uint32_t cur) {
    return cur == kNop || cur == kRet || cur == kMovW0_0 || cur == kMovW0_1;
}

inline bool Hooked(uintptr_t addr) {
    return addr && *(uint32_t *)addr == kStub;
}

inline void Put(uintptr_t addr, uint32_t v) {
    if (!WriteAddr((void *)addr, &v, 4))
        NSLog(@"[bypass] write failed @ %p", (void *)addr);
}

inline void ApplyOne(uintptr_t addr, uint32_t want, int wide) {
    Put(addr, want);
    if (wide) Put(addr + 4, kRet);
}

// ===================== хуки =====================
inline void InstallInner(uintptr_t base);   // forward

inline int (*o_AEA24)(void *, const char *, int, int);
inline int h_AEA24(void *kv, const char *k, int d, int f) {
    if (k && strstr(k, "mt_sar2")) return 1;   // сессию не глушим
    return 0;
}

inline int (*o_13BB0)(void *);
inline int h_13BB0(void *a) { return 0; }

inline int (*o_14D88)(int, uint8_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
inline int h_14D88(int a, uint8_t *b, uint64_t c, uint64_t d,
                   uint64_t e, uint64_t f, uint64_t g) {
    if (b) memset(b, 0, 48);
    return 0;
}

inline int (*o_98158)(void *, unsigned, unsigned, unsigned, int, int, void *);
inline int h_98158(void *h, unsigned a, unsigned b, unsigned c, int d, int e, void *p) {
    const char *path = (const char *)p;
    if (!o_98158) return 0;
    if (path && strstr(path, g_self)) return 0;      // свой образ не отдаём
    return o_98158(h, a, b, c, d, e, p);
}

inline int (*o_75D0)(uint8_t *); inline int h_75D0(uint8_t *) { return 0; }
inline int (*o_781C)(uint8_t *); inline int h_781C(uint8_t *) { return 0; }

inline int (*o_8C9C)(char *, uint64_t);
inline int h_8C9C(char *b, uint64_t n) { if (b && n) b[0] = 0; return 1; }

inline int (*o_9834)(int);           inline int h_9834(int) { return 0; }
inline int (*o_12FEC)(void *, int);  inline int h_12FEC(void *, int) { return 0; }
inline int (*o_13148)(void *, int);  inline int h_13148(void *, int) { return 0; }
inline int (*o_13238)(void *, int);  inline int h_13238(void *, int) { return 0; }

// анкор инициализации SDK
inline int (*o_Init)(void *);
inline int (*o_InitEx)(void *, void *);

inline int h_Init(void *a) {
    if (!g_applied) Apply();
    InstallInner(Find());
    return o_Init ? o_Init(a) : 0;
}
inline int h_InitEx(void *a, void *b) {
    if (!g_applied) Apply();
    InstallInner(Find());
    return o_InitEx ? o_InitEx(a, b) : 0;
}

struct Hook { uintptr_t off; void *fn; void **orig; const char *name; };

inline const Hook kHooks[] = {
    { 0xAEA24, (void *)h_AEA24, (void **)&o_AEA24, "gate"      },
    { 0x13BB0, (void *)h_13BB0, (void **)&o_13BB0, "verdict"   },
    { 0x14D88, (void *)h_14D88, (void **)&o_14D88, "cdhash"    },
    { 0x98158, (void *)h_98158, (void **)&o_98158, "modfilter" },
    { 0x75D0,  (void *)h_75D0,  (void **)&o_75D0,  "bitmask"   },
    { 0x781C,  (void *)h_781C,  (void **)&o_781C,  "bitmask2"  },
    { 0x8C9C,  (void *)h_8C9C,  (void **)&o_8C9C,  "root"      },
    { 0x9834,  (void *)h_9834,  (void **)&o_9834,  "portscan"  },
    { 0x12FEC, (void *)h_12FEC, (void **)&o_12FEC, "cheatapp"  },
    { 0x13148, (void *)h_13148, (void **)&o_13148, "cheatdir"  },
    { 0x13238, (void *)h_13238, (void **)&o_13238, "cheatport" },
};

inline constexpr int kHookCount = (int)(sizeof(kHooks) / sizeof(kHooks[0]));

inline void InstallInner(uintptr_t base) {
    if (!base || g_installed) return;
    g_installed = true;
    for (auto &h : kHooks)
        if (InText(base, h.off)) hook(base + h.off, h.fn, h.orig);
}

// ===================== применение =====================
inline Status Apply() {
    if (g_applied) return g_status;

    uintptr_t b = Find();
    if (!b) return g_status = NotLoaded;
    if (!InText(b, kReportFallback)) return g_status = WrongVersion;

    // ставим сразу: h_Init может прийти в процессе и вызвать Apply повторно
    g_applied = true;

    // 1. слой доставки — геттер по символу, иначе по офсету
    uintptr_t rep = Export("AnoSDKGetReportData");
    if (!rep) rep = b + kReportFallback;
    if (InText(b, rep - b)) {
        uint32_t cur = *(uint32_t *)rep;
        if (!Already(cur)) ApplyOne(rep, kMovW0_0, 1);
    }

    // 2. четыре сканера
    int done = 0;
    const int total = 4;
    for (uintptr_t off : kScanOffs) {
        if (!InText(b, off)) continue;
        uint32_t *p = (uint32_t *)(b + off);
        if (!Already(*p)) {
            uint32_t w = IsPrologue(*p) ? kRet : kNop;
            Put((uintptr_t)p, w);
        }
        if (*p == kRet || *p == kNop || *p == kMovW0_1) done++;
    }

    // 3. анкоры по символам
    uintptr_t ini = Export("AnoSDKInit");
    if (ini) hook(ini, (void *)h_Init, (void **)&o_Init);
    uintptr_t inx = Export("AnoSDKInitEx");
    if (inx) hook(inx, (void *)h_InitEx, (void **)&o_InitEx);

    // 4. остальной хук-сет
    InstallInner(b);

    return g_status = (done == total) ? Patched : Partial;
}

// ===================== проверка =====================
inline Status Verify() {
    uintptr_t b = Find();
    if (!b) return g_status = NotLoaded;
    if (!InText(b, kReportFallback)) return g_status = WrongVersion;

    // слой доставки
    uintptr_t rep = Export("AnoSDKGetReportData");
    if (!rep) rep = b + kReportFallback;
    uint32_t cur = *(uint32_t *)rep;
    if (cur != kMovW0_0 && cur != kMovW0_1 && cur != kRet) return g_status = Unpatched;

    // сканеры
    int done = 0;
    for (uintptr_t off : kScanOffs) {
        if (!InText(b, off)) continue;
        uint32_t v = *(uint32_t *)(b + off);
        if (v == kRet || v == kNop || v == kMovW0_1) done++;
    }

    // хуки
    int hooked = 0;
    for (auto &h : kHooks)
        if (InText(b, h.off) && Hooked(b + h.off)) hooked++;
    if (Hooked(Export("AnoSDKInit"))) hooked++;

    if (done < 4 || hooked < kHookCount) return g_status = Partial;
    return g_status = Patched;
}

inline const char *Label() {
    switch (g_status) {
        case NotLoaded:    return "anogs: not loaded";
        case Unpatched:    return "anogs: UNPATCHED";
        case Partial:      return "anogs: PARTIAL";
        case Patched:      return "anogs: patched";
        case WrongVersion: return "anogs: VERSION MISMATCH";
    }
    return "?";
}

// ===================== запуск =====================
inline void *Worker(void *) {
    while (!Find()) usleep(10 * 1000);
    Apply();
    return nullptr;
}

inline void Start() {
    pthread_t th;
    if (pthread_create(&th, nullptr, Worker, nullptr) == 0) pthread_detach(th);
}

} 