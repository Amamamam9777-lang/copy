// LuaBridge.mm
#import "LuaBridge.h"
#include "lua.hpp"
#include <mach-o/dyld.h>
#include <string.h>

// ═════════════════════════════════════════════════════════════
// 1. ФУНКЦИИ СКАНЕРА ПАМЯТИ (Доступны из Lua)
// ═════════════════════════════════════════════════════════════

// Получить базовый адрес модуля по его имени (например, "anogs" или "UnityFramework")
static int lua_get_module_base(lua_State *L) {
    const char *module_name = luaL_checkstring(L, 1);
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, module_name)) {
            uintptr_t base = (uintptr_t)_dyld_get_image_header(i);
            lua_pushinteger(L, base); // Возвращаем адрес в Lua
            return 1;
        }
    }
    lua_pushinteger(L, 0); // Если не нашли
    return 1;
}

// Искать строку в памяти модуля и вернуть её смещение (Offset)
static int lua_find_string_in_module(lua_State *L) {
    const char *module_name = luaL_checkstring(L, 1);
    const char *search_str = luaL_checkstring(L, 2);
    
    uintptr_t base = 0;
    uintptr_t size = 0;
    
    // Ищем нужный модуль среди загруженных библиотек
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, module_name)) {
            const struct mach_header_64 *header = _dyld_get_image_header(i);
            base = (uintptr_t)header;
            
            // Получаем размер модуля через load commands (сегмент __TEXT)
            const struct load_command *cmd = (const struct load_command *)(header + 1);
            for (uint32_t j = 0; j < header->ncmds; j++) {
                if (cmd->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
                    if (strcmp(seg->segname, "__TEXT") == 0) {
                        size = seg->vmsize;
                        break;
                    }
                }
                cmd = (const struct load_command *)((uintptr_t)cmd + cmd->cmdsize);
            }
            break;
        }
    }
    
    if (base == 0 || size == 0) {
        lua_pushinteger(L, 0);
        return 1;
    }
    
    // Ищем строку в памяти
    const char *start = (const char *)base;
    const char *end = start + size;
    const char *found_ptr = NULL;
    size_t search_len = strlen(search_str);
    
    for (const char *p = start; p < end - search_len; p++) {
        if (memcmp(p, search_str, search_len) == 0) {
            found_ptr = p;
            break;
        }
    }
    
    if (found_ptr) {
        // Возвращаем СМЕЩЕНИЕ (Offset) от базы модуля
        uintptr_t offset = (uintptr_t)found_ptr - base;
        lua_pushinteger(L, offset);
    } else {
        lua_pushinteger(L, 0);
    }
    return 1;
}

// ═════════════════════════════════════════════════════════════
// 2. ФУНКЦИЯ ЗАПИСИ ЛОГОВ В DOCUMENTS
// ═════════════════════════════════════════════════════════════

static int lua_write_log(lua_State *L) {
    const char *msg = luaL_checkstring(L, 1);
    if (!msg) return 0;
    
    // Получаем путь к папке Documents игры
    NSString *documentsDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *filePath = [documentsDirectory stringByAppendingPathComponent:@"HMOOD_Lua_Log.txt"];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:filePath]) {
        [fm createFileAtPath:filePath contents:nil attributes:nil];
    }
    
    // Дописываем текст в конец файла
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:filePath];
    if (fileHandle) {
        [fileHandle seekToEndOfFile];
        NSString *line = [NSString stringWithFormat:@"%@\n", [NSString stringWithUTF8String:msg]];
        [fileHandle writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fileHandle closeFile];
    }
    return 0;
}

// ═════════════════════════════════════════════════════════════
// 3. РЕГИСТРАЦИЯ ВСЕХ ФУНКЦИЙ В LUA
// ═════════════════════════════════════════════════════════════

void register_lua_memory_functions(lua_State *L) {
    lua_register(L, "get_module_base", lua_get_module_base);
    lua_register(L, "find_string_in_module", lua_find_string_in_module);
    lua_register(L, "write_log", lua_write_log);
}

// ═════════════════════════════════════════════════════════════
// 4. ОСНОВНЫЕ ФУНКЦИИ ЗАПУСКА
// ═════════════════════════════════════════════════════════════

BOOL runLuaScript(NSString *scriptPath) {
    if (scriptPath == nil) {
        NSLog(@"[Lua] Путь к скрипту == nil");
        return NO;
    }

    lua_State *L = luaL_newstate();
    if (L == NULL) {
        NSLog(@"[Lua] Не удалось создать lua_State");
        return NO;
    }

    luaL_openlibs(L);
    register_lua_memory_functions(L); // <--- ВАЖНО: Регистрируем функции

    int status = luaL_dofile(L, [scriptPath UTF8String]);
    BOOL success = (status == LUA_OK);

    if (!success) {
        const char *err = lua_tostring(L, -1);
        NSLog(@"[Lua] Ошибка: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    }
    lua_close(L);
    return success;
}

BOOL runLuaString(const char* code) {
    if (code == NULL) {
        NSLog(@"[Lua] Код скрипта == NULL");
        return NO;
    }

    lua_State *L = luaL_newstate();
    if (L == NULL) {
        NSLog(@"[Lua] Не удалось создать lua_State");
        return NO;
    }

    luaL_openlibs(L);
    register_lua_memory_functions(L); // <--- ВАЖНО: Регистрируем функции

    int status = luaL_dostring(L, code);
    BOOL success = (status == LUA_OK);

    if (!success) {
        const char *err = lua_tostring(L, -1);
        NSLog(@"[Lua] Ошибка: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    }
    
    lua_close(L);
    return success;
}