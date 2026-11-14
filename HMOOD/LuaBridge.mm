// LuaBridge.mm
// Мост между Objective-C++ и Lua 5.4
// HMOOD project

#import "LuaBridge.h"
#include "lua.hpp"

// ═════════════════════════════════════════════════════════════
// runLuaScript — выполняет Lua-скрипт из файла
// ═════════════════════════════════════════════════════════════
BOOL runLuaScript(NSString *scriptPath) {
    if (scriptPath == nil) {
        NSLog(@"[Lua] Путь к скрипту == nil");
        return NO;
    }

    // 1. Создаём состояние Lua
    lua_State *L = luaL_newstate();
    if (L == NULL) {
        NSLog(@"[Lua] Не удалось создать lua_State");
        return NO;
    }

    // 2. Открываем стандартные библиотеки (print, math, string, table, os, io и т.д.)
    luaL_openlibs(L);

    // 3. Загружаем и выполняем скрипт
    int status = luaL_dofile(L, [scriptPath UTF8String]);
    BOOL success = (status == LUA_OK);

    if (!success) {
        const char *err = lua_tostring(L, -1);
        NSLog(@"[Lua] Ошибка выполнения '%@': %s",
              scriptPath.lastPathComponent, err ? err : "(unknown)");
        lua_pop(L, 1);
    } else {
        NSLog(@"[Lua] Скрипт '%@' выполнен успешно", scriptPath.lastPathComponent);
    }

    // 4. Освобождаем состояние
    lua_close(L);
    return success;
}

// ═════════════════════════════════════════════════════════════
// runLuaString — выполняет Lua-код, переданный как C-строка
// ═════════════════════════════════════════════════════════════
BOOL runLuaString(const char *code) {
    if (code == NULL) {
        NSLog(@"[Lua] Код скрипта == NULL");
        return NO;
    }

    // 1. Создаём состояние Lua
    lua_State *L = luaL_newstate();
    if (L == NULL) {
        NSLog(@"[Lua] Не удалось создать lua_State");
        return NO;
    }

    // 2. Открываем стандартные библиотеки
    luaL_openlibs(L);

    // 3. Выполняем код из строки
    int status = luaL_dostring(L, code);
    BOOL success = (status == LUA_OK);

    if (!success) {
        const char *err = lua_tostring(L, -1);
        NSLog(@"[Lua] Ошибка выполнения встроенного скрипта: %s",
              err ? err : "(unknown)");
        lua_pop(L, 1);
    } else {
        NSLog(@"[Lua] Встроенный скрипт выполнен успешно");
    }

    // 4. Освобождаем состояние
    lua_close(L);
    return success;
}
