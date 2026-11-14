// LuaBridge.mm
#import "LuaBridge.h"
#include "lua.hpp"   // Заголовок из папки Lua (у вас должен быть скопирован вместе с остальными)

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

    // 2. Открываем стандартные библиотеки
    luaL_openlibs(L);

    // 3. Загружаем и выполняем скрипт
    int status = luaL_dofile(L, [scriptPath UTF8String]);

    BOOL success = (status == LUA_OK);
    if (!success) {
        const char *err = lua_tostring(L, -1);
        NSLog(@"[Lua] Ошибка: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    } else {
        NSLog(@"[Lua] Скрипт '%@' выполнен успешно", scriptPath.lastPathComponent);
    }

    // 4. Закрываем состояние
    lua_close(L);
    return success;
}
