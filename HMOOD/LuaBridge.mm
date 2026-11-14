// LuaBridge.mm
#import "LuaBridge.h"
#include "lua.hpp"

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
    int status = luaL_dofile(L, [scriptPath UTF8String]);
    BOOL success = (status == LUA_OK);
    if (!success) {
        const char *err = lua_tostring(L, -1);
        NSLog(@"[Lua] Ошибка: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    } else {
        NSLog(@"[Lua] Скрипт '%@' выполнен успешно", scriptPath.lastPathComponent);
    }
    lua_close(L);
    return success;
}
