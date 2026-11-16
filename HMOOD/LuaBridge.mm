// LuaBridge.mm
#import "LuaBridge.h"
#include "lua.hpp"

// Функция записи логов в Documents (безопасная)
static int lua_write_log(lua_State *L) {
    const char *msg = luaL_checkstring(L, 1);
    if (!msg) return 0;
    
    NSString *documentsDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *filePath = [documentsDirectory stringByAppendingPathComponent:@"HMOOD_Lua_Log.txt"];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:filePath]) {
        [fm createFileAtPath:filePath contents:nil attributes:nil];
    }
    
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:filePath];
    if (fileHandle) {
        [fileHandle seekToEndOfFile];
        NSString *line = [NSString stringWithFormat:@"%@\n", [NSString stringWithUTF8String:msg]];
        [fileHandle writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fileHandle closeFile];
    }
    return 0;
}

// Регистрируем только безопасный логгер
void register_lua_memory_functions(lua_State *L) {
    lua_register(L, "write_log", lua_write_log);
}

BOOL runLuaScript(NSString *scriptPath) {
    if (scriptPath == nil) return NO;
    lua_State *L = luaL_newstate();
    if (L == NULL) return NO;
    
    luaL_openlibs(L);
    register_lua_memory_functions(L);
    
    int status = luaL_dofile(L, [scriptPath UTF8String]);
    if (status != LUA_OK) {
        NSLog(@"[Lua] Ошибка: %s", lua_tostring(L, -1));
    }
    lua_close(L);
    return status == LUA_OK;
}

BOOL runLuaString(const char* code) {
    if (code == NULL) return NO;
    lua_State *L = luaL_newstate();
    if (L == NULL) return NO;
    
    luaL_openlibs(L);
    register_lua_memory_functions(L);
    
    int status = luaL_dostring(L, code);
    if (status != LUA_OK) {
        NSLog(@"[Lua] Ошибка: %s", lua_tostring(L, -1));
    }
    lua_close(L);
    return status == LUA_OK;
}