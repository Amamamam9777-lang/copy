// LuaBridge.h
#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

// Запускает Lua-скрипт по указанному пути.
// Возвращает YES при успехе, NO при ошибке (ошибка пишется в консоль).
BOOL runLuaScript(NSString *scriptPath);

#ifdef __cplusplus
}
#endif
