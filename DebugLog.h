#pragma once
#include <windows.h>
#include <stdio.h>
#ifdef SOFIA_DEBUG
namespace DebugLog {
    inline FILE* g_logFile = nullptr;
    inline void Init() {
        if (g_logFile) return;
        g_logFile = fopen("sofia_debug.log", "a");
        if (g_logFile) {
            fprintf(g_logFile, "=== Sofia Debug Log ===\n");
            fflush(g_logFile);
        }
    }
    inline void Log(const char* fmt, ...) {
        if (!g_logFile) Init();
        if (!g_logFile) return;
        va_list args;
        va_start(args, fmt);
        vfprintf(g_logFile, fmt, args);
        va_end(args);
        fprintf(g_logFile, "\n");
        fflush(g_logFile); 
    }
    inline void Close() {
        if (g_logFile) { fclose(g_logFile); g_logFile = nullptr; }
    }
}
#define SLOG(fmt, ...) DebugLog::Log(fmt, ##__VA_ARGS__)
#define SLOG_INIT()    DebugLog::Init()
#define SLOG_CLOSE()   DebugLog::Close()
#else
#define SLOG(fmt, ...) ((void)0)
#define SLOG_INIT()    ((void)0)
#define SLOG_CLOSE()   ((void)0)
#endif
