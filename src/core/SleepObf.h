#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
namespace SleepObf {
    bool Init();
    void ObfuscatedSleep(DWORD milliseconds);
}
