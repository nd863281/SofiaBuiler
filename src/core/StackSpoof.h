#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
namespace StackSpoof {
    bool Init();
    LPVOID GetTrampoline();
    void SetTarget(LPVOID func);

    // BUG-2 FIX: Spinlock to prevent race condition between SetTarget + Call
    inline volatile LONG g_spoofLock = 0;
    static __forceinline void AcquireLock() {
        while (InterlockedCompareExchange(&g_spoofLock, 1, 0) != 0) {
            YieldProcessor();
        }
    }
    static __forceinline void ReleaseLock() {
        InterlockedExchange(&g_spoofLock, 0);
    }

#ifdef _WIN64
    template<typename Ret, typename Fn, typename... Args>
    static __forceinline Ret Call(Fn func, Args... args) {
        AcquireLock();
        SetTarget((LPVOID)func);
        Ret result = ((Ret(__cdecl*)(Args...))GetTrampoline())(args...);
        ReleaseLock();
        return result;
    }
    template<typename Fn, typename... Args>
    static __forceinline void CallVoid(Fn func, Args... args) {
        AcquireLock();
        SetTarget((LPVOID)func);
        ((void(__cdecl*)(Args...))GetTrampoline())(args...);
        ReleaseLock();
    }
#else
    template<typename Ret, typename Fn, typename... Args>
    static __forceinline Ret Call(Fn func, Args... args) {
        return ((Ret(__stdcall*)(Args...))func)(args...);
    }
    template<typename Fn, typename... Args>
    static __forceinline void CallVoid(Fn func, Args... args) {
        ((void(__stdcall*)(Args...))func)(args...);
    }
#endif
}
