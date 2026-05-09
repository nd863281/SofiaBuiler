#pragma once
#include <windows.h>
#include <string>
#include <vector>
namespace Crypto {
    std::string DecryptDPAPI(const std::vector<BYTE>& data);
    std::vector<BYTE> DecryptAES_GCM(const std::vector<BYTE>& key, const std::vector<BYTE>& iv, const std::vector<BYTE>& aad, const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& tag);
    std::vector<BYTE> DecryptChaCha20Poly1305(const std::vector<BYTE>& key, const std::vector<BYTE>& iv, const std::vector<BYTE>& aad, const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& tag);
    std::vector<BYTE> Base64Decode(const std::string& input);
}
