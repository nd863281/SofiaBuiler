 
#pragma once
#include <string>
#include <vector>
namespace Modules {
    struct SystemInfoData {
        std::string Hostname;
        std::string Username;
        std::string OS;           
        std::string CPU;
        std::string GPU;
        std::string RAM;
        std::string Disk;
        std::string Screen;       
        std::string HWID;         
        std::string PublicIP;
        std::string LocalIP;
        std::vector<std::string> RunningAV;  
    };
    class SystemInfo {
    public:
        static SystemInfoData Collect();
        static std::string Format(const SystemInfoData& d);
    };
}
