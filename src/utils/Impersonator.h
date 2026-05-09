#pragma once
#include <windows.h>
namespace Utils {
    class Impersonator {
    public:
        Impersonator();
        ~Impersonator();
        static bool IsAdmin();
        bool IsImpersonating() const { return _impersonating; }
    private:
        bool _impersonating = false;
        bool EnablePrivilege(LPCSTR privilege);
        DWORD GetProcessIdByName(LPCSTR name);
    };
}
