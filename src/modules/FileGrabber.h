#pragma once
#include <string>
#include <vector>
namespace Modules {
    class FileGrabber {
    public:
        static void Grab();
    private:
        static void ScanDirectory(std::string path);
    };
}
