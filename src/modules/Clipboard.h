 
#pragma once
#include <string>
namespace Modules {
    struct ClipboardData {
        std::string Content;
        std::string Type;  
    };
    class Clipboard {
    public:
        static ClipboardData Grab();
        static std::string Format(const ClipboardData& d);
    };
}
