@echo off
echo.
echo  ===============================================
echo    YUMIKO MEMORY ANALYZER
echo  ===============================================
echo    GitHub:  https://github.com/veridondevvv
echo    Discord: veridondevvv
echo    Version: 2.0
echo  ===============================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [WARNING] No admin rights!
    echo  Memory scan requires Administrator privileges.
    echo  Right-click ^> Run as Administrator.
    echo.
    pause
    exit /b 1
)

echo  [OK] Admin rights detected.
echo.
echo  Options:
echo   1) Single scan
echo   2) Continuous scan (every 5 seconds)
echo   3) Scan specific PID
echo   4) Deep scan (all memory regions)
echo.
set /p choice="Select (1/2/3/4): "

if "%choice%"=="1" (
    python minecraft_cheat_scanner.py
) else if "%choice%"=="2" (
    python minecraft_cheat_scanner.py --continuous --interval 5
) else if "%choice%"=="3" (
    set /p pid="Enter PID: "
    python minecraft_cheat_scanner.py --pid %pid%
) else if "%choice%"=="4" (
    python minecraft_cheat_scanner.py --deep
) else (
    python minecraft_cheat_scanner.py
)

echo.
echo  Scan complete.
echo  GitHub: https://github.com/veridondevvv  |  Discord: veridondevvv
pause
