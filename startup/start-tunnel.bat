@echo off
title PCAP Tunnel Watchdog - STATE SAFE VERSION
setlocal enabledelayedexpansion

:: ==========================================
:: CONFIG
:: ==========================================
set LOGFILE=D:\DevSpace\pcap-analyzer\startup\start-tunnel.log
set HOSTLOG=D:\DevSpace\pcap-analyzer\startup\devtunnel-host.log
set METAFILE=D:\DevSpace\pcap-analyzer\startup\tunnel-meta.json
set FRONTEND_ENV=D:\DevSpace\pcap-analyzer\frontend\.env.local
set BACKEND_ENV=D:\DevSpace\pcap-analyzer\backend\.env
set TUNNEL_NAME=pcap-backend
set TUNNEL_PORT=3001

call :LOG "=========================================="
call :LOG " PCAP Tunnel Watchdog - STATE SAFE"
call :LOG "=========================================="

:: ==========================================
:: CHECK DEVTUNNEL
:: ==========================================
where devtunnel >nul 2>&1
if errorlevel 1 (
    call :LOG "[FATAL] devtunnel not found"
    pause & exit /b 1
)

:: ==========================================
:: AUTH CHECK (ONLY ON START)
:: ==========================================
call :CHECK_AUTH

:: ==========================================
:: LOAD SAVED URL (SAFE JSON PARSE)
:: ==========================================
set TUNNEL_URL=

if exist "%METAFILE%" (
    for /f "delims=" %%A in ('
        powershell -NoProfile -Command ^
        "try { (Get-Content '%METAFILE%' -Raw | ConvertFrom-Json).Url } catch { '' }"
    ') do set TUNNEL_URL=%%A
)

:: ==========================================
:: VALIDATE URL
:: ==========================================
if defined TUNNEL_URL (
    echo %TUNNEL_URL% | findstr /i "https://" >nul
    if errorlevel 1 (
        call :LOG "[WARN] Corrupt URL - resetting"
        set TUNNEL_URL=
    )
)

:: ==========================================
:: CHECK TUNNEL STATE (REAL SOURCE OF TRUTH)
:: ==========================================
if defined TUNNEL_URL (
    devtunnel list 2>nul | findstr /i "%TUNNEL_NAME%" >nul
    if not errorlevel 1 (
        call :LOG "[REUSE] Tunnel exists - restarting host on existing tunnel"
        set REUSE_FLAG=1
        goto :START_HOST
    ) else (
        call :LOG "[WARN] Tunnel not found - recreating"
    )
)

goto :CREATE_TUNNEL

:: ==========================================
:: CREATE TUNNEL
:: ==========================================
:CREATE_TUNNEL
set REUSE_FLAG=
call :LOG "[INFO] Creating tunnel..."

devtunnel delete %TUNNEL_NAME% --force >nul 2>&1
devtunnel create %TUNNEL_NAME% --allow-anonymous >nul 2>&1
devtunnel port create %TUNNEL_NAME% --port-number %TUNNEL_PORT% --protocol http >nul 2>&1

goto :START_HOST

:: ==========================================
:: START HOST (SAFE + WAIT)
:: ==========================================
:START_HOST

if exist "%HOSTLOG%" del /f "%HOSTLOG%" >nul 2>&1

start /min "" cmd /c "devtunnel host %TUNNEL_NAME% >> %HOSTLOG% 2>&1"

call :LOG "[INFO] Waiting for host readiness..."

:: WAIT UNTIL LOG EXISTS AND HAS DATA
:WAIT_HOST_FILE
if not exist "%HOSTLOG%" (
    timeout /t 2 >nul
    goto :WAIT_HOST_FILE
)

for %%A in ("%HOSTLOG%") do if %%~zA EQU 0 (
    timeout /t 2 >nul
    goto :WAIT_HOST_FILE
)

:: ==========================================
:: CHECK IF HOST LOG SHOWS TOKEN EXPIRY
:: ==========================================
findstr /i "unauthorized\|token.*expir\|not logged in\|login required\|401\|403" "%HOSTLOG%" >nul 2>&1
if not errorlevel 1 (
    call :LOG "[AUTH] Token expired detected in host log - re-logging in..."
    devtunnel user login --github
    if errorlevel 1 (
        call :LOG "[FATAL] Re-login failed. Exiting."
        pause & exit /b 1
    )
    call :LOG "[AUTH] Re-login successful - retrying host start"
    goto :START_HOST
)

:: ==========================================
:: EXTRACT URL ONLY AFTER READY
:: ==========================================
set TUNNEL_URL=
set RAW_LINE=

for /f "delims=" %%L in ('
    findstr /i "https://.*devtunnels.ms" "%HOSTLOG%"
') do (
    set RAW_LINE=%%L
    goto :URL_OK
)

:URL_OK
if not defined RAW_LINE (
    call :LOG "[ERROR] URL extraction failed - check hostlog"
    type "%HOSTLOG%"
    pause & exit /b 1
)

call :LOG "[INFO] !RAW_LINE!"

for /f "delims=" %%U in ('
    powershell -NoProfile -Command "$m=[regex]::Matches('!RAW_LINE!','https://\S+'); $m[$m.Count-1].Value.TrimEnd(',')"
') do set TUNNEL_URL=%%U

if not defined TUNNEL_URL (
    call :LOG "[ERROR] Could not extract URL"
    pause & exit /b 1
)

call :SAVE_META
call :UPDATE_ENV

goto :WATCH

:: ==========================================
:: WATCH LOOP (NO FALSE RESTARTS)
:: ==========================================
:WATCH
echo %date% %time:~0,8% - [OK] Watchdog running (STATE SAFE MODE)
echo %date% %time:~0,8% - [OK] Watchdog running (STATE SAFE MODE) >> "%LOGFILE%"

:LOOP
timeout /t 30 >nul

:: ---- Check auth token before any devtunnel ops ----
call :CHECK_AUTH

:: Check tunnel exists on server
devtunnel list 2>nul | findstr /i "%TUNNEL_NAME%" >nul
if errorlevel 1 (
    echo %date% %time:~0,8% - [DETECTED] Tunnel gone - recreating
    echo %date% %time:~0,8% - [DETECTED] Tunnel gone - recreating >> "%LOGFILE%"
    goto :CREATE_TUNNEL
)

:: Check host process is still alive
tasklist /fi "imagename eq devtunnel.exe" | findstr /i "devtunnel.exe" >nul
if errorlevel 1 (
    echo %date% %time:~0,8% - [DETECTED] Host process dead - restarting
    echo %date% %time:~0,8% - [DETECTED] Host process dead - restarting >> "%LOGFILE%"
    goto :START_HOST
)

goto :LOOP

:: ==========================================
:: CHECK AUTH + AUTO RE-LOGIN ON TOKEN EXPIRY
:: ==========================================
:CHECK_AUTH
set AUTH_OUTPUT=
set AUTH_EXPIRED=0

:: Capture devtunnel user show output to a temp file
devtunnel user show > "%TEMP%\devtunnel-auth-check.tmp" 2>&1
set AUTH_ERR=%errorlevel%

:: Check for expiry/auth-failure keywords in the output
findstr /i "unauthorized\|token.*expir\|not logged in\|login required\|401\|403\|no user\|unauthenticated" "%TEMP%\devtunnel-auth-check.tmp" >nul 2>&1
if not errorlevel 1 set AUTH_EXPIRED=1

:: Also treat a non-zero exit from user show as suspicious
if !AUTH_ERR! NEQ 0 set AUTH_EXPIRED=1

if "!AUTH_EXPIRED!"=="1" (
    call :LOG "[AUTH] Token expired or not logged in - running: devtunnel login --github"
    devtunnel user login --github
    if errorlevel 1 (
        call :LOG "[FATAL] GitHub login failed. Please login manually and restart."
        pause & exit /b 1
    )
    call :LOG "[AUTH] Login successful"
) else (
    call :LOG "[AUTH] Token valid - no re-login needed"
)

del /f "%TEMP%\devtunnel-auth-check.tmp" >nul 2>&1
goto :eof

:: ==========================================
:: SAVE META
:: ==========================================
:SAVE_META
powershell -NoProfile -Command "$o=[ordered]@{Url='!TUNNEL_URL!';Time=(Get-Date)};$o|ConvertTo-Json|Set-Content '%METAFILE%'"
echo %date% %time:~0,8% - [INFO] Meta saved
echo %date% %time:~0,8% - [INFO] Meta saved >> "%LOGFILE%"
goto :eof

:: ==========================================
:: UPDATE ENV FILES
:: ==========================================
:UPDATE_ENV
set URL=!TUNNEL_URL!
set FRONTEND_KEY=
set BACKEND_KEY=

powershell -NoProfile -ExecutionPolicy Bypass -Command "$url = '!URL!'; $f = '%FRONTEND_ENV%'; $c = (Get-Content $f) -join \"`n\"; $c = $c -replace '(?m)^(NEXT_PUBLIC_API_URL=).*', ('NEXT_PUBLIC_API_URL=' + $url); $c | Set-Content $f"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$url = '!URL!'; $f = '%BACKEND_ENV%'; $c = (Get-Content $f) -join \"`n\"; $c = $c -replace '(?m)^(ALLOWED_ORIGIN=).*', ('ALLOWED_ORIGIN=' + $url); $c | Set-Content $f"

for /f "tokens=1 delims==" %%K in ('findstr /i "!URL!" "%FRONTEND_ENV%"') do set FRONTEND_KEY=%%K
for /f "tokens=1 delims==" %%K in ('findstr /i "!URL!" "%BACKEND_ENV%"') do set BACKEND_KEY=%%K

if "!REUSE_FLAG!"=="1" (
    echo %date% %time:~0,8% - [INFO] Frontend Unchanged ^(!FRONTEND_KEY!^) : !URL!
    echo %date% %time:~0,8% - [INFO] Frontend Unchanged ^(!FRONTEND_KEY!^) : !URL! >> "%LOGFILE%"
    echo %date% %time:~0,8% - [INFO] Backend Unchanged ^(!BACKEND_KEY!^) : !URL!
    echo %date% %time:~0,8% - [INFO] Backend Unchanged ^(!BACKEND_KEY!^) : !URL! >> "%LOGFILE%"
) else (
    echo %date% %time:~0,8% - [INFO] Frontend Updated ^(!FRONTEND_KEY!^) : !URL!
    echo %date% %time:~0,8% - [INFO] Frontend Updated ^(!FRONTEND_KEY!^) : !URL! >> "%LOGFILE%"
    echo %date% %time:~0,8% - [INFO] Backend Updated ^(!BACKEND_KEY!^) : !URL!
    echo %date% %time:~0,8% - [INFO] Backend Updated ^(!BACKEND_KEY!^) : !URL! >> "%LOGFILE%"
)

echo %date% %time:~0,8% - [HEALTH] !URL!/health
echo %date% %time:~0,8% - [HEALTH] !URL!/health >> "%LOGFILE%"

start "" "!URL!/health"

echo %date% %time:~0,8% - [DEBUG] UPDATE_ENV complete
echo %date% %time:~0,8% - [DEBUG] UPDATE_ENV complete >> "%LOGFILE%"

goto :eof

:: ==========================================
:: LOGGER
:: ==========================================
:LOG
set TS=%date% %time:~0,8%
echo %TS% - %~1
echo %TS% - %~1 >> "%LOGFILE%"
goto :eof