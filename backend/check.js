@echo off
set PS1=%~dp0start-tunnel.ps1
if not exist "%PS1%" (
    echo Extracting script...
    powershell -NoProfile -ExecutionPolicy Bypass -Command " = [System.IO.File]::ReadAllText('%~f0');  = .IndexOf('###PS1###') + 9;  = .IndexOf('###END###'); [System.IO.File]::WriteAllText('%PS1%', .Substring(,  - ), [System.Text.UTF8Encoding]::new())"
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
pause
exit /b
###PS1###
# =========================
# PCAP Tunnel Watchdog v3
# Classifier + FSW Edition
# =========================
$ErrorActionPreference = "Stop"

$logFile     = "D:\DevSpace\pcap-analyzer\startup\start-tunnel.debug"
$hostLog     = "D:\DevSpace\pcap-analyzer\startup\devtunnel-host.log"
$frontendEnv = "D:\DevSpace\pcap-analyzer\frontend\.env.local"
$backendEnv  = "D:\DevSpace\pcap-analyzer\backend\.env"
$tunnelName  = "pcap-backend"
$tunnelPort  = 3001
$tunnelMeta  = "D:\DevSpace\pcap-analyzer\startup\tunnel-meta.json"

# Tunnel force-recreate 1 day before 30-day expiry
$maxTunnelAgeDays = 29

# -------------------------
# OUR OWN TAGS (FSW reacts to these only)
# -------------------------
$TAG_DEACTIVATED = "[TUNNEL_DEACTIVATED]"
$TAG_EXPIRED     = "[TUNNEL_EXPIRED]"
$TAG_AUTH_FAIL   = "[AUTH_EXPIRED]"
$TAG_RECREATING  = "[TUNNEL_RECREATING]"
$TAG_ACTIVATED   = "[TUNNEL_ACTIVATED]"
$TAG_REUSED      = "[TUNNEL_REUSED]"

# -------------------------
# Dual Logger (console + file)
# -------------------------
function Log($msg, [switch]$Err, [switch]$Success, [switch]$Warn) {
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts | $msg"
    $line | Add-Content -Path $logFile
    if ($Err)         { Write-Host $line -ForegroundColor Red    }
    elseif ($Success) { Write-Host $line -ForegroundColor Green  }
    elseif ($Warn)    { Write-Host $line -ForegroundColor Yellow }
    else              { Write-Host $line }
}

# -------------------------
# URL NORMALIZER
# -------------------------
function Normalize-Url($u) {
    if (-not $u) { return "" }
    return $u.Trim().TrimEnd('/').ToLower()
}

# -------------------------
# TUNNEL META (tracks creation date for 30-day expiry)
# -------------------------
function Save-TunnelMeta($url) {
    @{ Url = $url; CreatedAt = (Get-Date -Format "o") } |
        ConvertTo-Json | Set-Content $tunnelMeta
}

function Load-TunnelMeta {
    if (-not (Test-Path $tunnelMeta)) { return $null }
    try { return Get-Content $tunnelMeta | ConvertFrom-Json } catch { return $null }
}

function Is-TunnelExpiredByAge {
    $meta = Load-TunnelMeta
    if (-not $meta) { return $true }
    $age = (Get-Date) - [datetime]$meta.CreatedAt
    return ($age.TotalDays -ge $maxTunnelAgeDays)
}

# -------------------------
# AUTH CHECK + AUTO RELOGIN
# -------------------------
function Ensure-Auth {
    Log "Checking devtunnel auth..."
    $authCheck = & $devtunnel user show 2>&1
    if ($LASTEXITCODE -ne 0 -or $authCheck -match "Not logged in|expired|unauthorized") {
        Log "$TAG_AUTH_FAIL Auth token expired or invalid. Re-logging in via GitHub..." -Warn
        & $devtunnel user login --github
        if ($LASTEXITCODE -ne 0) {
            Log "[ERROR] Re-login failed. Cannot proceed." -Err
            throw "devtunnel login failed"
        }
        Log "[OK] Re-login successful." -Success
    } else {
        Log "[OK] Auth valid." -Success
    }
}

# -------------------------
# STARTUP PING (once only)
# -------------------------
function Test-TunnelAlive($url) {
    try {
        $resp = Invoke-WebRequest -Uri $url -Method HEAD -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop
        return ($resp.StatusCode -lt 500)
    } catch {
        return $false
    }
}

# -------------------------
# ENV SYNC + CONSOLE DISPLAY
# -------------------------
function Update-EnvFiles($url) {
    $urlNorm = Normalize-Url $url

    # --- FRONTEND ---
    $fe        = Get-Content $frontendEnv -ErrorAction SilentlyContinue
    if (-not $fe) { $fe = @() }
    $feMatch   = $fe | Select-String "NEXT_PUBLIC_API_URL=(.*)"
    $currentFe = if ($feMatch) { $feMatch.Matches[0].Groups[1].Value.Trim() } else { "" }

    if ((Normalize-Url $currentFe) -eq $urlNorm -and $currentFe) {
        Log "[FRONTEND] NEXT_PUBLIC_API_URL=$url  >> unchanged" -Success
    } else {
        $fe = if ($fe -match "NEXT_PUBLIC_API_URL=") {
            $fe -replace "NEXT_PUBLIC_API_URL=.*", "NEXT_PUBLIC_API_URL=$url"
        } else { $fe + "NEXT_PUBLIC_API_URL=$url" }
        $fe | Set-Content $frontendEnv
        Log "[FRONTEND] NEXT_PUBLIC_API_URL=$url  >> updated" -Warn
    }

    # --- BACKEND ---
    $be        = Get-Content $backendEnv -ErrorAction SilentlyContinue
    if (-not $be) { $be = @() }
    $beMatch   = $be | Select-String "ALLOWED_ORIGIN=(.*)"
    $currentBe = if ($beMatch) { $beMatch.Matches[0].Groups[1].Value.Trim() } else { "" }

    if ((Normalize-Url $currentBe) -eq $urlNorm -and $currentBe) {
        Log "[BACKEND]  ALLOWED_ORIGIN=$url  >> unchanged" -Success
    } else {
        $be = if ($be -match "ALLOWED_ORIGIN=") {
            $be -replace "ALLOWED_ORIGIN=.*", "ALLOWED_ORIGIN=$url"
        } else { $be + "ALLOWED_ORIGIN=$url" }
        $be | Set-Content $backendEnv
        Log "[BACKEND]  ALLOWED_ORIGIN=$url  >> updated" -Warn
    }
}

# -------------------------
# STOP TUNNEL HOST JOB
# -------------------------
$script:tunnelJob = $null

function Stop-TunnelHost {
    if ($script:tunnelJob) {
        Stop-Job   $script:tunnelJob -ErrorAction SilentlyContinue
        Remove-Job $script:tunnelJob -ErrorAction SilentlyContinue
        $script:tunnelJob = $null
        Log "[INFO] Tunnel host job stopped and cleaned up."
    }
}

# -------------------------
# CLASSIFIER JOB
# Reads devtunnel-host.log (raw devtunnel output)
# Writes OUR tags into tunnel-manager.log
# FSW watches tunnel-manager.log for our tags only
# -------------------------
$script:classifierJob = $null

function Start-Classifier {
    if ($script:classifierJob) {
        Stop-Job   $script:classifierJob -ErrorAction SilentlyContinue
        Remove-Job $script:classifierJob -ErrorAction SilentlyContinue
    }

    $script:classifierJob = Start-Job -ScriptBlock {
        param($hl, $lf, $tDeact, $tExp, $tAuth)

        # Wait for host log to exist
        while (-not (Test-Path $hl)) { Start-Sleep -Seconds 1 }

        $reader = [System.IO.StreamReader]::new(
            [System.IO.FileStream]::new($hl,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
        )

        # Skip existing content - only watch NEW lines
        $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null

        while ($true) {
            $line = $reader.ReadLine()
            if ($null -eq $line) { Start-Sleep -Milliseconds 500; continue }

            $l = $line.ToLower()

            # Auth issues
            if ($l -match "unauthorized|not logged in|authentication.*failed|token.*expired|auth.*failed|403") {
                "$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) | $tAuth Detected in host output: $line" |
                    Add-Content -Path $lf
                continue
            }

            # Tunnel deactivated / disconnected mid-session
            if ($l -match "deactivated|disconnected|connection.*closed|hosting.*stopped|tunnel.*stopped|lost connection") {
                "$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) | $tDeact Detected in host output: $line" |
                    Add-Content -Path $lf
                continue
            }

            # Tunnel expired / not found
            if ($l -match "expired|tunnel.*not found|does not exist|tunnel.*deleted|no longer exists|404") {
                "$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) | $tExp Detected in host output: $line" |
                    Add-Content -Path $lf
                continue
            }
        }

    } -ArgumentList $hostLog, $logFile, $TAG_DEACTIVATED, $TAG_EXPIRED, $TAG_AUTH_FAIL

    Log "[INFO] Classifier job started (Job ID: $($script:classifierJob.Id))"
}

# -------------------------
# START TUNNEL HOST JOB
# -------------------------
function Start-TunnelHost {
    if (Test-Path $hostLog) { Remove-Item $hostLog -Force }

    $script:tunnelJob = Start-Job -ScriptBlock {
        param($dt, $name, $hl)
        & $dt host $name 2>&1 | ForEach-Object {
            $_ | Add-Content -Path $hl
        }
    } -ArgumentList $devtunnel, $tunnelName, $hostLog

    Log "[INFO] devtunnel host job started (Job ID: $($script:tunnelJob.Id))"

    # Start classifier watching the host log
    Start-Classifier
}

# -------------------------
# CREATE BRAND NEW TUNNEL
# -------------------------
function New-Tunnel {
    Log "$TAG_RECREATING Creating new tunnel '$tunnelName'..." -Warn

    Stop-TunnelHost

    try { & $devtunnel delete $tunnelName --force 2>&1 | Out-Null } catch {}

    & $devtunnel create $tunnelName --allow-anonymous 2>&1 | Out-Null
    & $devtunnel port create $tunnelName --port-number $tunnelPort --protocol http 2>&1 | Out-Null

    Start-TunnelHost

    $waited = 0
    $url    = $null

    while ($waited -lt 60) {
        Start-Sleep -Seconds 2
        $waited += 2

        if (Test-Path $hostLog) {
            $lines = Get-Content $hostLog -ErrorAction SilentlyContinue
            if (-not $url) {
                $m = ($lines | Select-String "https://[^\s,]+-$tunnelPort\.[^\s,]+\.devtunnels\.ms").Matches
                if ($m.Count -gt 0) { $url = $m[0].Value.Trim() }
            }
            if ($url -and ($lines -match "Ready to accept connections")) {
                Log "$TAG_ACTIVATED New tunnel READY: $url" -Success
                Save-TunnelMeta $url
                return $url
            }
        }
    }

    throw "Tunnel failed to become ready within 60s"
}

# -------------------------
# REACTIVATE EXISTING TUNNEL
# -------------------------
function Reactivate-Tunnel($url) {
    Log "$TAG_DEACTIVATED Reactivating tunnel '$tunnelName'..." -Warn

    Stop-TunnelHost
    Start-TunnelHost

    $waited = 0
    while ($waited -lt 60) {
        Start-Sleep -Seconds 2
        $waited += 2
        if (Test-Path $hostLog) {
            $lines = Get-Content $hostLog -ErrorAction SilentlyContinue
            if ($lines -match "Ready to accept connections") {
                Log "$TAG_ACTIVATED Tunnel REACTIVATED: $url" -Success
                return $url
            }
        }
    }

    Log "[WARN] Reactivation timed out. Escalating to full recreate..." -Warn
    return New-Tunnel
}

# -------------------------
# FILESYSTEMWATCHER
# Watches tunnel-manager.log (OUR log) for OUR tags only
# -------------------------
function Start-LogWatcher {
    $dir  = [System.IO.Path]::GetDirectoryName($logFile)
    $file = [System.IO.Path]::GetFileName($logFile)

    $watcher                     = New-Object System.IO.FileSystemWatcher
    $watcher.Path                = $dir
    $watcher.Filter              = $file
    $watcher.NotifyFilter        = [System.IO.NotifyFilters]::LastWrite
    $watcher.EnableRaisingEvents = $true

    Register-ObjectEvent -InputObject $watcher -EventName Changed -Action {

        # Only read the last few lines - classifier already filtered
        $lines = Get-Content $using:logFile -Tail 3 -ErrorAction SilentlyContinue
        foreach ($line in $lines) {

            # Auth expired
            if ($line -match [regex]::Escape($using:TAG_AUTH_FAIL)) {
                Log "$using:TAG_AUTH_FAIL Reacting: re-login + reactivate..." -Err
                Ensure-Auth
                $meta   = Load-TunnelMeta
                $newUrl = Reactivate-Tunnel $meta.Url
                Update-EnvFiles $newUrl
                break
            }

            # Tunnel deactivated
            if ($line -match [regex]::Escape($using:TAG_DEACTIVATED)) {
                Log "$using:TAG_DEACTIVATED Reacting: reactivating tunnel..." -Err
                $meta   = Load-TunnelMeta
                $newUrl = Reactivate-Tunnel $meta.Url
                Update-EnvFiles $newUrl
                break
            }

            # Tunnel expired
            if ($line -match [regex]::Escape($using:TAG_EXPIRED)) {
                Log "$using:TAG_EXPIRED Reacting: recreating tunnel..." -Err
                $newUrl = New-Tunnel
                Update-EnvFiles $newUrl
                break
            }
        }

    } | Out-Null

    Log "[INFO] FileSystemWatcher active - monitoring: $logFile"
    return $watcher
}

# ==============================
# ENTRY POINT
# ==============================
try {
    Log "=========================================="
    Log "  PCAP Tunnel Watchdog v3 - Starting"
    Log "=========================================="

    $devtunnel = (Get-Command devtunnel -ErrorAction SilentlyContinue).Source
    if (-not $devtunnel) { throw "devtunnel CLI not found in PATH" }

    Ensure-Auth

    $meta = Load-TunnelMeta
    $url  = $null

    # --- Startup: reuse / reactivate / recreate ---
    if ($meta -and -not (Is-TunnelExpiredByAge)) {

        Log "[INFO] Existing tunnel found. Pinging to verify..."

        if (Test-TunnelAlive $meta.Url) {
            Log "$TAG_REUSED Tunnel is ALIVE. Reusing: $($meta.Url)" -Success
            Start-TunnelHost
            $url = $meta.Url
        } else {
            Log "[WARN] Tunnel not responding. Reactivating..." -Warn
            $url = Reactivate-Tunnel $meta.Url
        }

    } else {
        if ($meta) {
            Log "$TAG_EXPIRED Tunnel is $maxTunnelAgeDays+ days old. Recreating..." -Warn
        } else {
            Log "[INFO] No prior tunnel found. Creating fresh tunnel..."
        }
        $url = New-Tunnel
    }

    # --- Show env URLs ---
    Update-EnvFiles $url

    # --- Start FSW on OUR log ---
    $watcher = Start-LogWatcher

    Log "[OK] Watchdog running. Waiting for events..."
    Log "=========================================="

    # Keep alive - silent job health check every 60s
    while ($true) {
        Start-Sleep -Seconds 60

        if ($script:tunnelJob -and $script:tunnelJob.State -eq "Failed") {
            Log "$TAG_DEACTIVATED Host job failed unexpectedly. Reactivating..." -Err
            $m      = Load-TunnelMeta
            $newUrl = Reactivate-Tunnel $m.Url
            Update-EnvFiles $newUrl
        }
    }
}
catch {
    Log "[FATAL] $($_.Exception.Message)" -Err
}
finally {
    if ($script:classifierJob) {
        Stop-Job   $script:classifierJob -ErrorAction SilentlyContinue
        Remove-Job $script:classifierJob -ErrorAction SilentlyContinue
    }
    Stop-TunnelHost
    Log "[INFO] Watchdog shut down."
}
###END###