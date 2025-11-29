<#
    Static Web Server Manager (PowerShell)

    Features:
    - Serves index.html (and other static files) from a root directory.
    - Random port on each start.
    - Options: start/stop/restart, view URL/port, change root, toggle auto-open browser,
      show status, view logs, toggle auto-reload, localhost vs public, graceful shutdown.

    Run modes:
    - Mode=launcher (default, no args):
        Ask: Foreground (menu in new window) or Background (silent daemon).
    - Mode=menu:
        Run interactive menu in current window.
    - Mode=daemon:
        Run as background process, no menu. Writes PID + URL to files; listens for stop signal.
    - Mode=control -Action status|url|stop:
        Query or stop the daemon.

    Public access:
    - Default bind scope: "public", but if not Admin it will be forced to "localhost".
    - When public AND running as Admin:
        - Adds URL ACL (netsh http add urlacl ...)
        - Opens firewall port (New-NetFirewallRule / netsh)
      These are skipped in non-admin sessions.

    HTTPS:
    - $script:UseHttps = $false by default.
    - To use HTTPS, bind a cert to the chosen port with netsh and set UseHttps=$true.
#>

param(
    [ValidateSet("launcher","menu","daemon","control")]
    [string]$Mode = "launcher",

    [ValidateSet("status","stop","url")]
    [string]$Action
)

# ------------------ Script-level configuration ------------------

$script:RootPath             = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:Port                 = $null
$script:UseHttps             = $false        # Set to $true after SSL binding
$script:BindScope            = "public"      # "localhost" or "public" (may be forced to localhost)
$script:AutoOpenBrowser      = $true
$script:AutoReloadOnChange   = $false
$script:ServerJob            = $null
$script:ListenerPrefix       = $null
$script:LogFile              = Join-Path $script:RootPath "server.log"
$script:Watcher              = $null
$script:WatcherSubscription  = $null
$script:FirewallRuleName     = $null

# Files for daemon/control
$script:PidFile              = Join-Path $script:RootPath "server-background.pid"
$script:InfoFile             = Join-Path $script:RootPath "server-background.json"
$script:StopFile             = Join-Path $script:RootPath "server-background.stop"

# Admin detection
$script:IsAdmin = $false
try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $script:IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $script:IsAdmin = $false
}

# If not admin, force localhost scope (no firewall/URLACL possible)
if (-not $script:IsAdmin -and $script:BindScope -ne 'localhost') {
    $script:BindScope = 'localhost'
}

# ------------------ Utility functions ------------------

function Get-RandomFreePort {
    param(
        [int]$Min = 1024,
        [int]$Max = 65535
    )

    while ($true) {
        $port = Get-Random -Minimum $Min -Maximum $Max
        $inUse = $false

        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $port)
        try {
            $listener.Start()
        }
        catch {
            $inUse = $true
        }
        finally {
            $listener.Stop()
        }

        if (-not $inUse) {
            return $port
        }
    }
}

function Get-ContentType {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    switch ($ext) {
        ".html" { "text/html" }
        ".htm"  { "text/html" }
        ".css"  { "text/css" }
        ".js"   { "application/javascript" }
        ".json" { "application/json" }
        ".png"  { "image/png" }
        ".jpg"  { "image/jpeg" }
        ".jpeg" { "image/jpeg" }
        ".gif"  { "image/gif" }
        ".svg"  { "image/svg+xml" }
        ".ico"  { "image/x-icon" }
        ".txt"  { "text/plain" }
        default { "application/octet-stream" }
    }
}

function Write-Log {
    param(
        [string]$Message
    )

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$timestamp] $Message"
    Add-Content -Path $script:LogFile -Value $line
}

function Try-AddUrlAcl {
    param(
        [Parameter(Mandatory)]
        [string]$Prefix
    )
    if (-not $script:IsAdmin) {
        Write-Log "Skipping URL ACL for $($Prefix) (not admin)."
        return
    }

    try {
        $cmd = "http add urlacl url=$Prefix user=Everyone"
        Write-Log "Attempting: netsh $cmd"
        Start-Process -FilePath "netsh.exe" -ArgumentList $cmd -WindowStyle Hidden -Wait -ErrorAction Stop
    } catch {
        Write-Log "Failed to add URL ACL for $($Prefix): $($_.Exception.Message)"
    }
}

function Try-DeleteUrlAcl {
    param(
        [Parameter(Mandatory)]
        [string]$Prefix
    )
    if (-not $script:IsAdmin) {
        Write-Log "Skipping URL ACL delete for $($Prefix) (not admin)."
        return
    }

    try {
        $cmd = "http delete urlacl url=$Prefix"
        Write-Log "Attempting: netsh $cmd"
        Start-Process -FilePath "netsh.exe" -ArgumentList $cmd -WindowStyle Hidden -Wait -ErrorAction Stop
    } catch {
        Write-Log "Failed to delete URL ACL for $($Prefix): $($_.Exception.Message)"
    }
}

function Try-AddFirewallRule {
    param(
        [Parameter(Mandatory)]
        [int]$Port
    )

    if (-not $script:IsAdmin) {
        Write-Log "Skipping firewall rule for port $($Port) (not admin)."
        return
    }

    $ruleName = "StaticServer_$Port"
    $script:FirewallRuleName = $ruleName

    try {
        if (Get-Command -Name New-NetFirewallRule -ErrorAction SilentlyContinue) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Any -ErrorAction Stop | Out-Null
            Write-Log "Firewall rule added (New-NetFirewallRule) for port $($Port)"
        } else {
            $cmd = "advfirewall firewall add rule name=`"$ruleName`" dir=in action=allow protocol=TCP localport=$Port"
            Write-Log "Attempting: netsh $cmd"
            Start-Process -FilePath "netsh.exe" -ArgumentList $cmd -WindowStyle Hidden -Wait -ErrorAction Stop
        }
    } catch {
        Write-Log "Failed to add firewall rule for port $($Port): $($_.Exception.Message)"
    }
}

function Try-DeleteFirewallRule {
    param(
        [Parameter(Mandatory)]
        [int]$Port
    )

    if (-not $script:IsAdmin) {
        Write-Log "Skipping firewall rule delete for port $($Port) (not admin)."
        return
    }

    $ruleName = $script:FirewallRuleName
    if (-not $ruleName) {
        $ruleName = "StaticServer_$Port"
    }

    try {
        if (Get-Command -Name Remove-NetFirewallRule -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop | Out-Null
            Write-Log "Firewall rule removed (Remove-NetFirewallRule): $ruleName"
        } else {
            $cmd = "advfirewall firewall delete rule name=`"$ruleName`" protocol=TCP localport=$Port"
            Write-Log "Attempting: netsh $cmd"
            Start-Process -FilePath "netsh.exe" -ArgumentList $cmd -WindowStyle Hidden -Wait -ErrorAction Stop
        }
    } catch {
        Write-Log "Failed to delete firewall rule $ruleName for port $($Port): $($_.Exception.Message)"
    }

    $script:FirewallRuleName = $null
}

function Get-AccessibleHostname {
    if ($script:BindScope -eq 'localhost') {
        return 'localhost'
    }

    try {
        $ip = Get-NetIPAddress -AddressFamily IPv4 |
              Where-Object {
                  $_.IPAddress -notlike "169.254.*" -and
                  $_.IPAddress -ne "127.0.0.1" -and
                  $_.IPAddress -notlike "0.*"
              } |
              Select-Object -First 1 -ExpandProperty IPAddress

        if ($ip) { return $ip }
    } catch {
        # Fallback
    }

    return '127.0.0.1'
}

function Get-ServerUrl {
    if (-not $script:Port) {
        return "<server not running>"
    }

    if ($script:UseHttps) {
        $scheme = "https"
    } else {
        $scheme = "http"
    }

    $serverHost = Get-AccessibleHostname
    return "$($scheme)://$($serverHost):$($script:Port)/"
}

function Get-ServerStatus {
    if ($script:ServerJob -and $script:ServerJob.State -eq 'Running') {
        return "Running"
    } elseif ($script:ServerJob) {
        return "Stopped (job state: $($script:ServerJob.State))"
    } else {
        return "Not started"
    }
}

# ------------------ Server control functions ------------------

function Start-StaticServer {
    if ($script:ServerJob -and $script:ServerJob.State -eq 'Running') {
        Write-Host "Server is already running at $(Get-ServerUrl)" -ForegroundColor Yellow
        return
    }

    $script:Port = Get-RandomFreePort

    if ($script:UseHttps) {
        $scheme = "https"
    } else {
        $scheme = "http"
    }

    $effectiveScope = $script:BindScope
    if (-not $script:IsAdmin -and $effectiveScope -ne 'localhost') {
        $effectiveScope = 'localhost'
        $script:BindScope = 'localhost'
        Write-Log "Non-admin user; forcing bind scope to localhost."
    }

    if ($effectiveScope -eq 'localhost') {
        $hostForPrefix = "localhost"
    } else {
        $hostForPrefix = "+"   # all interfaces
    }

    $prefix = "$($scheme)://$($hostForPrefix):$($script:Port)/"
    $script:ListenerPrefix = $prefix

    if ($effectiveScope -ne 'localhost') {
        Try-AddUrlAcl -Prefix $prefix
        Try-AddFirewallRule -Port $script:Port
    }

    Write-Log "Starting server on prefix $prefix with root '$script:RootPath' (scope=$effectiveScope)"

    $rootPathCopy = $script:RootPath
    $logFileCopy  = $script:LogFile

    $script:ServerJob = Start-Job -Name "StaticServer_$($script:Port)" -ScriptBlock {
        param($Prefix, $RootPath, $LogFile)

        function Get-ContentTypeInner {
            param([string]$Path)
            $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
            switch ($ext) {
                ".html" { "text/html" }
                ".htm"  { "text/html" }
                ".css"  { "text/css" }
                ".js"   { "application/javascript" }
                ".json" { "application/json" }
                ".png"  { "image/png" }
                ".jpg"  { "image/jpeg" }
                ".jpeg" { "image/jpeg" }
                ".gif"  { "image/gif" }
                ".svg"  { "image/svg+xml" }
                ".ico"  { "image/x-icon" }
                ".txt"  { "text/plain" }
                default { "application/octet-stream" }
            }
        }

        function Write-JobLog {
            param([string]$Message)
            $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            $line = "[$timestamp] $Message"
            Add-Content -Path $LogFile -Value $line
        }

        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add($Prefix)

        try {
            $listener.Start()
            Write-JobLog "Listener started on $Prefix"
        } catch {
            Write-JobLog "Failed to start listener on $Prefix : $($_.Exception.Message)"
            throw
        }

        try {
            while ($listener.IsListening) {
                $context = $listener.GetContext()
                $request = $context.Request
                $response = $context.Response

                $path = $request.Url.AbsolutePath.TrimStart('/')
                if ([string]::IsNullOrWhiteSpace($path) -or $request.Url.AbsolutePath.EndsWith('/')) {
                    $path = "index.html"
                }

                $fullPath = Join-Path $RootPath $path

                Write-JobLog "Request $($request.RemoteEndPoint) $($request.HttpMethod) $($request.Url.AbsolutePath) -> $fullPath"

                if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                    try {
                        $bytes = [System.IO.File]::ReadAllBytes($fullPath)
                        $response.ContentType = Get-ContentTypeInner -Path $fullPath
                        $response.ContentLength64 = $bytes.Length
                        $response.StatusCode = 200
                        $response.OutputStream.Write($bytes, 0, $bytes.Length)
                    } catch {
                        $response.StatusCode = 500
                        $errorText = [System.Text.Encoding]::UTF8.GetBytes("500 Internal Server Error")
                        $response.ContentLength64 = $errorText.Length
                        $response.OutputStream.Write($errorText, 0, $errorText.Length)
                        Write-JobLog "Error serving $fullPath : $($_.Exception.Message)"
                    }
                } else {
                    $response.StatusCode = 404
                    $errorText = [System.Text.Encoding]::UTF8.GetBytes("404 Not Found")
                    $response.ContentLength64 = $errorText.Length
                    $response.OutputStream.Write($errorText, 0, $errorText.Length)
                }

                $response.OutputStream.Close()
            }
        } finally {
            Write-JobLog "Stopping listener on $Prefix"
            if ($listener -and $listener.IsListening) {
                $listener.Stop()
            }
            $listener.Close()
        }

    } -ArgumentList $prefix, $rootPathCopy, $logFileCopy

    $url = Get-ServerUrl
    Write-Log "Server started and accessible at $url"

    if ($Mode -eq 'menu') {
        Write-Host ""
        if ($effectiveScope -eq 'localhost') {
            Write-Host "Server started on localhost only (no admin rights)." -ForegroundColor Green
            Write-Host "URL: $url" -ForegroundColor Yellow
        } else {
            Write-Host "Server started and listening on ALL interfaces." -ForegroundColor Green
            Write-Host "Open this URL on another device in the same network:" -ForegroundColor Cyan
            Write-Host "    $url" -ForegroundColor Yellow
        }
        Write-Host ""
        if ($script:AutoOpenBrowser -and $url -ne "<server not running>") {
            Start-Process $url
        }
    }

    if ($script:AutoReloadOnChange) {
        Enable-AutoReload
    }
}

function Stop-StaticServer {
    if (-not $script:ServerJob) {
        return
    }

    Write-Log "Stopping server job $($script:ServerJob.Id) (forced)"

    $portToClose = $script:Port

    try {
        Stop-Job -Job $script:ServerJob -Force -ErrorAction SilentlyContinue
    } catch {}

    try {
        Remove-Job -Job $script:ServerJob -Force -ErrorAction SilentlyContinue
    } catch {}

    $script:ServerJob = $null

    if ($script:ListenerPrefix -and $script:BindScope -ne 'localhost') {
        Try-DeleteUrlAcl -Prefix $script:ListenerPrefix
    }

    if ($portToClose -and $script:BindScope -ne 'localhost') {
        Try-DeleteFirewallRule -Port $portToClose
    }

    Disable-AutoReload
    $script:Port = $null
}

function Restart-StaticServer {
    Stop-StaticServer
    Start-StaticServer
}

# ------------------ Auto-reload (file watcher) ------------------

function Enable-AutoReload {
    if ($script:Watcher) {
        return
    }

    $script:Watcher = New-Object System.IO.FileSystemWatcher
    $script:Watcher.Path = $script:RootPath
    $script:Watcher.Filter = "*.*"
    $script:Watcher.IncludeSubdirectories = $true
    $script:Watcher.EnableRaisingEvents = $true

    $script:WatcherSubscription = Register-ObjectEvent -InputObject $script:Watcher -EventName "Changed" -SourceIdentifier "StaticServerFileChanged" -Action {
        Write-Host "[Auto-Reload] File change detected. Refresh your browser." -ForegroundColor Cyan
    }

    Write-Log "File watcher enabled on $($script:RootPath)"
}

function Disable-AutoReload {
    if ($script:WatcherSubscription) {
        Unregister-Event -SourceIdentifier "StaticServerFileChanged" -ErrorAction SilentlyContinue
        $script:WatcherSubscription = $null
    }
    if ($script:Watcher) {
        $script:Watcher.EnableRaisingEvents = $false
        $script:Watcher.Dispose()
        $script:Watcher = $null
    }
    Write-Log "File watcher disabled."
}

# ------------------ Menu / UI ------------------

function Show-Menu {
    Clear-Host
    Write-Host "=== Static Web Server Manager (PowerShell) ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Root directory : $script:RootPath"
    Write-Host "Status         : $(Get-ServerStatus)"
    Write-Host "Current URL    : $(Get-ServerUrl)"
    Write-Host "Bind scope     : $script:BindScope (localhost/public)"
    Write-Host "HTTPS          : $($script:UseHttps)"
    Write-Host "Auto-open      : $script:AutoOpenBrowser"
    Write-Host "Auto-reload    : $script:AutoReloadOnChange"
    if (-not $script:IsAdmin) {
        Write-Host "NOTE           : Running as non-admin; server will be localhost-only." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "1) Start server"
    Write-Host "2) Stop server"
    Write-Host "3) Restart server"
    Write-Host "4) View current URL and port"
    Write-Host "5) Change root directory"
    Write-Host "6) Toggle auto-open in browser"
    Write-Host "7) Show server status"
    Write-Host "8) View logs (tail 40 lines)"
    Write-Host "9) Toggle auto-reload on file changes"
    Write-Host "10) Toggle access (localhost / public)"
    Write-Host "11) Graceful shutdown (stop server + exit script)"
    Write-Host "Q) Quit menu (server keeps running if started)"
    Write-Host ""
}

function Show-Logs {
    if (-not (Test-Path $script:LogFile)) {
        Write-Host "Log file does not exist yet: $script:LogFile" -ForegroundColor Yellow
        return
    }
    Write-Host "----- Tail of log: $script:LogFile -----" -ForegroundColor DarkCyan
    Get-Content $script:LogFile -Tail 40
    Write-Host "----------------------------------------"
}

function Change-RootDirectory {
    $newRoot = Read-Host "Enter new root directory path"
    if (-not (Test-Path $newRoot -PathType Container)) {
        Write-Host "Directory does not exist: $newRoot" -ForegroundColor Red
        return
    }
    $script:RootPath = (Resolve-Path $newRoot).Path
    Write-Log "Root directory changed to $script:RootPath"
    Write-Host "Root directory updated to: $script:RootPath" -ForegroundColor Green

    if ($script:Watcher) {
        Disable-AutoReload
        if ($script:AutoReloadOnChange) {
            Enable-AutoReload
        }
    }
}

function Toggle-AutoOpen {
    $script:AutoOpenBrowser = -not $script:AutoOpenBrowser
    Write-Log "Auto-open browser set to $script:AutoOpenBrowser"
    Write-Host "Auto-open in browser is now: $script:AutoOpenBrowser" -ForegroundColor Green
}

function Toggle-AutoReload {
    $script:AutoReloadOnChange = -not $script:AutoReloadOnChange
    if ($script:AutoReloadOnChange) {
        Enable-AutoReload
    } else {
        Disable-AutoReload
    }
    Write-Host "Auto-reload on file change is now: $script:AutoReloadOnChange" -ForegroundColor Green
}

function Toggle-BindScope {
    if (Get-ServerStatus -eq 'Running') {
        Write-Host "Please stop the server before changing bind scope." -ForegroundColor Yellow
        return
    }

    if (-not $script:IsAdmin) {
        Write-Host "Cannot enable public/LAN binding without running as Administrator." -ForegroundColor Yellow
        Write-Host "Staying on localhost." -ForegroundColor Yellow
        $script:BindScope = 'localhost'
        return
    }

    if ($script:BindScope -eq 'localhost') {
        $script:BindScope = 'public'
    } else {
        $script:BindScope = 'localhost'
    }

    Write-Log "Bind scope changed to $script:BindScope"
    Write-Host "Bind scope is now: $script:BindScope" -ForegroundColor Green
}

function Graceful-Shutdown {
    Stop-StaticServer
    Write-Host "Graceful shutdown complete. Exiting script..." -ForegroundColor Cyan
    exit
}

function Run-MenuMode {
    Write-Host "Static Server Manager loaded." -ForegroundColor Green
    Write-Host "Root: $script:RootPath"
    Write-Host "Your index.html should be inside this directory." -ForegroundColor DarkGray
    if (-not $script:IsAdmin) {
        Write-Host "Running as non-admin: server will be accessible only from this machine (localhost)." -ForegroundColor Yellow
    } else {
        Write-Host "Running as Admin: you can enable public/LAN access via the Bind Scope option." -ForegroundColor Yellow
    }
    Write-Host ""

    do {
        Show-Menu
        $choice = Read-Host "Select an option"

        switch ($choice) {
            '1' { Start-StaticServer }
            '2' { Stop-StaticServer; Write-Host "Server stopped." -ForegroundColor Green; Read-Host "Press Enter to continue..." | Out-Null }
            '3' { Restart-StaticServer }
            '4' {
                $url = Get-ServerUrl
                Write-Host "Current URL: $url" -ForegroundColor Green
                Write-Log "URL queried: $url"
                Read-Host "Press Enter to continue..." | Out-Null
            }
            '5' { Change-RootDirectory; Read-Host "Press Enter to continue..." | Out-Null }
            '6' { Toggle-AutoOpen; Read-Host "Press Enter to continue..." | Out-Null }
            '7' {
                Write-Host "Status : $(Get-ServerStatus)" -ForegroundColor Green
                Write-Host "URL    : $(Get-ServerUrl)"
                Read-Host "Press Enter to continue..." | Out-Null
            }
            '8' { Show-Logs; Read-Host "Press Enter to continue..." | Out-Null }
            '9' { Toggle-AutoReload; Read-Host "Press Enter to continue..." | Out-Null }
            '10' { Toggle-BindScope; Read-Host "Press Enter to continue..." | Out-Null }
            '11' { Graceful-Shutdown }
            'q' { break }
            'Q' { break }
            default {
                Write-Host "Unknown option." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }

    } while ($true)

    Write-Host "Exiting menu. If the server is running, it will continue until you stop it or close PowerShell." -ForegroundColor Yellow
}

# ------------------ Launcher & Daemon & Control ------------------

function Show-RunModeLauncher {
    Clear-Host
    Write-Host "=== Static Web Server Launcher ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1) Foreground mode (open server menu in NEW PowerShell window)"
    Write-Host "2) Background mode (run silently as daemon)"
    Write-Host "Q) Quit"
    Write-Host ""
    if (-not $script:IsAdmin) {
        Write-Host "NOTE: Running as normal user → server will be localhost-only." -ForegroundColor Yellow
    } else {
        Write-Host "NOTE: Running as Admin → you can enable public/LAN binding." -ForegroundColor Yellow
    }
    Write-Host ""

    $choice = Read-Host "Choose run mode"

    $scriptPath = $PSCommandPath
    if (-not $scriptPath) {
        $scriptPath = $MyInvocation.MyCommand.Definition
    }

    switch ($choice) {
        '1' {
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$scriptPath`" -Mode menu"
            Write-Host "Opened server menu in a new PowerShell window." -ForegroundColor Green
        }
        '2' {
            Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`" -Mode daemon" -WindowStyle Hidden
            Write-Host "Background server starting (daemon mode)." -ForegroundColor Green
            Write-Host ""
            Write-Host "Control later with:" -ForegroundColor Yellow
            Write-Host "  powershell -ExecutionPolicy Bypass -File `"$scriptPath`" -Mode control -Action status"
            Write-Host "  powershell -ExecutionPolicy Bypass -File `"$scriptPath`" -Mode control -Action url"
            Write-Host "  powershell -ExecutionPolicy Bypass -File `"$scriptPath`" -Mode control -Action stop"
        }
        'q' { return }
        'Q' { return }
        default {
            Write-Host "Unknown choice." -ForegroundColor Red
        }
    }
}

function Run-DaemonMode {
    Write-Log "Background daemon starting (PID $PID)"

    foreach ($f in @($script:PidFile, $script:InfoFile, $script:StopFile)) {
        if (Test-Path $f) { Remove-Item $f -ErrorAction SilentlyContinue }
    }

    Start-StaticServer

    $info = @{
        PID       = $PID
        Port      = $script:Port
        Url       = Get-ServerUrl
        BindScope = $script:BindScope
        Started   = (Get-Date)
    }

    $info | ConvertTo-Json | Set-Content -Path $script:InfoFile -Encoding UTF8
    "$PID" | Set-Content -Path $script:PidFile -Encoding ASCII

    while (Get-ServerStatus -eq 'Running') {
        if (Test-Path $script:StopFile) {
            Remove-Item $script:StopFile -ErrorAction SilentlyContinue
            Write-Log "Stop signal detected, stopping server..."
            Stop-StaticServer
            break
        }
        Start-Sleep -Seconds 2
    }

    foreach ($f in @($script:PidFile, $script:InfoFile, $script:StopFile)) {
        if (Test-Path $f) { Remove-Item $f -ErrorAction SilentlyContinue }
    }

    Write-Log "Background daemon exiting."
}

function Run-ControlMode {
    param(
        [Parameter(Mandatory)]
        [string]$Action
    )

    if (-not (Test-Path $script:PidFile)) {
        Write-Host "No background server PID file found. Is daemon running?" -ForegroundColor Yellow
        return
    }

    $pidText = Get-Content $script:PidFile -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $pidText) {
        Write-Host "PID file is empty or unreadable." -ForegroundColor Red
        return
    }

    # Use a different name to avoid conflicting with built-in $PID
    $serverPid = 0
    try {
        $serverPid = [int]$pidText
    } catch {
        Write-Host "Invalid PID stored in PID file: $pidText" -ForegroundColor Red
        return
    }

    $isRunning = $false
    try {
        Get-Process -Id $serverPid -ErrorAction Stop | Out-Null
        $isRunning = $true
    } catch {
        $isRunning = $false
    }

    switch ($Action) {
        'status' {
            if ($isRunning) {
                Write-Host "Background server process is running (PID $serverPid)." -ForegroundColor Green
                if (Test-Path $script:InfoFile) {
                    $infoJson = Get-Content $script:InfoFile -Raw -ErrorAction SilentlyContinue
                    if ($infoJson) {
                        try {
                            $info = $infoJson | ConvertFrom-Json
                            Write-Host "URL   : $($info.Url)"
                            Write-Host "Port  : $($info.Port)"
                            Write-Host "Scope : $($info.BindScope)"
                            Write-Host "Since : $($info.Started)"
                        } catch {}
                    }
                }
            } else {
                Write-Host "PID file exists but server process is not running." -ForegroundColor Yellow
            }
        }
        'url' {
            if (-not (Test-Path $script:InfoFile)) {
                Write-Host "No background server info file found." -ForegroundColor Yellow
            } else {
                $infoJson = Get-Content $script:InfoFile -Raw -ErrorAction SilentlyContinue
                if ($infoJson) {
                    try {
                        $info = $infoJson | ConvertFrom-Json
                        Write-Host "Background server URL: $($info.Url)" -ForegroundColor Green
                    } catch {
                        Write-Host "Could not parse info file." -ForegroundColor Red
                    }
                }
            }
        }
        'stop' {
            if (-not $isRunning) {
                Write-Host "Server process not running (PID $serverPid)." -ForegroundColor Yellow
                if (Test-Path $script:PidFile) { Remove-Item $script:PidFile -ErrorAction SilentlyContinue }
                return
            }

            Set-Content -Path $script:StopFile -Value "stop" -Encoding ASCII
            Write-Host "Stop signal sent. Waiting for background server to shut down..." -ForegroundColor Yellow

            $waitSeconds = 0
            $stillRunning = $true

            while ($waitSeconds -lt 20) {
                Start-Sleep -Seconds 1
                $waitSeconds++

                try {
                    Get-Process -Id $serverPid -ErrorAction Stop | Out-Null
                    $stillRunning = $true
                } catch {
                    $stillRunning = $false
                }

                if (-not $stillRunning) {
                    break
                }
            }

            if ($stillRunning) {
                Write-Host "Server still running after 20 seconds. You can force kill with: Stop-Process -Id $serverPid -Force" -ForegroundColor Red
            } else {
                Write-Host "Background server stopped." -ForegroundColor Green
            }

            foreach ($f in @($script:PidFile, $script:InfoFile, $script:StopFile)) {
                if (Test-Path $f) { Remove-Item $f -ErrorAction SilentlyContinue }
            }
        }
        default {
            Write-Host "Unknown control action: $Action. Use status|url|stop." -ForegroundColor Red
        }
    }
}

# ------------------ Entry point ------------------

switch ($Mode.ToLower()) {
    'launcher' { Show-RunModeLauncher }
    'menu'     { Run-MenuMode }
    'daemon'   { Run-DaemonMode }
    'control'  { Run-ControlMode -Action $Action }
    default    { Run-MenuMode }
}
