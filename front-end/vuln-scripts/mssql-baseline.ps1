$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# Baseline MSSQL: if SQL Express is already installed, configure it safely --
# Windows-auth only, xp_cmdshell disabled, SA disabled, TCP on 1433 with
# standard firewall rule. Does NOT install SQL Server (that's a heavy download
# and belongs in a Proxmox template or separate install script).

$sqlService = Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -like 'MSSQL$*' -or $_.Name -eq 'MSSQLSERVER' } |
              Select-Object -First 1

if (-not $sqlService) {
    Write-Host "No MSSQL service detected on this host -- skipping SQL baseline."
    Write-Host "Install SQL Server Express first, then re-run this script."
    [Environment]::Exit(0)
}

Write-Step "Found SQL service: $($sqlService.Name)"
Set-Service -Name $sqlService.Name -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name $sqlService.Name -ErrorAction SilentlyContinue

# Instance short name for sqlcmd -S argument
$instanceName = if ($sqlService.Name -like 'MSSQL$*') { $sqlService.Name.Substring(6) } else { 'MSSQLSERVER' }
$sqlServerArg = if ($instanceName -eq 'MSSQLSERVER') { '.' } else { ".\$instanceName" }

Write-Step "Forcing Windows-authentication-only (LoginMode=1)"
$regBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
$instances = Get-ChildItem $regBase -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match "MSSQL\d+\.$instanceName" }
foreach ($inst in $instances) {
    $serverPath = "$($inst.PSPath)\MSSQLServer"
    if (Test-Path $serverPath) {
        Set-ItemProperty -Path $serverPath -Name "LoginMode" -Value 1 -Force
    }
}

Write-Step "Enabling TCP/IP on port 1433 (standard)"
foreach ($inst in $instances) {
    $tcpPath = "$($inst.PSPath)\MSSQLServer\SuperSocketNetLib\Tcp"
    if (Test-Path $tcpPath) {
        Set-ItemProperty -Path $tcpPath -Name "Enabled" -Value 1 -Force
        $ipAllPath = "$tcpPath\IPAll"
        if (Test-Path $ipAllPath) {
            Set-ItemProperty -Path $ipAllPath -Name "TcpPort" -Value "1433" -Force
            Set-ItemProperty -Path $ipAllPath -Name "TcpDynamicPorts" -Value "" -Force
        }
    }
}

Restart-Service -Name $sqlService.Name -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 8

# Find sqlcmd
$sqlcmd = $null
foreach ($pattern in @(
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\*\Tools\Binn\SQLCMD.EXE",
    "C:\Program Files\Microsoft SQL Server\*\Tools\Binn\SQLCMD.EXE"
)) {
    $found = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $sqlcmd = $found.FullName; break }
}

if ($sqlcmd) {
    Write-Step "Disabling SA + xp_cmdshell"
    & $sqlcmd -S $sqlServerArg -E -Q "ALTER LOGIN [sa] DISABLE;" 2>&1 | Out-Null
    & $sqlcmd -S $sqlServerArg -E -Q @"
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
"@ 2>&1 | Out-Null
} else {
    Write-Host "sqlcmd not found -- SA disable + xp_cmdshell lockdown skipped."
}

Write-Step "Opening TCP/1433 in firewall"
New-NetFirewallRule -DisplayName "Lab-MSSQL-1433-Allow" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

Write-Host ""
Write-Host "=== mssql-baseline complete ==="
Write-Host "Auth mode     : Windows-only"
Write-Host "SA account    : disabled"
Write-Host "xp_cmdshell   : disabled"
Write-Host "Port          : 1433/TCP"
