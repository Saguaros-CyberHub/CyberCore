$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# --- unattend.xml with plaintext credentials ---
Write-Step "Seeding unattend.xml with plaintext credentials"
$pantherDir = "C:\Windows\Panther"
if (-not (Test-Path $pantherDir)) { New-Item -ItemType Directory -Path $pantherDir -Force | Out-Null }

$unattend = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup">
      <AutoLogon>
        <Password>
          <Value>Winter2024!Deploy</Value>
          <PlainText>true</PlainText>
        </Password>
        <Enabled>true</Enabled>
        <LogonCount>3</LogonCount>
        <Username>deploy</Username>
      </AutoLogon>
      <UserAccounts>
        <AdministratorPassword>
          <Value>Admin2024!</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
    </component>
  </settings>
</unattend>
'@
Set-Content "$pantherDir\unattend.xml" $unattend -Encoding UTF8

# --- Group Policy Preferences (cpassword -- the classic) ---
Write-Step "Seeding GPP cpassword in SYSVOL-style path"
$gppDir = "C:\ProgramData\LabGPP\Groups"
New-Item -ItemType Directory -Path $gppDir -Force | Out-Null
# cpassword below decrypts to "Password123" via the well-known AES key (MS14-025 era).
Set-Content "$gppDir\Groups.xml" @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
        name="labadmin"
        image="2" changed="2024-08-12 14:00:00"
        uid="{AA3C5F58-12B4-42A9-A07F-CE4F62F1D2B1}">
    <Properties action="U"
                newName=""
                fullName="Lab Admin"
                description=""
                cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
                changeLogon="0" noChange="1" neverExpires="1"
                acctDisabled="0" userName="labadmin"/>
  </User>
</Groups>
'@ -Encoding UTF8

# --- Plaintext creds in a nightly-backup .bat (common admin laziness pattern) ---
Write-Step "Seeding backup .bat with net-use credentials"
$scriptsDir = "C:\Scripts"
if (-not (Test-Path $scriptsDir)) { New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null }
Set-Content "$scriptsDir\nightly-backup.bat" @"
@echo off
REM Nightly backup -- last edited by msp-tech on 2024-08-02
net use Z: \\backup01\nightly /user:BACKUPSVC Autumn2024!Backup /persistent:no
robocopy C:\Data Z:\data /MIR /R:2 /W:5 > C:\Lab\logs\nightly-backup.log 2>&1
net use Z: /delete
"@ -Encoding ASCII
icacls "$scriptsDir\nightly-backup.bat" /grant "Users:(R)" | Out-Null

# --- WinSCP-style saved session file (base64-ish encoded password) ---
Write-Step "Seeding WinSCP.ini with saved session"
$winscpDir = "C:\Users\Public\Documents"
Set-Content "$winscpDir\WinSCP.ini" @"
[Sessions]
[Sessions\sftp%5Ffiles]
HostName=files.internal.lab
UserName=msp-tech
PortNumber=22
Password=A35C7D81E9B2F4A6C8D0E1F20304050607
Protocol=2
"@ -Encoding UTF8

# --- Environment variable with "password" -- some tools grep env for this ---
Write-Step "Setting machine-level env var DB_PASSWORD"
[Environment]::SetEnvironmentVariable("DB_PASSWORD", "Winter2024!DB", "Machine")

# --- PowerShell history with a clear-text credential (AllUsersAllHosts) ---
Write-Step "Seeding PSReadLine history with embedded password"
$psHistory = "$env:APPDATA\..\..\..\Users\student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
if (-not (Test-Path $psHistory)) { New-Item -ItemType Directory -Path $psHistory -Force | Out-Null }
Set-Content "$psHistory\ConsoleHost_history.txt" @"
Get-Service
ipconfig /all
net use \\fileserver\backups /user:BACKUPSVC Autumn2024!Backup
whoami /all
Get-ADUser -Filter * | Select Name
"@ -Encoding ASCII

Write-Host ""
Write-Host "=== cached-credentials complete ==="
Write-Host "unattend.xml    : C:\Windows\Panther\unattend.xml (Admin2024!)"
Write-Host "Groups.xml      : cpassword -> Password123"
Write-Host "nightly-backup  : C:\Scripts\nightly-backup.bat (Autumn2024!Backup)"
Write-Host "WinSCP.ini      : C:\Users\Public\Documents\WinSCP.ini"
Write-Host "env DB_PASSWORD : Winter2024!DB"
Write-Host "PSReadLine      : student history"
