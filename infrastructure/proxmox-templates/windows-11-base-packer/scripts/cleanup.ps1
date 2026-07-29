# Runs immediately before sysprep.ps1.
#
# Note that this empties C:\Windows\Temp. Anything that has to survive until
# Sysprep -- sysprep-unattend.xml -- is staged in C:\Windows\Setup\Scripts.

$ErrorActionPreference = "Continue"

Write-Host "Cleaning temporary files"

# The build account's name comes from a Packer variable, so enumerate profiles
# rather than hardcoding a path under C:\Users.
$ProfileTemp = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName "AppData\Local\Temp\*" }

$TempPaths = @(
    "C:\Windows\Temp\*"
    "$env:TEMP\*"
) + $ProfileTemp

# Packer stages its own scaffolding in C:\Windows\Temp -- the per-provisioner
# script and the environment-variable file the elevated wrapper dot-sources. This
# script runs from inside that scaffolding, so a blanket wipe deletes the files
# the *next* provisioner is about to run and Packer fails with "the term
# c:/Windows/Temp/packer-ps-env-vars-....ps1 is not recognized".
$PackerArtifacts = @("packer-*", "script-*")

foreach ($Path in $TempPaths) {
    Remove-Item `
        -Path $Path `
        -Recurse `
        -Force `
        -Exclude $PackerArtifacts `
        -ErrorAction SilentlyContinue
}

Clear-RecycleBin -Force -ErrorAction SilentlyContinue

Write-Host "Removing Windows Update download cache"

Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue

Remove-Item `
    -Path "C:\Windows\SoftwareDistribution\Download\*" `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Start-Service -Name wuauserv -ErrorAction SilentlyContinue

Write-Host "Clearing Windows event logs"

wevtutil.exe el |
    ForEach-Object {
        wevtutil.exe cl "$_" 2>$null
    }

Write-Host "Removing Packer auto-logon"

# Set by autounattend.xml so the first-logon bootstrap could run. It must not
# survive into the template -- DefaultPassword is stored in cleartext.
$WinlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

$AutoLogonValues = @(
    "AutoAdminLogon"
    "AutoLogonCount"
    "DefaultPassword"
    "DefaultUserName"
    "DefaultDomainName"
)

foreach ($Value in $AutoLogonValues) {
    Remove-ItemProperty `
        -Path $WinlogonKey `
        -Name $Value `
        -ErrorAction SilentlyContinue
}

Write-Host "Cleanup complete"
