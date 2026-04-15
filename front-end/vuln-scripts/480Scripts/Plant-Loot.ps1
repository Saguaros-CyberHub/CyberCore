<#
.SYNOPSIS
    Plants proof files (unique per student), loot, and breadcrumb data
    on MedAlliance-WIN Tier 1 for grading and discovery.

.NOTES
    Proof files:
      C:\Users\m.chen\Desktop\local.txt                    — user-level proof
      C:\Users\Administrator\Desktop\proof.txt              — admin-level proof
    Both contain a unique hash derived from the student ID so the professor
    can verify screenshots are from the student's own lane.

    Loot planted:
      Browser saved passwords (simulated via text file)
      RDP connection history in registry
      Payroll spreadsheet in m.chen's Documents
      Bash-history equivalent (PowerShell console history)
#>

param(
    [Parameter(Mandatory=$true)][string]$StudentId,
    [Parameter(Mandatory=$true)][string]$WinIP
)

$ErrorActionPreference = "Continue"
$subnetRef = $WinIP -replace '\.\d+$', ''

function Write-Phase {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')][Loot] $Msg"
}

# ═══════════════════════════════════════════════════════════════
#  1. GENERATE UNIQUE PROOF HASHES
# ═══════════════════════════════════════════════════════════════
#
# Each student gets unique proof.txt and local.txt content so the
# professor can verify screenshots come from the student's own lane.

$sha = [System.Security.Cryptography.SHA256]::Create()

$localHash = [BitConverter]::ToString(
    $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("CYBV480-LOCAL-${StudentId}-${WinIP}"))
).Replace("-", "").ToLower().Substring(0, 32)

$proofHash = [BitConverter]::ToString(
    $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("CYBV480-PROOF-${StudentId}-${WinIP}"))
).Replace("-", "").ToLower().Substring(0, 32)

Write-Phase "Generated proof hashes for student: $StudentId"

# ═══════════════════════════════════════════════════════════════
#  2. PLANT PROOF FILES
# ═══════════════════════════════════════════════════════════════

# m.chen's Desktop — local.txt (user-level access proof)
$mchenDesktop = "C:\Users\m.chen\Desktop"
New-Item -Path $mchenDesktop -ItemType Directory -Force | Out-Null

@"
===================================
  MedAlliance-WIN  local.txt
  CYBV 480 — Tier 1
===================================
  Flag: $localHash
===================================

You have proven user-level access as m.chen.

Next steps:
  - Enumerate this system for privilege escalation vectors
  - Check: whoami /priv, net localgroup administrators
  - Run WinPEAS or PowerUp.ps1
  - Look for: unquoted service paths, writable services,
    AlwaysInstallElevated, stored credentials, writable tasks
  - Escalate to Administrator or SYSTEM
  - Collect proof.txt from Administrator's Desktop
"@ | Set-Content "$mchenDesktop\local.txt" -Encoding UTF8

Write-Phase "Planted local.txt on m.chen Desktop ($localHash)"

# Administrator's Desktop — proof.txt (admin-level access proof)
$adminDesktop = "C:\Users\Administrator\Desktop"
New-Item -Path $adminDesktop -ItemType Directory -Force | Out-Null

@"
===================================
  MedAlliance-WIN  proof.txt
  CYBV 480 — Tier 1
===================================
  Flag: $proofHash
===================================

Congratulations — you have achieved Administrator/SYSTEM
access on MEDALLIANCE-WIN.

For your report, screenshot this with:
  - whoami
  - hostname
  - ipconfig
  - type C:\Users\Administrator\Desktop\proof.txt

All in one terminal window.
"@ | Set-Content "$adminDesktop\proof.txt" -Encoding UTF8

Write-Phase "Planted proof.txt on Administrator Desktop ($proofHash)"

# ═══════════════════════════════════════════════════════════════
#  3. PLANT LOOT IN m.chen's PROFILE
# ═══════════════════════════════════════════════════════════════

$mchenDocs = "C:\Users\m.chen\Documents"
New-Item -Path $mchenDocs -ItemType Directory -Force | Out-Null

# Fake "saved browser passwords" file (simulating browser credential dump)
@"
=== Chrome Saved Passwords Export ===
Generated: 2024-10-15 by Chrome Password Manager

URL                                          Username              Password
---                                          --------              --------
https://portal.medalliance.local/admin       admin                 admin
https://portal.medalliance.local/login       m.chen                MedAlliance2024!
http://medalliance-lnx/webmail               m.chen                MedAlliance2024!
https://outlook.office365.com                m.chen@medalliance.local  MedAlliance2024!
https://github.com                           mchen-medallliance    GitH3alth2024!
https://aws.amazon.com/console               medalliance-admin     (not saved)
http://${WinIP}:8080                         admin                 admin

NOTE: Chrome warns that 4 of these passwords appeared in data breaches.
"@ | Set-Content "$mchenDocs\chrome_passwords_export.txt" -Encoding UTF8

# Fake payroll summary (PII — exfiltration target)
@"
MedAlliance Health Partners — Payroll Summary Q3 2024
=====================================================
CONFIDENTIAL — Finance Department Use Only

Employee             Dept        Gross (Monthly)  SSN (Last 4)  Direct Deposit
--------             ----        ---------------  -----------   --------------
Marcus Chen          IT          $6,541.67        4521          ****4521
Jennifer Thompson    IT          $7,666.67        8834          ****8834
David Park           Finance     $5,583.33        1187          ****1187
Sarah Mitchell       HR          $7,916.67        5593          ****5593
Robert Garcia        Clinical    $7,333.33        7742          ****7742
Amanda Foster        Finance     $11,833.33       6628          ****6628
James Wilson         IT          $4,333.33        9915          ****9915
Maria Rodriguez      Clinical    $3,666.67        3341          ****3341
Kevin Brown          Operations  $5,083.33        2267          ****2267
Lisa Anderson        HR          $4,833.33        4479          ****4479
Thomas Martinez      IT          $4,000.00        6653          ****6653
Rachel Kim           Clinical    $6,000.00        1198          ****1198
Michael Davis        Finance     $4,250.00        8827          ****8827
Emily Taylor         Operations  $3,166.67        5544          ****5544
Daniel Lee           IT          $7,083.33        2210          ****2210
Jessica Clark        Clinical    $4,666.67        9933          ****9933
Andrew Wright        Finance     $6,166.67        1176          ****1176
Nicole Harris        HR          $4,500.00        7782          ****7782
Christopher Moore    Operations  $5,250.00        3358          ****3358
Stephanie White      Clinical    $7,583.33        4495          ****4495

Q3 Total Payroll: $349,166.70
Tax Withholding:  $87,291.68
Net Disbursed:    $261,875.02

Prepared by: D. Park | Approved by: A. Foster
"@ | Set-Content "$mchenDocs\payroll_summary_Q3_2024.txt" -Encoding UTF8

Write-Phase "Planted loot in m.chen Documents."

# ═══════════════════════════════════════════════════════════════
#  4. PLANT RDP CONNECTION HISTORY
# ═══════════════════════════════════════════════════════════════

Write-Phase "Planting RDP connection history..."

# Plant RDP connection history in Default user's registry
# (will show up when students check recent connections)
$rdpServers = "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers"
if (-not (Test-Path $rdpServers)) { New-Item -Path $rdpServers -Force | Out-Null }

# Fake connections showing this machine talks to the Linux server and DC
$targets = @(
    @{ IP = "${subnetRef}.20"; User = "j.thompson"; Hint = "medalliance-lnx" },
    @{ IP = "${subnetRef}.50"; User = "m.chen";     Hint = "MEDALLIANCE-DC"  }
)

foreach ($t in $targets) {
    $serverPath = "$rdpServers\$($t.IP)"
    New-Item -Path $serverPath -Force | Out-Null
    Set-ItemProperty -Path $serverPath -Name "UsernameHint" -Value "$($t.Hint)\$($t.User)"
}

# Also set MRU (Most Recently Used) for the RDP client
$mruPath = "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default"
if (-not (Test-Path $mruPath)) { New-Item -Path $mruPath -Force | Out-Null }
Set-ItemProperty -Path $mruPath -Name "MRU0" -Value "${subnetRef}.20"
Set-ItemProperty -Path $mruPath -Name "MRU1" -Value "${subnetRef}.50"

Write-Phase "RDP history planted (shows connections to .20 and .50)."

# ═══════════════════════════════════════════════════════════════
#  5. PLANT POWERSHELL HISTORY (equivalent of .bash_history)
# ═══════════════════════════════════════════════════════════════

Write-Phase "Planting PowerShell history..."

$psHistoryDir = "C:\Users\m.chen\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
New-Item -Path $psHistoryDir -ItemType Directory -Force | Out-Null

@"
Get-Service | Where-Object {`$_.Status -eq 'Running'}
net user
net localgroup Administrators
whoami /priv
sqlcmd -S .\SQLEXPRESS -U sa -P SQLAdmin2024! -Q "SELECT name FROM sys.databases"
Test-NetConnection ${subnetRef}.20 -Port 22
Enter-PSSession -ComputerName ${subnetRef}.50 -Credential medalliance\m.chen
Invoke-WebRequest -Uri http://${subnetRef}.20/admin/ -UseBasicParsing
Get-ChildItem "C:\Program Files\MedAlliance\" -Recurse
sc.exe qc MedHealthSvc
schtasks /query /fo LIST /v | Select-String "daily_report"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
cmdkey /list
Get-SmbShare
net use \\${subnetRef}.20\Public
ssh j.thompson@${subnetRef}.20
"@ | Set-Content "$psHistoryDir\ConsoleHost_history.txt" -Encoding UTF8

Write-Phase "PowerShell history planted."

# ═══════════════════════════════════════════════════════════════
#  6. PLANT ADDITIONAL BREADCRUMBS
# ═══════════════════════════════════════════════════════════════

# Sticky notes / Desktop notes
@"
Reminders — Marcus Chen
========================
- SQL Server SA password: SQLAdmin2024!  (CHANGE THIS!!!)
- Health Monitor: http://localhost:8080 (admin/admin)
- Linux SSH: ssh j.thompson@${subnetRef}.20
- DC: MEDALLIANCE-DC at ${subnetRef}.50 (not joined yet)
- daily_report.bat needs to be locked down
- Talk to Daniel about the security audit findings
"@ | Set-Content "$mchenDesktop\reminders.txt" -Encoding UTF8

# Plant a file on Administrator's Desktop too (only visible after privesc)
@"
MedAlliance-WIN — Administrator Notes
======================================
KEEP THIS SECURE. Administrator access only.

Recovery passwords:
  Local admin:     MedAll!ance#Adm1n2024
  BitLocker:       (not enabled — TODO)
  SQL SA:          SQLAdmin2024!
  Service acct:    MedHealthSvc / H3althM0n!tor2024

Domain join planned for Q2 2025:
  DC: ${subnetRef}.50 (MEDALLIANCE-DC)
  Domain: medalliance.local
  Admin contact: domain admin (see DC docs)

Backup encryption key: (stored in HR safe, not digital)
"@ | Set-Content "$adminDesktop\admin_recovery_notes.txt" -Encoding UTF8

Write-Phase "All loot and breadcrumbs planted."

# ═══════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════
Write-Phase ""
Write-Phase "=== Loot & Proof Summary ==="
Write-Phase "  local.txt : C:\Users\m.chen\Desktop\local.txt"
Write-Phase "            : $localHash"
Write-Phase "  proof.txt : C:\Users\Administrator\Desktop\proof.txt"
Write-Phase "            : $proofHash"
Write-Phase "  Loot      : browser passwords, payroll, personal notes, PS history"
Write-Phase "  Breadcrumbs: RDP history, reminders, admin recovery notes"
Write-Phase ""
