INSERT INTO "vuln_scripts" ("id", "slug", "name", "description", "category", "os_target", "difficulty", "script_content", "services_exposed", "depends_on", "estimated_runtime_sec", "is_active", "created_at", "script_args", "script_type") VALUES
('6234c889-67b2-4558-a183-5d0a7e4adaf3',	'win-artifact',	'Windows Artifacts',	NULL,	'User Simulation',	'windows',	'beginner',	'param(
    [switch]$Setup,
    [switch]$Verify,
    [switch]$Reset
)

$ErrorActionPreference = "Stop"

$Root              = "C:\ProgramData\DunderCorp\Artifacts"
$ProgramDataRoot   = "C:\ProgramData\DunderCorp"
$CredsDir          = Join-Path $Root "Creds"
$LogsDir           = Join-Path $Root "Logs"
$ConfigsDir        = Join-Path $Root "Configs"
$ExportsDir        = Join-Path $Root "Exports"
$NotesDir          = Join-Path $Root "Notes"
$TranscriptDir     = Join-Path $Root "Transcripts"

$AgentConf         = Join-Path $ConfigsDir "agent.conf"
$UnattendBackup    = Join-Path $ConfigsDir "staged_unattend.xml.bak"
$SupportHashes     = Join-Path $CredsDir "support_hashes.txt"
$InstallLog        = Join-Path $LogsDir "install.log"
$OpsNotes          = Join-Path $NotesDir "ops_notes.txt"
$TranscriptFile    = Join-Path $TranscriptDir "PowerShell_transcript-DunderOps.txt"

$User2History      = "C:\Users\USER2\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
$AdminHistory      = "C:\Users\ADMIN\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

$LabShare          = "C:\LabShare"
$LabSharePublic    = Join-Path $LabShare "Public"
$LabShareDrop      = Join-Path $LabShare "Drop"
$LabShareUsers     = Join-Path $LabShare "Users"

$AdminHome         = "C:\Users\ADMIN"
$User2Home         = "C:\Users\USER2"
$UserHome          = "C:\Users\USER"

$AdminDesktop      = Join-Path $AdminHome "Desktop"
$User2Desktop      = Join-Path $User2Home "Desktop"
$UserDesktop       = Join-Path $UserHome "Desktop"

$AdminDocuments    = Join-Path $AdminHome "Documents"
$User2Documents    = Join-Path $User2Home "Documents"
$UserDocuments     = Join-Path $UserHome "Documents"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-IfExists {
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force
    }
}

function Get-RandomPastDate {
    param(
        [int]$MinDaysAgo = 2,
        [int]$MaxDaysAgo = 35
    )

    $days = Get-Random -Minimum $MinDaysAgo -Maximum ($MaxDaysAgo + 1)
    $hours = Get-Random -Minimum 0 -Maximum 23
    $mins = Get-Random -Minimum 0 -Maximum 59
    return (Get-Date).AddDays(-$days).AddHours(-$hours).AddMinutes(-$mins)
}

function Set-BackdatedTimestamp {
    param(
        [string]$Path,
        [int]$MinDaysAgo = 2,
        [int]$MaxDaysAgo = 35
    )

    if (Test-Path $Path) {
        $dt = Get-RandomPastDate -MinDaysAgo $MinDaysAgo -MaxDaysAgo $MaxDaysAgo
        $item = Get-Item $Path -Force
        $item.CreationTime = $dt
        $item.LastWriteTime = $dt
        $item.LastAccessTime = $dt
    }
}

function Write-SeededTextFile {
    param(
        [string]$Path,
        [string]$Content,
        [string]$Encoding = "UTF8",
        [int]$MinDaysAgo = 2,
        [int]$MaxDaysAgo = 35
    )

    $parent = Split-Path $Path -Parent
    if ($parent) {
        Ensure-Dir $parent
    }

    if (-not (Test-Path $Path)) {
        Set-Content -Path $Path -Value $Content -Encoding $Encoding
        Set-BackdatedTimestamp -Path $Path -MinDaysAgo $MinDaysAgo -MaxDaysAgo $MaxDaysAgo
    }
}

function Ensure-BaseLayout {
    foreach ($d in @(
        $Root, $CredsDir, $LogsDir, $ConfigsDir, $ExportsDir, $NotesDir, $TranscriptDir,
        $LabShare, $LabSharePublic, $LabShareDrop, $LabShareUsers
    )) {
        Ensure-Dir $d
    }

    foreach ($d in @(
        $AdminDesktop, $User2Desktop, $UserDesktop,
        $AdminDocuments, $User2Documents, $UserDocuments
    )) {
        if (Test-Path (Split-Path $d -Parent)) {
            Ensure-Dir $d
        }
    }
}

function Ensure-DesktopFolders {
    Write-Step "Creating realistic desktop folders"

    foreach ($d in @(
        (Join-Path $AdminDesktop "Infra"),
        (Join-Path $AdminDesktop "Quarterly Review"),
        (Join-Path $AdminDesktop "Scripts"),
        (Join-Path $AdminDesktop "To Sort"),
        (Join-Path $AdminDesktop "Archive"),

        (Join-Path $User2Desktop "Tickets"),
        (Join-Path $User2Desktop "Exports"),
        (Join-Path $User2Desktop "Temp"),
        (Join-Path $User2Desktop "VPN"),
        (Join-Path $User2Desktop "Old Notes"),

        (Join-Path $UserDesktop "Projects"),
        (Join-Path $UserDesktop "Downloads To File"),
        (Join-Path $UserDesktop "Screenshots"),
        (Join-Path $UserDesktop "Old"),
        (Join-Path $UserDesktop "Reference")
    )) {
        Ensure-Dir $d
        Set-BackdatedTimestamp -Path $d -MinDaysAgo 3 -MaxDaysAgo 28
    }
}

function Seed-ProgramDataArtifacts {
    Write-Step "Seeding ProgramData artifacts"

    Write-SeededTextFile -Path $AgentConf -Content @"
[telemetry]
ServiceName=DunderTelemetry
TaskName=DunderCacheRefresh
Mode=legacy
RetrySeconds=30

[internal]
BackupHost=backup-srv01.dundercorp.local
MgmtHost=mgmt-srv01.dundercorp.local
FinanceHost=finance-srv01.dundercorp.local
ProxyHost=proxy01.dundercorp.local

[paths]
HashFile=$SupportHashes
Transcript=$TranscriptFile
StagedUnattend=$UnattendBackup
"@ -MinDaysAgo 10 -MaxDaysAgo 25

    Write-SeededTextFile -Path $UnattendBackup -Content @"
<unattend>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup">
      <AutoLogon>
        <Enabled>false</Enabled>
        <Username>svc_deploy</Username>
        <Password>
          <Value>LabDeploy2026!</Value>
          <PlainText>true</PlainText>
        </Password>
      </AutoLogon>
    </component>
  </settings>
</unattend>
"@ -MinDaysAgo 18 -MaxDaysAgo 35

    Write-SeededTextFile -Path $SupportHashes -Encoding ASCII -Content @"
# Lab-only hash material
# Format: account:NTLM
svc_backup:DE769E624BFE51CB4109255F0F1E0910
svc_install:51B056A8B2C13AEFE10D95EF051EF70A
legacy_sync:C65FF5F2633515BCA9B3370DD709074A
"@ -MinDaysAgo 7 -MaxDaysAgo 18

    Write-SeededTextFile -Path $InstallLog -Content @"
[2026-03-01 14:00:01] INFO  DunderOps maintenance package installed
[2026-03-01 14:00:05] INFO  Telemetry service registered as LocalSystem
[2026-03-01 14:00:08] INFO  Cache refresh task registered as SYSTEM
[2026-03-01 14:00:11] INFO  Legacy deployment backup copied to $UnattendBackup
[2026-03-01 14:00:14] INFO  Hash cache staged at $SupportHashes
[2026-03-01 14:00:16] INFO  Export staging path initialized at $ExportsDir
"@ -MinDaysAgo 12 -MaxDaysAgo 30

    Write-SeededTextFile -Path $OpsNotes -Content @"
Operations Notes
----------------
- Legacy telemetry still depends on ProgramData paths for hooks and cached exports.
- Cache refresh and telemetry rails should be reviewed before quarterly image refresh.
- Support hashes are for migration validation only and should not remain on production endpoints.
- Old unattended backup should be removed after deployment cleanup.
"@ -MinDaysAgo 4 -MaxDaysAgo 15

    Write-SeededTextFile -Path $TranscriptFile -Content @"
**********************
Windows PowerShell transcript start
Start time: 20260323174200
Username  : WINDOWS\ADMIN
RunAs User: WINDOWS\ADMIN
Machine   : WIN11LAB
**********************
PS> schtasks /query /tn DunderCacheRefresh /v /fo list
PS> sc.exe qc DunderTelemetry
PS> reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
PS> icacls C:\ProgramData\DunderCorp\Privesc\hooks\preflight.ps1
PS> icacls C:\ProgramData\DunderCorp\Privesc\tasks\refresh_cache.ps1
PS> Get-Content C:\ProgramData\DunderCorp\Artifacts\Creds\support_hashes.txt
**********************
Windows PowerShell transcript end
**********************
"@ -MinDaysAgo 3 -MaxDaysAgo 9

    Write-SeededTextFile -Path (Join-Path $ExportsDir "inventory_q1.csv") -Content @"
Hostname,Owner,Status,Notes
WIN11LAB,IT Ops,Active,Training image
backup-util,Operations,Review,Legacy sync still enabled
web-training,Security,Active,OWASP apps staged
filesrv-old,Infrastructure,Pending cleanup,Review before decom
"@ -MinDaysAgo 8 -MaxDaysAgo 22

    Write-SeededTextFile -Path (Join-Path $ExportsDir "vpn_approved_hosts.txt") -Content @"
vpn-gw01.dundercorp.local
backup-srv01.dundercorp.local
finance-srv01.dundercorp.local
mgmt-srv01.dundercorp.local
"@ -MinDaysAgo 5 -MaxDaysAgo 14

    Write-SeededTextFile -Path (Join-Path $ExportsDir "endpoint_rollup.csv") -Content @"
Hostname,PrimaryUser,Department,VPN,Notes
WIN11LAB,USER2,Support,Yes,Needs cleanup review
OPS-WS-14,ADMIN,Infrastructure,Yes,Old scripts on desktop
SEC-WS-08,USER,Security,No,Archive pending
"@ -MinDaysAgo 6 -MaxDaysAgo 16
}

function Seed-PowerShellHistory {
    Write-Step "Seeding PowerShell history"

    Write-SeededTextFile -Path $User2History -Content @"
whoami /priv
Get-Service DunderTelemetry
schtasks /query /fo LIST /v
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ChildItem C:\ProgramData\DunderCorp -Recurse
type C:\ProgramData\DunderCorp\Artifacts\Configs\agent.conf
"@ -MinDaysAgo 2 -MaxDaysAgo 8

    Write-SeededTextFile -Path $AdminHistory -Content @"
sc.exe qc DunderTelemetry
sc.exe sdshow DunderTelemetry
schtasks /run /tn DunderCacheRefresh
Get-Content C:\ProgramData\DunderCorp\Artifacts\Creds\support_hashes.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Get-ChildItem C:\Users\ADMIN\Desktop -Force
"@ -MinDaysAgo 2 -MaxDaysAgo 8
}

function Seed-LabShareArtifacts {
    Write-Step "Seeding LabShare artifacts"

    Write-SeededTextFile -Path (Join-Path $LabSharePublic "printer_inventory.txt") -Content @"
Printer Inventory
-----------------
print-core-01   10.20.14.22
print-west-01   10.20.14.23
print-east-01   10.20.14.24
"@ -MinDaysAgo 11 -MaxDaysAgo 28

    Write-SeededTextFile -Path (Join-Path $LabSharePublic "migration_todo.txt") -Content @"
Migration TODO
--------------
- verify backup utility host list
- retire old telemetry notes
- confirm admin startup helpers removed after image refresh
"@ -MinDaysAgo 5 -MaxDaysAgo 14

    Write-SeededTextFile -Path (Join-Path $LabShareUsers "support_contacts.txt") -Content @"
Support Contacts
----------------
ADMIN
USER
USER2
svc_backup
svc_install
"@ -MinDaysAgo 7 -MaxDaysAgo 18

    Write-SeededTextFile -Path (Join-Path $LabShareDrop "readme.txt") -Content @"
Drop Share
----------
Temporary exchange area for support files.
Do not leave long-term exports here.
"@ -MinDaysAgo 2 -MaxDaysAgo 6
}

function Seed-AdminDesktopAndDocs {
    Write-Step "Seeding ADMIN desktop and document artifacts"

    Write-SeededTextFile -Path (Join-Path $AdminDesktop "Infra\server_list.txt") -Content @"
backup-srv01.dundercorp.local
finance-srv01.dundercorp.local
mgmt-srv01.dundercorp.local
proxy01.dundercorp.local
"@ -MinDaysAgo 9 -MaxDaysAgo 20

    Write-SeededTextFile -Path (Join-Path $AdminDesktop "Infra\host_aliases.csv") -Content @"
Alias,IP
mgmt-srv01,10.10.10.10
finance-srv01,10.10.10.20
backup-srv01,10.10.10.50
"@ -MinDaysAgo 9 -MaxDaysAgo 20

    Write-SeededTextFile -Path (Join-Path $AdminDesktop "Scripts\restart-services.ps1") -Content @"
Get-Service DunderTelemetry,WinRM,sshd | Restart-Service
"@ -MinDaysAgo 3 -MaxDaysAgo 8

    Write-SeededTextFile -Path (Join-Path $AdminDesktop "Scripts\collect-logs.ps1") -Content @"
Get-ChildItem C:\ProgramData\DunderCorp -Recurse -Include *.log,*.txt
"@ -MinDaysAgo 4 -MaxDaysAgo 10

    Write-SeededTextFile -Path (Join-Path $AdminDesktop "Quarterly Review\action_items.txt") -Content @"
Q1 Action Items
---------------
- validate backup rotations
- remove old unattend backups from field machines
- confirm telemetry rails before April image push
"@ -MinDaysAgo 7 -MaxDaysAgo 15

    Write-SeededTextFile -Path (Join-Path $AdminDesktop "Quarterly Review\backup-followup.txt") -Content @"
Backup Follow-up
----------------
Need final sign-off on legacy sync retirement.
"@ -MinDaysAgo 6 -MaxDaysAgo 12

    Write-SeededTextFile -Path (Join-Path $AdminDesktop "To Sort\old-ops-notes.txt") -Content @"
Old Ops Notes
-------------
Need to move remaining hash cache out of ProgramData after migration.
"@ -MinDaysAgo 15 -MaxDaysAgo 28

    Write-SeededTextFile -Path (Join-Path $AdminDesktop "Archive\old-server-list-2025.txt") -Content @"
legacy-web-02
legacy-proxy-01
filesrv-old
"@ -MinDaysAgo 20 -MaxDaysAgo 35

    Write-SeededTextFile -Path (Join-Path $AdminDesktop "todo.txt") -Content @"
- clear old review notes
- recheck startup helpers
- move exports off desktop
"@ -MinDaysAgo 2 -MaxDaysAgo 5

    Write-SeededTextFile -Path (Join-Path $AdminDocuments "Maintenance Notes.txt") -Content @"
Maintenance Notes
-----------------
Local telemetry and cache-refresh items are still on this workstation for testing.
Check ProgramData before cleanup.
"@ -MinDaysAgo 5 -MaxDaysAgo 12

    Write-SeededTextFile -Path (Join-Path $AdminDocuments "infra-overview.txt") -Content @"
Infra Overview
--------------
Primary internal hosts:
- mgmt-srv01.dundercorp.local
- backup-srv01.dundercorp.local
- finance-srv01.dundercorp.local
"@ -MinDaysAgo 8 -MaxDaysAgo 16

    Write-SeededTextFile -Path (Join-Path $AdminDocuments "review-questions.txt") -Content @"
Review Questions
----------------
- Why are old support hashes still staged locally?
- Who owns cleanup for telemetry cache?
"@ -MinDaysAgo 3 -MaxDaysAgo 7
}

function Seed-User2DesktopAndDocs {
    Write-Step "Seeding USER2 desktop and document artifacts"

    Write-SeededTextFile -Path (Join-Path $User2Desktop "Tickets\ticket-1042.txt") -Content @"
Ticket 1042
-----------
User reports old deployment files still visible under ProgramData.
Escalate if services restart unexpectedly.
"@ -MinDaysAgo 4 -MaxDaysAgo 9

    Write-SeededTextFile -Path (Join-Path $User2Desktop "Tickets\ticket-1061.txt") -Content @"
Ticket 1061
-----------
Customer asked whether old backup utility exports can be removed from desktop.
"@ -MinDaysAgo 2 -MaxDaysAgo 6

    Write-SeededTextFile -Path (Join-Path $User2Desktop "Exports\hosts_to_check.txt") -Content @"
Hosts To Check
--------------
10.10.10.10
10.10.10.20
10.10.10.50
"@ -MinDaysAgo 5 -MaxDaysAgo 11

    Write-SeededTextFile -Path (Join-Path $User2Desktop "Exports\printer-export.csv") -Content @"
Printer,Queue,Status
print-core-01,PRN-204,Active
print-west-01,PRN-221,Review
"@ -MinDaysAgo 4 -MaxDaysAgo 8

    Write-SeededTextFile -Path (Join-Path $User2Desktop "VPN\vpn_notes.txt") -Content @"
VPN Notes
---------
Approved destinations:
- backup-srv01.dundercorp.local
- finance-srv01.dundercorp.local
"@ -MinDaysAgo 6 -MaxDaysAgo 13

    Write-SeededTextFile -Path (Join-Path $User2Desktop "Old Notes\migration.txt") -Content @"
Migration
---------
Telemetry helper still references old backup naming.
Need to confirm cleanup after deploy.
"@ -MinDaysAgo 12 -MaxDaysAgo 24

    Write-SeededTextFile -Path (Join-Path $User2Desktop "Temp\desktop-scratch.txt") -Content @"
scratch:
- ask ADMIN about old startup helper
- move export after review
"@ -MinDaysAgo 1 -MaxDaysAgo 3

    Write-SeededTextFile -Path (Join-Path $User2Desktop "readme-first.txt") -Content @"
Desktop Notes
-------------
Most of the useful stuff is either in Tickets, Exports, or ProgramData.
"@ -MinDaysAgo 1 -MaxDaysAgo 4

    Write-SeededTextFile -Path (Join-Path $User2Documents "ticket_queue.csv") -Content @"
Ticket,Owner,Status
1042,USER2,Open
1049,USER2,Waiting
1057,USER2,Review
"@ -MinDaysAgo 4 -MaxDaysAgo 10

    Write-SeededTextFile -Path (Join-Path $User2Documents "support_reminders.txt") -Content @"
Support Reminders
-----------------
- check DunderTelemetry after patching
- confirm cache task runs after login
- move temp exports off desktop
"@ -MinDaysAgo 2 -MaxDaysAgo 6

    Write-SeededTextFile -Path (Join-Path $User2Documents "finance-hosts.txt") -Content @"
finance-srv01.dundercorp.local
finance-db01.dundercorp.local
"@ -MinDaysAgo 7 -MaxDaysAgo 15
}

function Seed-UserDesktopAndDocs {
    Write-Step "Seeding USER desktop and document artifacts"

    Write-SeededTextFile -Path (Join-Path $UserDesktop "Projects\desktop-shortlist.txt") -Content @"
Desktop Shortlist
-----------------
- quarterly export cleanup
- archive screenshots
- move notes into Reference
"@ -MinDaysAgo 5 -MaxDaysAgo 11

    Write-SeededTextFile -Path (Join-Path $UserDesktop "Projects\cleanup-plan.txt") -Content @"
Cleanup Plan
------------
- move old host notes
- review screenshot folder
- sort export references
"@ -MinDaysAgo 4 -MaxDaysAgo 9

    Write-SeededTextFile -Path (Join-Path $UserDesktop "Reference\host_aliases.txt") -Content @"
mgmt-srv01 = 10.10.10.10
finance-srv01 = 10.10.10.20
backup-srv01 = 10.10.10.50
"@ -MinDaysAgo 6 -MaxDaysAgo 15

    Write-SeededTextFile -Path (Join-Path $UserDesktop "Reference\share-notes.txt") -Content @"
Public  = broad read
Users   = authenticated read
Drop    = authenticated write
"@ -MinDaysAgo 3 -MaxDaysAgo 7

    Write-SeededTextFile -Path (Join-Path $UserDesktop "Downloads To File\inbox-review.txt") -Content @"
Need to file:
- old onboarding notes
- screenshot bundle
- host alias draft
"@ -MinDaysAgo 2 -MaxDaysAgo 5

    Write-SeededTextFile -Path (Join-Path $UserDesktop "Old\desktop-2025.txt") -Content @"
2025 leftovers
--------------
- retire onboarding shortcuts
- archive temp notes
"@ -MinDaysAgo 16 -MaxDaysAgo 30

    Write-SeededTextFile -Path (Join-Path $UserDesktop "reference-todo.txt") -Content @"
- check WinRM notes
- verify SSH artifacts
- keep LabShare tidy
"@ -MinDaysAgo 1 -MaxDaysAgo 4

    Write-SeededTextFile -Path (Join-Path $UserDocuments "desktop_tasks.txt") -Content @"
Desktop Tasks
-------------
- clean ProgramData notes
- verify SMB share list
- review startup helpers
"@ -MinDaysAgo 3 -MaxDaysAgo 7

    Write-SeededTextFile -Path (Join-Path $UserDocuments "it-onboarding-draft.txt") -Content @"
Onboarding Draft
----------------
- map core shares
- verify WinRM path
- review SSH defaults
"@ -MinDaysAgo 8 -MaxDaysAgo 18
}

function Setup-Artifacts {
    Ensure-BaseLayout
    Ensure-DesktopFolders
    Seed-ProgramDataArtifacts
    Seed-PowerShellHistory
    Seed-LabShareArtifacts
    Seed-AdminDesktopAndDocs
    Seed-User2DesktopAndDocs
    Seed-UserDesktopAndDocs

    Write-Step "Setup complete"
}

function Verify-Artifacts {
    Write-Step "ProgramData artifact root"
    if (Test-Path $Root) {
        Get-ChildItem $Root -Recurse -ErrorAction SilentlyContinue |
            Select-Object FullName, Length, LastWriteTime |
            Format-Table -Wrap -AutoSize
    }

    Write-Step "Core intel files"
    foreach ($f in @($AgentConf, $UnattendBackup, $SupportHashes, $InstallLog, $OpsNotes, $TranscriptFile, $User2History, $AdminHistory)) {
        if (Test-Path $f) {
            Get-Item $f | Select-Object FullName, Length, LastWriteTime | Format-List
        }
    }

    Write-Step "Desktop folders"
    foreach ($desktop in @($AdminDesktop, $User2Desktop, $UserDesktop)) {
        if (Test-Path $desktop) {
            Write-Host ""
            Write-Host "[$desktop]"
            Get-ChildItem $desktop -Force -ErrorAction SilentlyContinue |
                Select-Object Name, Mode, Length, LastWriteTime |
                Format-Table -AutoSize
        }
    }

    Write-Step "Documents folders"
    foreach ($docs in @($AdminDocuments, $User2Documents, $UserDocuments)) {
        if (Test-Path $docs) {
            Write-Host ""
            Write-Host "[$docs]"
            Get-ChildItem $docs -Force -ErrorAction SilentlyContinue |
                Select-Object Name, Mode, Length, LastWriteTime |
                Format-Table -AutoSize
        }
    }

    Write-Step "LabShare artifacts"
    foreach ($dir in @($LabSharePublic, $LabShareUsers, $LabShareDrop)) {
        if (Test-Path $dir) {
            Write-Host ""
            Write-Host "[$dir]"
            Get-ChildItem $dir -Force -ErrorAction SilentlyContinue |
                Select-Object Name, Length, LastWriteTime |
                Format-Table -AutoSize
        }
    }

    Write-Step "Suggested review paths"
    Write-Host @"
C:\ProgramData\DunderCorp\Artifacts
C:\Users\ADMIN\Desktop
C:\Users\ADMIN\Documents
C:\Users\USER2\Desktop
C:\Users\USER2\Documents
C:\Users\USER\Desktop
C:\Users\USER\Documents
C:\LabShare\Public
C:\LabShare\Users
C:\LabShare\Drop
"@
}

function Reset-Artifacts {
    Write-Step "Removing ProgramData artifacts"
    Remove-IfExists $Root

    Write-Step "Removing seeded PowerShell history"
    Remove-IfExists $User2History
    Remove-IfExists $AdminHistory

    Write-Step "Removing LabShare seeded files"
    foreach ($f in @(
        (Join-Path $LabSharePublic "printer_inventory.txt"),
        (Join-Path $LabSharePublic "migration_todo.txt"),
        (Join-Path $LabShareUsers "support_contacts.txt"),
        (Join-Path $LabShareDrop "readme.txt")
    )) {
        Remove-IfExists $f
    }

    Write-Step "Removing seeded desktop/document content"
    foreach ($p in @(
        (Join-Path $AdminDesktop "Infra"),
        (Join-Path $AdminDesktop "Quarterly Review"),
        (Join-Path $AdminDesktop "Scripts"),
        (Join-Path $AdminDesktop "To Sort"),
        (Join-Path $AdminDesktop "Archive"),
        (Join-Path $AdminDesktop "todo.txt"),

        (Join-Path $User2Desktop "Tickets"),
        (Join-Path $User2Desktop "Exports"),
        (Join-Path $User2Desktop "Temp"),
        (Join-Path $User2Desktop "VPN"),
        (Join-Path $User2Desktop "Old Notes"),
        (Join-Path $User2Desktop "readme-first.txt"),

        (Join-Path $UserDesktop "Projects"),
        (Join-Path $UserDesktop "Downloads To File"),
        (Join-Path $UserDesktop "Screenshots"),
        (Join-Path $UserDesktop "Old"),
        (Join-Path $UserDesktop "Reference"),
        (Join-Path $UserDesktop "reference-todo.txt"),

        (Join-Path $AdminDocuments "Maintenance Notes.txt"),
        (Join-Path $AdminDocuments "infra-overview.txt"),
        (Join-Path $AdminDocuments "review-questions.txt"),

        (Join-Path $User2Documents "ticket_queue.csv"),
        (Join-Path $User2Documents "support_reminders.txt"),
        (Join-Path $User2Documents "finance-hosts.txt"),

        (Join-Path $UserDocuments "desktop_tasks.txt"),
        (Join-Path $UserDocuments "it-onboarding-draft.txt")
    )) {
        Remove-IfExists $p
    }

    Write-Step "Reset complete"
}

if (-not ($Setup -or $Verify -or $Reset)) {
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\artifacts.ps1 -Setup"
    Write-Host "  .\artifacts.ps1 -Verify"
    Write-Host "  .\artifacts.ps1 -Reset"
    exit 1
}

if ($Reset) {
    Reset-Artifacts
}

if ($Setup) {
    Setup-Artifacts
}

if ($Verify) {
    Verify-Artifacts
}',	'[]',	'{}',	60,	'1',	'2026-04-15 00:56:47.694408+00',	'-Setup -Verify',	'vulnerable'),
('64856b8e-2eca-432e-906b-eb985ee186b9',	'winrm',	'WinRm',	'Configures a deliberate WinRM exposure for vulnerability-lab use by enabling PowerShell remoting, setting the WinRM service to start automatically, and granting a chosen non-admin user (default USER2) remote management logon rights via the Remote Management Users group. In its default path it provisions WinRM over HTTP on 5985; with -EnableHttps, it additionally creates a self-signed certificate, reconfigures the HTTPS listener on 5986, and opens the corresponding firewall rule, making the host remotely reachable for WinRM-based authentication and post-auth access testing.',	'Network Services',	'windows',	'intermediate',	'param(
    [switch]$Setup,
    [switch]$Verify,
    [switch]$Reset,
    [switch]$EnableHttps,
    [string]$WinRMUser = "USER2"
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Ensure-PrivateProfile {
    Write-Step "Setting active network profile(s) to Private"
    Get-NetConnectionProfile | ForEach-Object {
        if ($_.NetworkCategory -ne "Private") {
            Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private
        }
    }
}

function Add-User-To-RemoteManagementUsers {
    param([string]$Username)

    $group = "Remote Management Users"
    $existing = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "\\$Username$" }

    if (-not $existing) {
        Add-LocalGroupMember -Group $group -Member $Username
    }
}

function Remove-HttpsListener {
    $listeners = ""
    try {
        $listeners = winrm enumerate winrm/config/listener 2>$null | Out-String
    } catch {
        return
    }

    if ($listeners -match "Transport = HTTPS") {
        try {
            winrm delete ''winrm/config/Listener?Address=*+Transport=HTTPS'' 2>$null | Out-Null
        } catch {
        }
    }
}

function Configure-WinRM {
    Ensure-PrivateProfile

    Write-Step "Enabling PowerShell remoting / WinRM"
    Enable-PSRemoting -Force

    Write-Step "Ensuring WinRM service is automatic and running"
    Set-Service -Name WinRM -StartupType Automatic
    Start-Service WinRM

    Write-Step "Adding $WinRMUser to Remote Management Users"
    Add-User-To-RemoteManagementUsers -Username $WinRMUser

    if ($EnableHttps) {
        Write-Step "Creating self-signed certificate for WinRM HTTPS"
        $cert = New-SelfSignedCertificate `
            -DnsName $env:COMPUTERNAME, "localhost" `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -FriendlyName "WinRM HTTPS Lab"

        Write-Step "Resetting HTTPS listener"
        Remove-HttpsListener

        Write-Step "Configuring WinRM HTTPS listener"
        # Let winrm quickconfig create the HTTPS listener using the available cert
        cmd /c "winrm quickconfig -transport:https -quiet"

        Write-Step "Ensuring WinRM HTTPS firewall rule exists"
        if (-not (Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule `
                -DisplayName "Windows Remote Management (HTTPS-In)" `
                -Direction Inbound `
                -Action Allow `
                -Protocol TCP `
                -LocalPort 5986 | Out-Null
        }
    }

    Write-Step "Setup complete"
}

function Reset-WinRM {
    Write-Step "Removing HTTPS listener if present"
    Remove-HttpsListener

    Write-Step "Removing WinRM HTTPS firewall rule if present"
    try {
        Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTPS-In)" -ErrorAction SilentlyContinue |  
            Remove-NetFirewallRule
    } catch {
    }

    Write-Step "Disabling PowerShell remoting"
    Disable-PSRemoting -Force | Out-Null

    Write-Step "Stopping and disabling WinRM service"
    try { Stop-Service WinRM -Force -ErrorAction SilentlyContinue } catch {}
    Set-Service -Name WinRM -StartupType Disabled

    Write-Step "Reset complete"
}

function Show-Verification {
    Write-Step "WinRM service"
    Get-Service WinRM |
        Select-Object Name, Status, StartType |
        Format-Table -AutoSize

    Write-Step "WinRM listeners"
    try {
        winrm enumerate winrm/config/listener
    } catch {
        Write-Warning "Could not enumerate WinRM listeners."
    }

    Write-Step "Listening ports"
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object LocalPort -in 5985,5986 |
        Select-Object LocalAddress, LocalPort, State, OwningProcess |
        Format-Table -AutoSize

    Write-Step "WinRM firewall rules"
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object DisplayName -like "*Windows Remote Management*" |
        Select-Object DisplayName, Enabled, Direction, Action |
        Format-Table -AutoSize

    Write-Step "Test-WSMan localhost"
    try {
        Test-WSMan localhost
    } catch {
        Write-Warning "Test-WSMan localhost failed: $($_.Exception.Message)"
    }

    Write-Step "Remote Management Users membership"
    try {
        Get-LocalGroupMember "Remote Management Users" |
            Select-Object Name, PrincipalSource |
            Format-Table -AutoSize
    } catch {
        Write-Warning "Could not enumerate Remote Management Users."
    }

    Write-Step "WSMan client TrustedHosts"
    try {
        Get-Item WSMan:\localhost\Client\TrustedHosts | Format-List
    } catch {
        Write-Warning "Could not read TrustedHosts."
    }

    Write-Step "Suggested external tests"
    Write-Host @"
Kali / Linux-first tests:

# Basic port checks
nc -vz <VM-IP> 5985
nc -vz <VM-IP> 5986

# Nmap
nmap -sV -Pn -p 5985,5986 <VM-IP>
nmap --script http-title,http-headers -p 5985,5986 <VM-IP>

# Evil-WinRM
evil-winrm -i <VM-IP> -u $WinRMUser -p ''<PASSWORD>''

# NetExec / CrackMapExec style checks
netexec winrm <VM-IP> -u $WinRMUser -p ''<PASSWORD>''
crackmapexec winrm <VM-IP> -u $WinRMUser -p ''<PASSWORD>''

# PowerShell remoting from a Windows client (optional)
Test-WSMan <VM-IP>
`$password = ConvertTo-SecureString ''<PASSWORD>'' -AsPlainText -Force
`$creds = New-Object System.Management.Automation.PSCredential(''.\$WinRMUser'', `$password)
Invoke-Command -ComputerName <VM-IP> -Credential `$creds -ScriptBlock { whoami }
"@

    Write-Step "Interpretation hints"
    Write-Host @"
- 5985 = WinRM over HTTP
- 5986 = WinRM over HTTPS
- Kali students will usually use evil-winrm or netexec/crackmapexec
- TrustedHosts mainly matters for Windows PowerShell clients using IP-based remoting
- Valid credentials do not always imply remoting rights unless the user is an admin or in Remote Management Users
"@
}

if (-not ($Setup -or $Verify -or $Reset)) {
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\winrm.ps1 -Setup"
    Write-Host "  .\winrm.ps1 -Verify"
    Write-Host "  .\winrm.ps1 -Reset"
    Write-Host "  .\winrm.ps1 -Setup -EnableHttps"
    Write-Host "  .\winrm.ps1 -Setup -WinRMUser USER2"
    exit 1
}

if ($Reset) {
    Reset-WinRM
}

if ($Setup) {
    Configure-WinRM
}

if ($Verify) {
    Show-Verification
}',	'["WinRM/5985"]',	'{USER2,CHOSEN_USER_ADDITIONAL_FLAG}',	60,	'1',	'2026-04-15 01:01:02.164505+00',	'-Setup -Verify',	'vulnerable'),
('3cb19c80-47e8-4043-ab45-2a6cbb3e1235',	'win-smb-null-session',	'SMB Null Session',	'- enumerate shares
- try null/no-pass
- use valid creds
- compare access denied vs nonexistent shares
- manually probe `IPC$`, `ADMIN$`, `C$`
- use `enum4linux`, `rpcclient`, `smbmap`, `nmap smb-enum-*` where available',	'Network Services',	'windows',	'intermediate',	'param(
    [switch]$Setup,
    [switch]$Verify,
    [switch]$Reset,
    [switch]$EnableNullSession
)

$ErrorActionPreference = "Stop"

$BasePath = "C:\LabShare"
$ShareNames = @("Public","Users","Drop","LabShare")

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Ensure-Folder {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-Share-IfExists {
    param([string]$Name)
    $existing = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-SmbShare -Name $Name -Force
    }
}

function Reset-Share {
    param(
        [string]$Name,
        [string]$Path,
        [string[]]$ReadAccess = @(),
        [string[]]$ChangeAccess = @(),
        [string[]]$FullAccess = @()
    )

    Remove-Share-IfExists -Name $Name

    $params = @{
        Name = $Name
        Path = $Path
    }

    if ($ReadAccess.Count -gt 0)   { $params["ReadAccess"]   = $ReadAccess }
    if ($ChangeAccess.Count -gt 0) { $params["ChangeAccess"] = $ChangeAccess }
    if ($FullAccess.Count -gt 0)   { $params["FullAccess"]   = $FullAccess }

    New-SmbShare @params | Out-Null
}

function Configure-Network-Baseline {
    Write-Step "Setting active network profile(s) to Private"
    Get-NetConnectionProfile | ForEach-Object {
        if ($_.NetworkCategory -ne "Private") {
            Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private
        }
    }

    Write-Step "Enabling SMB / File Sharing firewall rules"
    Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Out-Null
}

function Configure-SmbLab {
    Configure-Network-Baseline

    Write-Step "Creating folders"
    Ensure-Folder $BasePath
    Ensure-Folder "$BasePath\Public"
    Ensure-Folder "$BasePath\Users"
    Ensure-Folder "$BasePath\Drop"

    Write-Step "Setting NTFS permissions"

    # Public: everyone read
    icacls "$BasePath\Public" /inheritance:r `
        /grant:r "Everyone:(OI)(CI)RX" "Administrators:(OI)(CI)F" | Out-Null

    # Users: authenticated/local users read
    icacls "$BasePath\Users" /inheritance:r `
        /grant:r "Users:(OI)(CI)RX" "Administrators:(OI)(CI)F" | Out-Null

    # Drop: authenticated/local users modify
    icacls "$BasePath\Drop" /inheritance:r `
        /grant:r "Users:(OI)(CI)M" "Administrators:(OI)(CI)F" | Out-Null

    Write-Step "Creating SMB shares"
    Reset-Share -Name "Public" -Path "$BasePath\Public" -ReadAccess @("Everyone") -FullAccess @("Administrators")
    Reset-Share -Name "Users"  -Path "$BasePath\Users"  -ReadAccess @("Users")    -FullAccess @("Administrators")
    Reset-Share -Name "Drop"   -Path "$BasePath\Drop"   -ChangeAccess @("Users")   -FullAccess @("Administrators")

    if ($EnableNullSession) {
        Write-Step "Enabling anonymous/null-session lab mode"

        New-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            -Name "NullSessionShares" `
            -PropertyType MultiString `
            -Value @("Public") `
            -Force | Out-Null

        New-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            -Name "RestrictNullSessAccess" `
            -PropertyType DWord `
            -Value 0 `
            -Force | Out-Null

        New-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "RestrictAnonymous" `
            -PropertyType DWord `
            -Value 0 `
            -Force | Out-Null
    }
    else {
        Write-Step "Leaving anonymous/null-session mode disabled"
    }

    Write-Step "Setup complete"
}

function Reset-SmbLab {
    Write-Step "Removing SMB shares"
    foreach ($name in $ShareNames) {
        Remove-Share-IfExists -Name $name
    }

    Write-Step "Resetting null-session related settings to safer defaults"

    try {
        Remove-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            -Name "NullSessionShares" `
            -ErrorAction SilentlyContinue
    } catch {
    }

    New-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "RestrictNullSessAccess" `
        -PropertyType DWord `
        -Value 1 `
        -Force | Out-Null

    New-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictAnonymous" `
        -PropertyType DWord `
        -Value 1 `
        -Force | Out-Null

    Write-Step "Leaving folders in place"
    Write-Host "Folders under $BasePath were not deleted."
    Write-Host "Run -Setup to recreate the lab shares cleanly."
}

function Show-Verification {
    Write-Step "SMB listeners"
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object LocalPort -in 445,139 |
        Select-Object LocalAddress, LocalPort, State |
        Format-Table -AutoSize

    Write-Step "Shares"
    Get-SmbShare |
        Where-Object Name -in "Public","Users","Drop","IPC$","ADMIN$","C$","LabShare" |
        Select-Object Name, Path, Description |
        Format-Table -AutoSize

    Write-Step "Share-level permissions"
    foreach ($share in @("Public","Users","Drop")) {
        $exists = Get-SmbShare -Name $share -ErrorAction SilentlyContinue
        if ($exists) {
            Write-Host ""
            Write-Host "[$share]"
            Get-SmbShareAccess -Name $share |
                Select-Object Name, ScopeName, AccountName, AccessControlType, AccessRight |
                Format-Table -AutoSize
        }
    }

    Write-Step "NTFS permissions"
    foreach ($path in @("$BasePath\Public", "$BasePath\Users", "$BasePath\Drop")) {
        if (Test-Path $path) {
            Write-Host ""
            Write-Host "[$path]"
            icacls $path
        }
    }

    Write-Step "SMB server settings"
    Get-SmbServerConfiguration |
        Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature |
        Format-List

    Write-Step "Anonymous / null-session related settings"
    Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction SilentlyContinue |
        Select-Object NullSessionShares, RestrictNullSessAccess |
        Format-List

    Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue |
        Select-Object RestrictAnonymous |
        Format-List

    Write-Step "Current SMB sessions"
    Get-SmbSession -ErrorAction SilentlyContinue |
        Select-Object SessionId, ClientComputerName, ClientUserName, NumOpens |
        Format-Table -AutoSize

    Write-Step "Current SMB open files"
    Get-SmbOpenFile -ErrorAction SilentlyContinue |
        Select-Object ClientComputerName, ClientUserName, Path, ShareRelativePath |
        Format-Table -AutoSize

    Write-Step "Suggested external tests"
    Write-Host @"
HackTricks-style tests to run from another host:

# Null / anonymous share listing
smbclient -L //<VM-IP> -N

# Authenticated share listing
smbclient -L //<VM-IP> -U USER
smbclient -L //<VM-IP> -U USER2

# Connect to a share
smbclient //<VM-IP>/Public -U USER2
smbclient //<VM-IP>/Users  -U USER2
smbclient //<VM-IP>/Drop   -U USER2

# Recursive / permission-oriented checks
smbclient //<VM-IP>/Users -U USER2 -c ''recurse;ls''
smbclient //<VM-IP>/Drop  -U USER2 -c ''recurse;ls''

# Manual common share probing
smbclient //<VM-IP>/IPC$   -U USER2
smbclient //<VM-IP>/ADMIN$ -U USER2
smbclient //<VM-IP>/C$     -U USER2

# Better enumeration tooling if available
enum4linux -a <VM-IP>
enum4linux-ng -A <VM-IP>
nmap --script "safe or smb-enum-*" -p 445 <VM-IP>
rpcclient -U "USER2%PASSWORD" <VM-IP>
smbmap -u "USER2" -p "PASSWORD" -H <VM-IP>
"@

    Write-Step "Interpretation hints"
    Write-Host @"
- NT_STATUS_ACCESS_DENIED often means the share exists but access is blocked.
- NT_STATUS_BAD_NETWORK_NAME usually means the share name does not exist.
- Share permissions and NTFS permissions are separate; both matter.
- IPC$, ADMIN$, and C$ are useful manual probes even when list output is restricted.
"@
}

if (-not ($Setup -or $Verify -or $Reset)) {
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\configure_smb.ps1 -Setup"
    Write-Host "  .\configure_smb.ps1 -Verify"
    Write-Host "  .\configure_smb.ps1 -Reset"
    Write-Host "  .\configure_smb.ps1 -Setup -EnableNullSession"
    exit 1
}

if ($Reset) {
    Reset-SmbLab
}

if ($Setup) {
    Configure-SmbLab
}

if ($Verify) {
    Show-Verification
}',	'["445/SMB"]',	'{}',	60,	'1',	'2026-04-15 00:42:17.958954+00',	'-Setup -Verify -EnableNullSession',	'vulnerable'),
('3c61e322-ec7c-49e2-94a2-62dcc172415e',	'win-persistence',	'persistence',	'Creates three Windows persistence artifacts tied to logon/startup execution: an HKLM\Software\Microsoft\Windows\CurrentVersion\Run entry (DunderOpsUpdate) that launches wscript.exe against opshelper.vbs, a Startup folder CMD artifact (DunderStartup.cmd), and a SYSTEM scheduled task (DunderUserEnvSync) triggered onlogon to execute userenv_sync.ps1. It stages supporting files and logs under C:\ProgramData\DunderCorp\Persistence, applies read-oriented ACLs to keep the persistence layer non-writable by standard users, and includes verification and teardown routines for all created artifacts.',	'Network Services',	'windows',	'intermediate',	'param(
    [switch]$Setup,
    [switch]$Verify,
    [switch]$Reset
)

$ErrorActionPreference = "Stop"

$Root            = "C:\ProgramData\DunderCorp\Persistence"
$BinDir          = Join-Path $Root "bin"
$ScriptsDir      = Join-Path $Root "scripts"
$LogsDir         = Join-Path $Root "logs"

$RunValueName    = "DunderOpsUpdate"
$TaskName        = "DunderUserEnvSync"

$OpsHelperVbs    = Join-Path $BinDir "opshelper.vbs"
$SyncScript      = Join-Path $ScriptsDir "userenv_sync.ps1"
$RunLog          = Join-Path $LogsDir "opshelper.log"
$TaskLog         = Join-Path $LogsDir "userenv_sync.log"

$StartupCmd      = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\DunderStartup.cmd"
$StartupLog      = Join-Path $LogsDir "startup.log"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-IfExists {
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Force -Recurse
    }
}

function Write-TextFile {
    param(
        [string]$Path,
        [string]$Content,
        [string]$Encoding = "ASCII"
    )

    $parent = Split-Path $Path -Parent
    if ($parent) {
        Ensure-Dir $parent
    }

    Set-Content -Path $Path -Value $Content -Encoding $Encoding
}

function Ensure-BaseLayout {
    foreach ($d in @($Root, $BinDir, $ScriptsDir, $LogsDir)) {
        Ensure-Dir $d
    }
}

function Protect-PersistenceFiles {
    Write-Step "Applying read-oriented ACLs to persistence files"

    if (Test-Path $Root) {
        icacls $Root /inheritance:r | Out-Null
        icacls $Root /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" "Users:(OI)(CI)(RX)" | Out-Null
    }

    foreach ($f in @($OpsHelperVbs, $SyncScript, $StartupCmd)) {
        if (Test-Path $f) {
            icacls $f /grant:r "SYSTEM:(F)" "Administrators:(F)" "Users:(RX)" | Out-Null
        }
    }
}

function Seed-PersistenceHelpers {
    Write-Step "Seeding persistence helper files"

    Write-TextFile -Path $OpsHelperVbs -Encoding ASCII -Content @"
Set oShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
logPath = "$RunLog"
Set f = fso.OpenTextFile(logPath, 8, True)
f.WriteLine Now & " [RUNKEY] DunderOpsUpdate launched"
f.Close
"@

    Write-TextFile -Path $SyncScript -Encoding ASCII -Content @"
`$ErrorActionPreference = ''SilentlyContinue''
"`$(Get-Date -Format s) [TASK] DunderUserEnvSync executed as $env:USERNAME" | Out-File "$TaskLog" -Append -Encoding ascii
"`$(Get-Date -Format s) [TASK] Syncing environment markers" | Out-File "$TaskLog" -Append -Encoding ascii
"@

    Write-TextFile -Path $StartupCmd -Encoding ASCII -Content @"
@echo off
echo %date% %time% [STARTUP] Dunder startup helper >> "$StartupLog"
"@
}

function Ensure-RunKey {
    Write-Step "Creating HKLM Run-key persistence entry"

    New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Force | Out-Null
    New-ItemProperty `
        -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name $RunValueName `
        -Value "wscript.exe `"$OpsHelperVbs`"" `
        -PropertyType String `
        -Force | Out-Null
}

function Ensure-StartupArtifact {
    Write-Step "Ensuring startup-folder persistence artifact"
    if (-not (Test-Path $StartupCmd)) {
        throw "Startup command file was not created."
    }
}

function Ensure-LogonTask {
    Write-Step "Creating scheduled task persistence entry"

    try {
        schtasks /delete /tn "\$TaskName" /f 2>$null | Out-Null
    } catch {}

    $taskCmd = ''powershell.exe -NoProfile -ExecutionPolicy Bypass -File "'' + $SyncScript + ''"''

    schtasks /create `
        /tn "\$TaskName" `
        /sc onlogon `
        /ru SYSTEM `
        /rl HIGHEST `
        /tr $taskCmd `
        /f | Out-Null
}

function Setup-Persistence {
    Ensure-BaseLayout
    Seed-PersistenceHelpers
    Ensure-RunKey
    Ensure-StartupArtifact
    Ensure-LogonTask
    Protect-PersistenceFiles

    Write-Step "Setup complete"
}

function Reset-Persistence {
    Write-Step "Removing scheduled task"
    try {
        schtasks /delete /tn "\$TaskName" /f 2>$null | Out-Null
    } catch {}

    Write-Step "Removing HKLM Run-key entry"
    try {
        Remove-ItemProperty `
            -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" `
            -Name $RunValueName `
            -ErrorAction SilentlyContinue
    } catch {}

    Write-Step "Removing startup-folder artifact"
    Remove-IfExists $StartupCmd

    Write-Step "Removing persistence data root"
    Remove-IfExists $Root

    Write-Step "Reset complete"
}

function Verify-Persistence {
    Write-Step "HKLM Run-key entry"
    try {
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
            Select-Object $RunValueName |
            Format-List
    } catch {
        Write-Warning "Could not read HKLM Run key."
    }

    Write-Step "Startup-folder artifact"
    if (Test-Path $StartupCmd) {
        Get-Item $StartupCmd |
            Select-Object FullName, Length, LastWriteTime |
            Format-List
        icacls $StartupCmd
    } else {
        Write-Warning "Startup artifact not found."
    }

    Write-Step "Scheduled task persistence"
    try {
        schtasks /query /tn "\$TaskName" /fo LIST /v
    } catch {
        Write-Warning "Scheduled task query failed."
    }

    Write-Step "Helper files"
    foreach ($f in @($OpsHelperVbs, $SyncScript)) {
        if (Test-Path $f) {
            Get-Item $f |
                Select-Object FullName, Length, LastWriteTime |
                Format-List
            icacls $f
        }
    }

    Write-Step "Recent persistence logs"
    foreach ($log in @($RunLog, $StartupLog, $TaskLog)) {
        if (Test-Path $log) {
            Write-Host ""
            Write-Host "[$log]"
            Get-Content $log -Tail 10
        }
    }

    Write-Step "Suggested enumeration"
    Write-Host @"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
schtasks /query /fo LIST /v | findstr /i Dunder
Get-CimInstance Win32_StartupCommand
Get-ChildItem "$Root" -Recurse
"@

    Write-Step "Notes"
    Write-Host @"
- This script owns persistence mechanisms, not privesc rails.
- $RunValueName is the HKLM Run-key entry.
- \${TaskName} is the scheduled-task persistence entry.
- $StartupCmd is the startup-folder artifact.
- File ACLs are intentionally read-oriented so this layer is persistence, not another privesc rail.
"@
}

if (-not ($Setup -or $Verify -or $Reset)) {
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\persistence.ps1 -Setup"
    Write-Host "  .\persistence.ps1 -Verify"
    Write-Host "  .\persistence.ps1 -Reset"
    exit 1
}

if ($Reset) {
    Reset-Persistence
}

if ($Setup) {
    Setup-Persistence
}

if ($Verify) {
    Verify-Persistence
}',	'["N/A"]',	'{}',	60,	'1',	'2026-04-15 00:50:43.946655+00',	'-Setup -Verify',	'vulnerable'),
('ce4b15e1-4fc1-40d7-bc7a-d4e166624ba3',	'win-priv-esc',	'Windows PrivEsc',	'Builds a Windows local privilege-escalation lab layer by creating two primary SYSTEM execution rails: a scheduled task (DunderCacheRefresh) that runs refresh_cache.ps1 every minute as SYSTEM, and a weak service (DunderTelemetry) whose ImagePath executes telemetry_service.ps1 as LocalSystem. It intentionally makes key execution points user-modifiable—specifically preflight.ps1, refresh_cache.ps1, and the service registry key under HKLM\SYSTEM\CurrentControlSet\Services\DunderTelemetry—while also staging supporting persistence artifacts, credential/intel files, logs, and PowerShell history under C:\ProgramData\DunderCorp\Privesc for post-exploitation enumeration and collection.',	'Privilege Escalation',	'windows',	'beginner',	'param(
    [switch]$Setup,
    [switch]$Verify,
    [switch]$Reset
)

$ErrorActionPreference = "Stop"

$Root              = "C:\ProgramData\DunderCorp\Privesc"
$SvcDir            = Join-Path $Root "svc"
$HooksDir          = Join-Path $Root "hooks"
$TasksDir          = Join-Path $Root "tasks"
$CredsDir          = Join-Path $Root "creds"
$ArtifactsDir      = Join-Path $Root "artifacts"
$LogsDir           = Join-Path $Root "logs"
$TranscriptDir     = Join-Path $Root "transcripts"
$BinDir            = Join-Path $Root "bin"

$ServiceName       = "DunderTelemetry"
$TaskName          = "DunderCacheRefresh"
$RunValueName      = "DunderOpsUpdate"

$TelemetryScript   = Join-Path $SvcDir "telemetry_service.ps1"
$PreflightScript   = Join-Path $HooksDir "preflight.ps1"
$RefreshScript     = Join-Path $TasksDir "refresh_cache.ps1"
$OpsHelperVbs      = Join-Path $BinDir "opshelper.vbs"
$StartupCmd        = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\DunderStartup.cmd"

$AgentConf         = Join-Path $ArtifactsDir "agent.conf"
$UnattendBackup    = Join-Path $ArtifactsDir "staged_unattend.xml.bak"
$OpsNotes          = Join-Path $ArtifactsDir "ops_notes.txt"
$SupportHashes     = Join-Path $CredsDir "support_hashes.txt"
$InstallLog        = Join-Path $LogsDir "install.log"
$TranscriptFile    = Join-Path $TranscriptDir "PowerShell_transcript-DunderOps.txt"
$ServiceLog        = Join-Path $LogsDir "telemetry_service.log"
$TaskLog           = Join-Path $LogsDir "cache_refresh.log"

$User2History      = "C:\Users\USER2\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
$AdminHistory      = "C:\Users\ADMIN\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-IfExists {
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Force -Recurse
    }
}

function Write-TextFile {
    param(
        [string]$Path,
        [string]$Content,
        [string]$Encoding = "UTF8"
    )

    $parent = Split-Path $Path -Parent
    if ($parent) {
        Ensure-Dir $parent
    }

    Set-Content -Path $Path -Value $Content -Encoding $Encoding
}

function Grant-UsersModify {
    param([string]$Path)
    if (Test-Path $Path) {
        icacls $Path /grant "Users:(M)" | Out-Null
    }
}

function Grant-UsersModifyRecursive {
    param([string]$Path)
    if (Test-Path $Path) {
        icacls $Path /grant "Users:(OI)(CI)(M)" | Out-Null
    }
}

function Grant-UsersReadRecursive {
    param([string]$Path)
    if (Test-Path $Path) {
        icacls $Path /grant "Users:(OI)(CI)(RX)" | Out-Null
    }
}

function Ensure-BaseLayout {
    foreach ($d in @($Root,$SvcDir,$HooksDir,$TasksDir,$CredsDir,$ArtifactsDir,$LogsDir,$TranscriptDir,$BinDir)) {
        Ensure-Dir $d
    }
}

function Seed-HelperScripts {
    Write-Step "Seeding helper scripts"

    Write-TextFile -Path $TelemetryScript -Encoding ASCII -Content @"
`$ErrorActionPreference = ''SilentlyContinue''
"`$(Get-Date -Format s) [SERVICE] DunderTelemetry invoked as $env:USERNAME" | Out-File "$ServiceLog" -Append -Encoding ascii
if (Test-Path "$PreflightScript") {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PreflightScript" *>> "$ServiceLog"
}
Start-Sleep -Seconds 2
"@

    Write-TextFile -Path $PreflightScript -Encoding ASCII -Content @"
"`$(Get-Date -Format s) [HOOK] Preflight checks completed" | Out-File "$ServiceLog" -Append -Encoding ascii
"`$(Get-Date -Format s) [HOOK] Inventory sync placeholder" | Out-File "$ServiceLog" -Append -Encoding ascii
"@

    Write-TextFile -Path $RefreshScript -Encoding ASCII -Content @"
"`$(Get-Date -Format s) [TASK] Cache refresh executed as $env:USERNAME" | Out-File "$TaskLog" -Append -Encoding ascii
"`$(Get-Date -Format s) [TASK] Pulling staged config from DunderCorp" | Out-File "$TaskLog" -Append -Encoding ascii
"@

    Write-TextFile -Path $OpsHelperVbs -Encoding ASCII -Content @"
Set oShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
logPath = "$LogsDir\opshelper.log"
Set f = fso.OpenTextFile(logPath, 8, True)
f.WriteLine Now & " [RUNKEY] DunderOpsUpdate launched"
f.Close
"@

    Grant-UsersModify $PreflightScript
    Grant-UsersModify $RefreshScript
    Grant-UsersReadRecursive $SvcDir
    Grant-UsersReadRecursive $BinDir
}

function Seed-Artifacts {
    Write-Step "Seeding credential and persistence artifacts"

    Write-TextFile -Path $AgentConf -Content @"
[telemetry]
ServiceName=DunderTelemetry
TaskName=DunderCacheRefresh
HookPath=$PreflightScript
TaskScript=$RefreshScript

[internal]
BackupHost=backup-srv01.dundercorp.local
MgmtHost=mgmt-srv01.dundercorp.local
FinanceHost=finance-srv01.dundercorp.local

[creds]
SupportHashFile=$SupportHashes
PreferredUser=svc_backup
"@

    Write-TextFile -Path $OpsNotes -Content @"
Operations Notes
----------------
- Legacy telemetry still depends on preflight hooks under ProgramData.
- Cache refresh task survives reboot and runs under SYSTEM for patch prep.
- Review startup persistence entries before quarterly image refresh.
- Retire old unattend backups after migration closes.
"@

    Write-TextFile -Path $UnattendBackup -Content @"
<unattend>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup">
      <AutoLogon>
        <Enabled>false</Enabled>
        <Username>svc_deploy</Username>
        <Password>
          <Value>LabDeploy2026!</Value>
          <PlainText>true</PlainText>
        </Password>
      </AutoLogon>
    </component>
  </settings>
</unattend>
"@

    Write-TextFile -Path $SupportHashes -Encoding ASCII -Content @"
# Lab-only hash material
# Format: account:NTLM
svc_backup:DE769E624BFE51CB4109255F0F1E0910
svc_install:51B056A8B2C13AEFE10D95EF051EF70A
legacy_sync:C65FF5F2633515BCA9B3370DD709074A
"@

    Write-TextFile -Path $InstallLog -Content @"
[2026-03-01 14:00:01] INFO  DunderOps maintenance package installed
[2026-03-01 14:00:05] INFO  Telemetry service registered as LocalSystem
[2026-03-01 14:00:08] INFO  Cache refresh task registered as SYSTEM
[2026-03-01 14:00:11] INFO  Legacy deployment backup copied to $UnattendBackup
[2026-03-01 14:00:14] INFO  Hash cache staged at $SupportHashes
"@

    Write-TextFile -Path $TranscriptFile -Content @"
**********************
Windows PowerShell transcript start
Start time: 20260323174200
Username  : WINDOWS\ADMIN
RunAs User: WINDOWS\ADMIN
Machine   : WIN11LAB
**********************
PS> schtasks /query /tn $TaskName /v /fo list
PS> sc.exe qc $ServiceName
PS> reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
PS> icacls $PreflightScript
PS> icacls $RefreshScript
**********************
Windows PowerShell transcript end
**********************
"@

    Grant-UsersReadRecursive $ArtifactsDir
    Grant-UsersReadRecursive $CredsDir
    Grant-UsersReadRecursive $TranscriptDir
    Grant-UsersReadRecursive $LogsDir
}

function Seed-PowerShellHistory {
    Write-Step "Seeding PowerShell history"

    Write-TextFile -Path $User2History -Content @"
whoami /priv
Get-Service $ServiceName
schtasks /query /tn $TaskName /fo list /v
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ChildItem C:\ProgramData\DunderCorp -Recurse
"@

    Write-TextFile -Path $AdminHistory -Content @"
sc.exe qc $ServiceName
sc.exe sdshow $ServiceName
schtasks /run /tn $TaskName
icacls $PreflightScript
icacls $RefreshScript
Get-Content $SupportHashes
"@
}

function Ensure-RunKeyPersistence {
    Write-Step "Creating HKLM Run-key persistence artifact"
    New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Force | Out-Null
    New-ItemProperty `
        -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name $RunValueName `
        -Value "wscript.exe `"$OpsHelperVbs`"" `
        -PropertyType String `
        -Force | Out-Null
}

function Ensure-StartupPersistence {
    Write-Step "Creating startup-folder persistence artifact"
    Write-TextFile -Path $StartupCmd -Encoding ASCII -Content @"
@echo off
echo %date% %time% [STARTUP] Dunder startup helper >> "$LogsDir\startup.log"
"@
}

function Ensure-SYSTEMTask {
    Write-Step "Creating SYSTEM scheduled task"

    try {
        schtasks /delete /tn "\$TaskName" /f 2>$null | Out-Null
    } catch {}

    $taskCmd = ''powershell.exe -NoProfile -ExecutionPolicy Bypass -File "'' + $RefreshScript + ''"''

    schtasks /create `
        /tn "\$TaskName" `
        /sc minute `
        /mo 1 `
        /ru SYSTEM `
        /rl HIGHEST `
        /tr $taskCmd `
        /f | Out-Null

    Grant-UsersModify $RefreshScript
}

function Ensure-TelemetryService {
    Write-Step "Creating weak SYSTEM service rail"

    try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 1

    # Remove any existing service cleanly
    $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingSvc) {
        try { & sc.exe delete $ServiceName | Out-Null } catch {}
        Start-Sleep -Seconds 2
    }

    $binPath = "C:\Windows\System32\cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$TelemetryScript`""

    # Create the service reliably
    New-Service `
        -Name $ServiceName `
        -BinaryPathName $binPath `
        -DisplayName "DunderCorp Telemetry Service" `
        -Description "Legacy DunderCorp telemetry maintenance runner" `
        -StartupType Manual | Out-Null

    Start-Sleep -Seconds 1

    # Confirm it exists before continuing
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        throw "Service $ServiceName was not created successfully."
    }

    # Allow authenticated users to query/start/stop/interrogate
    try {
        $sddl = ''D:(A;;CCLCSWRPWPLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLOCRRC;;;AU)''
        & sc.exe sdset $ServiceName $sddl | Out-Null
    } catch {
        Write-Warning ("Failed to set service SDDL on {0}: {1}" -f $ServiceName, $_.Exception.Message)
    }

    Grant-UsersModify $PreflightScript

    $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    try {
        if (-not (Test-Path $svcRegPath)) {
            throw "Service registry path does not exist after creation."
        }

        $acl = Get-Acl $svcRegPath
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "Users",
            "FullControl",
            "ContainerInherit",
            "None",
            "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $svcRegPath -AclObject $acl
    } catch {
        Write-Warning ("Failed to weaken service registry ACL on {0}: {1}" -f $svcRegPath, $_.Exception.Message)
    }
}

function Setup-PrivescLayer {
    Ensure-BaseLayout
    Seed-HelperScripts
    Seed-Artifacts
    Seed-PowerShellHistory
    Ensure-RunKeyPersistence
    Ensure-StartupPersistence
    Ensure-SYSTEMTask
    Ensure-TelemetryService

    Write-Step "Setup complete"
}

function Reset-PrivescLayer {
    Write-Step "Removing scheduled task"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

    Write-Step "Removing weak service"
    try { & sc.exe stop $ServiceName | Out-Null } catch {}
    Start-Sleep -Seconds 1
    try { & sc.exe delete $ServiceName | Out-Null } catch {}

    Write-Step "Removing persistence entries"
    try {
        Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $RunValueName -ErrorAction SilentlyContinue
    } catch {}
    Remove-IfExists $StartupCmd

    Write-Step "Removing seeded history files"
    Remove-IfExists $User2History
    Remove-IfExists $AdminHistory

    Write-Step "Removing privesc data root"
    Remove-IfExists $Root

    Write-Step "Reset complete"
}

function Show-RegistryAcl {
    param([string]$Path)

    try {
        Get-Acl $Path |
            Select-Object -ExpandProperty Access |
            Select-Object IdentityReference, RegistryRights, AccessControlType, IsInherited |
            Format-Table -AutoSize
    } catch {
        Write-Warning "Could not read ACL for $Path"
    }
}

function Verify-PrivescLayer {
    Write-Step "Service rail"
    try {
        Get-Service -Name $ServiceName -ErrorAction SilentlyContinue |
            Select-Object Name, Status, StartType |
            Format-Table -AutoSize
    } catch {
        Write-Warning "Service $ServiceName not found."
    }

    try {
        & sc.exe qc $ServiceName
        & sc.exe sdshow $ServiceName
    } catch {}

    Write-Host ""
    Write-Host "[Service registry ACL]"
    Show-RegistryAcl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

    Write-Host ""
    Write-Host "[Service scripts ACLs]"
    if (Test-Path $TelemetryScript) { icacls $TelemetryScript }
    if (Test-Path $PreflightScript) { icacls $PreflightScript }

    Write-Step "Scheduled task rail"
    try {
        Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
            Select-Object TaskName, State, TaskPath |
            Format-Table -AutoSize
        Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue |
            Select-Object LastRunTime, NextRunTime, LastTaskResult |
            Format-Table -AutoSize
    } catch {
        Write-Warning "Task $TaskName not found."
    }

    Write-Host ""
    Write-Host "[Task script ACL]"
    if (Test-Path $RefreshScript) { icacls $RefreshScript }

    Write-Step "Persistence artifacts"
    try {
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
            Select-Object $RunValueName |
            Format-List
    } catch {}
    if (Test-Path $StartupCmd) {
        Get-Item $StartupCmd | Select-Object FullName, Length, LastWriteTime | Format-List
    }

    Write-Step "Seeded files"
    Get-ChildItem $Root -Recurse -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime |
        Format-Table -Wrap -AutoSize

    Write-Step "Credential and intel files"
    foreach ($f in @($AgentConf,$UnattendBackup,$SupportHashes,$InstallLog,$TranscriptFile,$User2History,$AdminHistory)) {
        if (Test-Path $f) {
            Get-Item $f | Select-Object FullName, Length, LastWriteTime | Format-List
        }
    }

    Write-Step "Suggested local enumeration"
    Write-Host @"
whoami /priv
Get-Service $ServiceName
sc.exe qc $ServiceName
sc.exe sdshow $ServiceName
reg query HKLM\System\CurrentControlSet\Services\$ServiceName
schtasks /query /tn $TaskName /fo LIST /v
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
dir `"$Root`" /s
icacls `"$PreflightScript`"
icacls `"$RefreshScript`"
type `"$SupportHashes`"
"@

    Write-Step "Notes"
    Write-Host @"
- $TaskName is the clean SYSTEM task rail.
- $ServiceName is an intentionally fragile legacy service rail.
- Starting $ServiceName may return a service error, but its ImagePath still executes as SYSTEM before failing.
- The data under $Root is non-sensitive lab material.
"@
}

if (-not ($Setup -or $Verify -or $Reset)) {
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\privesc.ps1 -Setup"
    Write-Host "  .\privesc.ps1 -Verify"
    Write-Host "  .\privesc.ps1 -Reset"
    exit 1
}

if ($Reset) {
    Reset-PrivescLayer
}

if ($Setup) {
    Setup-PrivescLayer
}

if ($Verify) {
    Verify-PrivescLayer
}',	'[]',	'{}',	60,	'1',	'2026-04-15 00:54:34.582353+00',	'-Setup -Verify',	'vulnerable'),
('7b64e19e-b4f9-4b20-9c6e-ad0b291822c9',	'win-life-artifacts',	'Life Artifacts',	'Adds Users/Artifacts to the machine',	'User Simulation',	'windows',	'intermediate',	'$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Ensure-LocalUser {
    param([string]$Username, [string]$Password, [switch]$AddToAdministrators)
    $existing = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Step "Creating local user $Username"
        $secure = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $Username -Password $secure -FullName $Username -Description "Lab account $Username" -PasswordNeverExpires -AccountNeverExpires | Out-Null
    } else {
        Write-Step "User $Username already exists"
    }
    if ($AddToAdministrators) {
        $isMember = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\\$Username$" }
        if (-not $isMember) {
            Write-Step "Adding $Username to Administrators"
            Add-LocalGroupMember -Group "Administrators" -Member $Username
        }
    }
}

function Write-TextFile {
    param([string]$Path, [string]$Content)
    $parent = Split-Path $Path -Parent
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Set-Content -Path $Path -Value $Content -Encoding UTF8
}

# Create users
Ensure-LocalUser -Username "USER2" -Password "User2Pass123!"
Ensure-LocalUser -Username "ADMIN" -Password "AdminPass123!" -AddToAdministrators

# Create profile folders
Write-Step "Creating profile folders"
foreach ($u in @("USER2","ADMIN")) {
    foreach ($folder in @("C:\Users\$u", "C:\Users\$u\Desktop", "C:\Users\$u\Documents", "C:\Users\$u\Documents\scripts", "C:\Users\$u\Downloads")) {
        if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    }
}

foreach ($folder in @("C:\LabShare", "C:\LabShare\Public", "C:\LabShare\Legacy", "C:\ProgramData\Ops")) {
    if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
}

# Seed USER2 artifacts
Write-Step "Seeding USER2 artifacts"
Write-TextFile -Path "C:\Users\USER2\Documents\vpn_notes.txt" -Content @"
VPN Notes
Primary concentrator: vpn-gw01
Fallback concentrator: vpn-gw02
Split tunnel exceptions requested for: 10.20.14.0/24, 10.30.5.0/24
Need to verify whether old inventory portal is still reachable internally.
"@

Write-TextFile -Path "C:\Users\USER2\Documents\hosts_to_check.txt" -Content @"
Hosts to check
10.20.14.15    filesrv-old
10.20.14.22    print-core
10.30.5.18     backup-util
10.30.5.41     web-training
"@

Write-TextFile -Path "C:\Users\USER2\Desktop\Q1-Inventory.csv" -Content @"
Hostname,Role,Owner,Status
WIN11LAB-EDGE,Training Workstation,IT Ops,Active
filesrv-old,Legacy File Server,Infrastructure,Pending Migration
backup-util,Backup Utility Host,Ops,Review
web-training,Training Web Node,Security,Active
"@

# Seed ADMIN artifacts
Write-Step "Seeding ADMIN artifacts"
Write-TextFile -Path "C:\Users\ADMIN\Desktop\Maintenance Notes.txt" -Content @"
Maintenance Notes
- Legacy training apps moved to local bootstrap script.
- Backup utility review still pending.
- Remove temporary exceptions after migration window closes.
- Confirm old deployment batch files no longer used by support.
- Revisit local admin assignments on training systems.
"@

Write-TextFile -Path "C:\Users\ADMIN\Documents\scripts\restart-services.ps1" -Content @''
$services = @("W3SVC","WinRM","sshd")
foreach ($svc in $services) {
    try { Restart-Service -Name $svc -Force -ErrorAction Stop } catch { Write-Host "Failed to restart $svc" }
}
''@

# Seed shared artifacts
Write-Step "Seeding shared artifacts"
Write-TextFile -Path "C:\ProgramData\Ops\migration_todo.txt" -Content @"
Migration TODO
- Validate training app startup after reboot.
- Review old support scripts in LabShare\Legacy.
- Confirm backup utility host list is still accurate.
- Remove leftover temporary admin changes after QA signoff.
"@

# Set basic ownership
try { icacls "C:\Users\USER2" /grant "USER2:(OI)(CI)F" /T | Out-Null } catch {}
try { icacls "C:\Users\ADMIN" /grant "ADMIN:(OI)(CI)F" /T | Out-Null } catch {}

Write-Host ""
Write-Host "=== Life Artifacts Complete ==="
Write-Host "Users: USER2 (standard), ADMIN (local administrator)"
Write-Host "Artifacts seeded in: C:\Users\USER2, C:\Users\ADMIN, C:\LabShare, C:\ProgramData\Ops"
',	'[]',	'{}',	60,	'1',	'2026-04-13 20:44:23.435424+00',	'',	'baseline'),
('c41e0bb8-e666-40aa-8fa1-560b97ec31bc',	'win-owasp-setup',	'Setup OWASP',	'Setup a OWASP Web Server',	'Web Server',	'windows',	'intermediate',	'$ErrorActionPreference = "Stop"

$LabRoot       = "C:\LabApps"
$InstallersDir = Join-Path $LabRoot "installers"
$ToolsDir      = Join-Path $LabRoot "tools"
$JavaToolsDir  = Join-Path $ToolsDir "java23"
$NodeToolsDir  = Join-Path $ToolsDir "node20"
$WebGoatDir    = Join-Path $LabRoot "WebGoat"
$JuiceDir      = Join-Path $LabRoot "JuiceShop"
$VulnDir       = Join-Path $LabRoot "targets\VulnServer"
$LogsDir       = Join-Path $LabRoot "logs"
$StateDir      = Join-Path $LabRoot "state"
$ConfigPath    = Join-Path $StateDir "runtime.json"

$ProgressLog = "C:\LabApps\progress.log"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
    Add-Content -Path $ProgressLog -Value "[$(Get-Date -Format ''HH:mm:ss'')] $Message" -ErrorAction SilentlyContinue
}

function Get-OnlyChildDir {
    param([string]$Path)
    $dirs = Get-ChildItem $Path -Directory -ErrorAction SilentlyContinue
    if ($dirs.Count -eq 1) { return $dirs[0].FullName }
    $match = $dirs | Where-Object { Test-Path (Join-Path $_.FullName "bin\java.exe") -or Test-Path (Join-Path $_.FullName "node.exe") -or Test-Path (Join-Path $_.FullName "package.json") } | Select-Object -First 1
    if ($match) { return $match.FullName }
    return $null
}

# Create dirs
foreach ($d in @($LogsDir, $StateDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# Verify downloads exist
$javaZip = Join-Path $InstallersDir "temurin23.zip"
$nodeMsi = Join-Path $InstallersDir "node.msi"
$webGoatJar = Join-Path $WebGoatDir "webgoat.jar"
$juiceZip = Join-Path $InstallersDir "juiceshop.zip"
$vulnExe = Join-Path $VulnDir "vulnserver.exe"

$missing = @()
if (-not (Test-Path $javaZip)) { $missing += "temurin23.zip" }
if (-not (Test-Path $nodeMsi)) { $missing += "node.msi" }
if (-not (Test-Path $webGoatJar)) { $missing += "webgoat.jar" }
if (-not (Test-Path $juiceZip)) { $missing += "juiceshop.zip" }
if (-not (Test-Path $vulnExe)) { $missing += "vulnserver.exe" }

if ($missing.Count -gt 0) {
    Write-Host "ERROR: Missing files - run owasp-download first:"
    $missing | ForEach-Object { Write-Host "  - $_" }
    [Environment]::Exit(1)
}

# Extract Java
$javaExe = $null
Write-Step "Extracting Java 23..."
if (-not (Test-Path "$JavaToolsDir\*")) {
    Expand-Archive -Path $javaZip -DestinationPath $JavaToolsDir -Force
}
$javaRoot = Get-OnlyChildDir -Path $JavaToolsDir
if ($javaRoot) { $javaExe = Join-Path $javaRoot "bin\java.exe" }
if (-not $javaExe -or -not (Test-Path $javaExe)) { throw "Java not found after extraction" }
Write-Host "  Java: $javaExe"

# Install Node via MSI
$nodeExe = $null
Write-Step "Installing Node.js..."
$nodeCheck = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCheck) {
    Start-Process msiexec.exe -ArgumentList "/i `"$nodeMsi`" /quiet /norestart" -Wait
    Start-Sleep -Seconds 3
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
}
$nodeCheck = Get-Command node -ErrorAction SilentlyContinue
if ($nodeCheck) {
    $nodeExe = $nodeCheck.Source
} else {
    # Check common install locations
    $candidates = @("C:\Program Files\nodejs\node.exe", "C:\Program Files (x86)\nodejs\node.exe")
    foreach ($c in $candidates) { if (Test-Path $c) { $nodeExe = $c; break } }
}
if (-not $nodeExe -or -not (Test-Path $nodeExe)) { throw "Node not found after install" }
Write-Host "  Node: $nodeExe"

# Extract Juice Shop
$juiceRoot = $null
Write-Step "Extracting Juice Shop..."
$juiceDirs = Get-ChildItem $JuiceDir -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "package.json") }
if (-not $juiceDirs -or $juiceDirs.Count -eq 0) {
    Expand-Archive -Path $juiceZip -DestinationPath $JuiceDir -Force
    $juiceDirs = Get-ChildItem $JuiceDir -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "package.json") }
}
if ($juiceDirs) { $juiceRoot = $juiceDirs[0].FullName }
if (-not $juiceRoot) { throw "Juice Shop not found after extraction" }
Write-Host "  Juice Shop: $juiceRoot"

# Firewall rules
Write-Step "Adding firewall rules"
foreach ($rule in @(@{Name="WebGoat 8080";Port=8080}, @{Name="Juice Shop 3000";Port=3000}, @{Name="VulnServer 9999";Port=9999})) {
    if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $rule.Port | Out-Null
    }
}

# Save config
$config = [pscustomobject]@{
    JavaExe       = $javaExe
    NodeExe       = $nodeExe
    WebGoatJar    = $webGoatJar
    JuiceRoot     = $juiceRoot
    VulnServerExe = $vulnExe
}
$config | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8

Write-Host ""
Write-Host "=== Setup Complete ==="
Write-Host "Java:       $javaExe"
Write-Host "Node:       $nodeExe"
Write-Host "WebGoat:    $webGoatJar"
Write-Host "JuiceShop:  $juiceRoot"
Write-Host "VulnServer: $vulnExe"
Write-Host ""
Write-Host "Next: Run the ''owasp-start'' script to launch all services."
',	'["3000", "8080"]',	'{}',	60,	'1',	'2026-04-13 20:48:24.139219+00',	'-Setup',	'baseline'),
('e2dd2bdd-c943-42a2-a90e-b7c96fa27f00',	'win-install-480-services',	'Install 480 Services',	'Installs IIS (port 80 corporate landing + port 8080 health monitor dashboard), FTP with anonymous read on /logs that leak usernames and service info, configures SQL Server 2019 Express (sets SA password SQLAdmin2024!, enables xp_cmdshell, creates hr_database with 20 employees/payroll/PII and a system_credentials table that''s a goldmine), and enables WinRM + RDP.

Installs and configures IIS (80 + 8080), FTP (21), MSSQL (1433),
    WinRM (5985), and RDP (3389) on the MedAlliance-WIN Tier 1 target.',	'Network Services',	'windows',	'intermediate',	'<#
.SYNOPSIS
    Installs and configures IIS (80 + 8080), FTP (21), MSSQL (1433),
    WinRM (5985), and RDP (3389) on the MedAlliance-WIN Tier 1 target.

.NOTES
    Originally assumed Windows Server 2019 with SQL Express pre-installed.
    Now also runs on Windows 11 client SKUs (25H2) for instructor testing.

    SQL configuration is OPTIONAL — if no MSSQL* service is detected, the
    SQL section is skipped but all other artifacts (IT_Docs breadcrumb that
    references the SA password, planted creds, etc.) remain intact, so
    students still have a consistent lab story.
#>

param(
    [Parameter(Mandatory=$true)][string]$WinIP,
    [switch]$SkipSQL
)

$ErrorActionPreference = "Continue"
$script:SectionFailures = @()

function Write-Phase {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format ''HH:mm:ss'')][Services] $Msg"
}

# ═══════════════════════════════════════════════════════════════
#  0. SKU DETECTION + DEPLOY-CONTEXT MARKER
# ═══════════════════════════════════════════════════════════════
$script:OSInfo   = Get-CimInstance Win32_OperatingSystem
$script:IsServer = $script:OSInfo.ProductType -ne 1  # 1=workstation, 2=DC, 3=member server
$script:OSCaption = $script:OSInfo.Caption
Write-Host "[Prereq] Detected: $script:OSCaption (IsServer=$script:IsServer)"

# Persist a small marker file so the sibling scripts don''t have to re-detect.
$ctxDir = "C:\ProgramData\MedAlliance"
if (-not (Test-Path $ctxDir)) { New-Item -Path $ctxDir -ItemType Directory -Force | Out-Null }
$ctxPath = Join-Path $ctxDir "deploy-context.json"
$ctx = @{
    OSCaption = $script:OSCaption
    IsServer  = $script:IsServer
    WinIP     = $WinIP
    Timestamp = (Get-Date).ToString("s")
}
$ctx | ConvertTo-Json | Set-Content -Path $ctxPath -Encoding UTF8
Write-Phase "Wrote deploy context marker: $ctxPath"

# ═══════════════════════════════════════════════════════════════
#  Helper: Install-MedFeature — branches Server vs Client feature API
# ═══════════════════════════════════════════════════════════════
# On Server SKUs: Install-WindowsFeature <ServerName> -IncludeManagementTools
# On Client SKUs: Enable-WindowsOptionalFeature -Online -FeatureName <ClientName> -NoRestart
function Install-MedFeature {
    param(
        [Parameter(Mandatory=$true)][string]$ServerName,
        [Parameter(Mandatory=$true)][string]$ClientName
    )
    try {
        if ($script:IsServer) {
            if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
                Install-WindowsFeature -Name $ServerName -IncludeManagementTools -ErrorAction SilentlyContinue | Out-Null
                Write-Phase "  [Feature:Server] $ServerName enabled."
            } else {
                Write-Warning "  [Feature:Server] Install-WindowsFeature unavailable for $ServerName"
            }
        } else {
            if (Get-Command Enable-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
                $state = (Get-WindowsOptionalFeature -Online -FeatureName $ClientName -ErrorAction SilentlyContinue).State
                if ($state -ne ''Enabled'') {
                    Enable-WindowsOptionalFeature -Online -FeatureName $ClientName -NoRestart -All -ErrorAction SilentlyContinue | Out-Null
                    Write-Phase "  [Feature:Client] $ClientName enabled."
                } else {
                    Write-Phase "  [Feature:Client] $ClientName already enabled."
                }
            } else {
                Write-Warning "  [Feature:Client] Enable-WindowsOptionalFeature unavailable for $ClientName"
            }
        }
    } catch {
        Write-Warning "  [Feature] Could not enable $ServerName/$ClientName : $_"
    }
}

# ═══════════════════════════════════════════════════════════════
#  1. IIS + FTP FEATURE INSTALLATION
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Starting IIS/FTP feature install..."

    # Core IIS
    Install-MedFeature -ServerName ''Web-Server''         -ClientName ''IIS-WebServer''
    Install-MedFeature -ServerName ''Web-Common-Http''    -ClientName ''IIS-CommonHttpFeatures''
    Install-MedFeature -ServerName ''Web-Default-Doc''    -ClientName ''IIS-DefaultDocument''
    Install-MedFeature -ServerName ''Web-Dir-Browsing''   -ClientName ''IIS-DirectoryBrowsing''
    Install-MedFeature -ServerName ''Web-Http-Errors''    -ClientName ''IIS-HttpErrors''
    Install-MedFeature -ServerName ''Web-Static-Content'' -ClientName ''IIS-StaticContent''
    Install-MedFeature -ServerName ''Web-Http-Logging''   -ClientName ''IIS-HttpLogging''
    Install-MedFeature -ServerName ''Web-Stat-Compression'' -ClientName ''IIS-HttpCompressionStatic''
    Install-MedFeature -ServerName ''Web-Filtering''      -ClientName ''IIS-RequestFiltering''
    Install-MedFeature -ServerName ''Web-Asp-Net45''      -ClientName ''IIS-ASPNET45''
    Install-MedFeature -ServerName ''Web-Net-Ext45''      -ClientName ''IIS-NetFxExtensibility45''
    Install-MedFeature -ServerName ''Web-ISAPI-Ext''      -ClientName ''IIS-ISAPIExtensions''
    Install-MedFeature -ServerName ''Web-ISAPI-Filter''   -ClientName ''IIS-ISAPIFilter''
    Install-MedFeature -ServerName ''Web-Mgmt-Console''   -ClientName ''IIS-ManagementConsole''

    # FTP
    Install-MedFeature -ServerName ''Web-Ftp-Server''     -ClientName ''IIS-FTPServer''
    Install-MedFeature -ServerName ''Web-Ftp-Service''    -ClientName ''IIS-FTPSvc''
    Install-MedFeature -ServerName ''Web-Ftp-Ext''        -ClientName ''IIS-FTPExtensibility''

    Write-Phase "[Section] IIS/FTP features completed."
} catch {
    Write-Warning "[Section] IIS/FTP feature install failed: $_"
    $script:SectionFailures += ''IIS-Features''
}

# ═══════════════════════════════════════════════════════════════
#  2. IIS SITE CONFIGURATION (default + HealthMonitor on 8080)
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Starting IIS site configuration..."

    if (-not (Get-Module -ListAvailable WebAdministration)) {
        Write-Warning "[IIS] WebAdministration module not available — IIS site config skipped."
        $script:SectionFailures += ''IIS-Sites''
    } else {
        Import-Module WebAdministration -ErrorAction Stop

        # ── Default site on port 80: corporate landing page ──
        $wwwroot = "C:\inetpub\wwwroot"
        if (-not (Test-Path $wwwroot)) {
            New-Item -Path $wwwroot -ItemType Directory -Force | Out-Null
        }

        # Remove default IIS pages (only if present)
        Remove-Item "$wwwroot\iisstart.htm" -Force -ErrorAction SilentlyContinue
        Remove-Item "$wwwroot\iisstart.png" -Force -ErrorAction SilentlyContinue

        $landingPage = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MedAlliance Health Partners</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:''Segoe UI'',system-ui,sans-serif;background:#f0f2f5;color:#333}
.nav{background:#0a2540;color:#fff;padding:16px 32px;display:flex;align-items:center;gap:16px}
.nav h1{font-size:18px;font-weight:600}
.nav .tag{background:#e94560;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600}
.wrap{max-width:900px;margin:40px auto;padding:0 20px}
.card{background:#fff;border-radius:12px;padding:32px;margin-bottom:24px;
      box-shadow:0 1px 3px rgba(0,0,0,.08);border:1px solid #e8e8e8}
.card h2{font-size:16px;color:#0a2540;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid #eee}
.card p{line-height:1.7;color:#555;margin-bottom:12px}
.services{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-top:16px}
.svc{background:#f8f9fb;border:1px solid #eee;border-radius:8px;padding:16px}
.svc h3{font-size:14px;color:#0a2540;margin-bottom:4px}
.svc p{font-size:13px;color:#888;margin:0}
.svc .port{display:inline-block;background:#e8f4fd;color:#0066cc;padding:1px 8px;
           border-radius:4px;font-size:12px;font-family:monospace;margin-top:8px}
.footer{text-align:center;color:#aaa;font-size:12px;padding:40px 0}
</style>
</head>
<body>
<div class="nav">
  <h1>MedAlliance Health Partners</h1>
  <span class="tag">INTERNAL</span>
</div>
<div class="wrap">
  <div class="card">
    <h2>Internal Systems Portal</h2>
    <p>Welcome to the MedAlliance Health Partners internal network. This server provides
       centralized IT services for staff. For access issues, contact IT at ext 4200 or
       <strong>it-support@medalliance.local</strong>.</p>
  </div>
  <div class="card">
    <h2>Available Services</h2>
    <div class="services">
      <div class="svc">
        <h3>Health Monitor</h3>
        <p>System status dashboard</p>
        <span class="port">:8080</span>
      </div>
      <div class="svc">
        <h3>File Shares</h3>
        <p>Company documents (SMB)</p>
        <span class="port">:445</span>
      </div>
      <div class="svc">
        <h3>HR Database</h3>
        <p>Employee records (SQL)</p>
        <span class="port">:1433</span>
      </div>
      <div class="svc">
        <h3>FTP Logs</h3>
        <p>System log archive</p>
        <span class="port">:21</span>
      </div>
      <div class="svc">
        <h3>Remote Desktop</h3>
        <p>RDP access for staff</p>
        <span class="port">:3389</span>
      </div>
      <div class="svc">
        <h3>Remote Mgmt</h3>
        <p>WinRM for IT admins</p>
        <span class="port">:5985</span>
      </div>
    </div>
  </div>
  <div class="card">
    <h2>IT Notices</h2>
    <p><strong>2024-11-10:</strong> Scheduled maintenance completed. SQL Server backups verified.
       Please report any service interruptions to IT.</p>
    <p><strong>2024-09-15:</strong> Windows Defender real-time protection has been temporarily
       disabled due to compatibility issues with the Health Monitor agent. A fix is pending
       from the vendor. <em>— M. Chen, Network Admin</em></p>
    <p><strong>2024-08-13:</strong> Automatic Windows Updates have been paused until Q1 2025
       to prevent disruption to clinical workflows during the EMR migration.</p>
  </div>
</div>
<div class="footer">
  MedAlliance Health Partners &copy; 2024 | MEDALLIANCE-WIN | IIS/10.0
</div>
</body>
</html>
"@
        Set-Content -Path "$wwwroot\index.html" -Value $landingPage -Encoding UTF8
        Write-Phase "Default site (port 80) configured."

        # ── Health Monitor dashboard on port 8080 ──
        $monitorPath = "C:\inetpub\healthmonitor"
        if (-not (Test-Path $monitorPath)) {
            New-Item -Path $monitorPath -ItemType Directory -Force | Out-Null
        }

        $loginPage = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><title>Health Monitor — Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:''Segoe UI'',sans-serif;background:#0f172a;color:#e2e8f0;
     display:flex;justify-content:center;align-items:center;min-height:100vh}
.login{background:#1e293b;border-radius:12px;padding:40px;width:380px;
       box-shadow:0 4px 24px rgba(0,0,0,.4);border:1px solid #334155}
.login h2{font-size:18px;margin-bottom:8px}
.login .sub{color:#64748b;font-size:13px;margin-bottom:28px}
label{display:block;font-size:13px;color:#94a3b8;margin-bottom:4px;margin-top:16px}
input{width:100%;padding:10px 12px;background:#0f172a;border:1px solid #334155;
      color:#e2e8f0;border-radius:6px;font-size:14px}
input:focus{outline:none;border-color:#3b82f6}
button{width:100%;padding:12px;background:#dc2626;color:#fff;border:none;
       border-radius:6px;font-size:14px;cursor:pointer;margin-top:24px;font-weight:600}
button:hover{background:#b91c1c}
.hint{color:#475569;font-size:11px;margin-top:20px;text-align:center;line-height:1.6}
</style>
</head>
<body>
<div class="login">
  <h2>Health Monitor v3.1</h2>
  <div class="sub">MEDALLIANCE-WIN &mdash; System Dashboard</div>
  <form action="dashboard.html" method="GET">
    <label for="u">Username</label>
    <input id="u" name="username" type="text" placeholder="admin" autocomplete="off">
    <label for="p">Password</label>
    <input id="p" name="password" type="password" placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;">
    <button type="submit">Sign In</button>
  </form>
  <div class="hint">
    Default credentials are documented in the IT_Docs share.<br>
    Contact IT (ext 4200) if your account is locked.
  </div>
</div>
<!-- MedAlliance Health Monitor v3.1.2 | build 2024.11.02 | ASP.NET 4.8.1 | IIS/10.0 -->
</body>
</html>
"@
        Set-Content -Path "$monitorPath\index.html" -Value $loginPage -Encoding UTF8

        $subnetRef = $WinIP -replace ''\.\d+$'', ''''  # e.g., 192.168.10
        $dashboardPage = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><title>Health Monitor — Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:''Segoe UI'',sans-serif;background:#0f172a;color:#e2e8f0}
.topbar{background:#1e293b;padding:14px 24px;display:flex;justify-content:space-between;
        align-items:center;border-bottom:2px solid #dc2626}
.topbar h1{font-size:16px;font-weight:600}
.topbar .user{color:#64748b;font-size:13px}
.topbar .user strong{color:#e2e8f0}
.content{padding:24px;max-width:1100px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:24px}
.card{background:#1e293b;border-radius:8px;padding:20px;border:1px solid #334155}
.card .label{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:8px}
.card .value{font-size:28px;font-weight:700}
.card .detail{font-size:12px;color:#475569;margin-top:6px}
.ok{color:#22c55e}.warn{color:#eab308}.crit{color:#ef4444}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;color:#64748b;font-weight:500;
   border-bottom:1px solid #334155;font-size:12px;text-transform:uppercase;letter-spacing:.5px}
td{padding:10px 12px;border-bottom:1px solid #1e293b}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.dot.g{background:#22c55e}.dot.r{background:#ef4444}.dot.y{background:#eab308}
.section{margin-bottom:24px}
.section h3{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:#dc2626;
            margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #334155}
</style>
</head>
<body>
<div class="topbar">
  <h1>MedAlliance Health Monitor</h1>
  <div class="user">Signed in as <strong>admin</strong> (System Administrator)
    &nbsp;|&nbsp; <a href="index.html" style="color:#dc2626;text-decoration:none">Logout</a></div>
</div>
<div class="content">

<div class="grid">
  <div class="card"><div class="label">Uptime</div>
    <div class="value ok">47d 13h</div>
    <div class="detail">Last reboot: 2024-10-01 03:00 (scheduled)</div></div>
  <div class="card"><div class="label">CPU</div>
    <div class="value ok">23%</div>
    <div class="detail">4 vCPU | Peak: 67% at 09:15</div></div>
  <div class="card"><div class="label">Memory</div>
    <div class="value warn">78%</div>
    <div class="detail">3.1 / 4.0 GB — MSSQL: 1.8 GB</div></div>
  <div class="card"><div class="label">Disk C:</div>
    <div class="value ok">45%</div>
    <div class="detail">18 GB / 40 GB used</div></div>
</div>

<div class="card section">
<h3>Services</h3>
<table>
<tr><th>Service</th><th>Port</th><th>Status</th><th>Configuration Notes</th></tr>
<tr><td>IIS Web Server</td><td>80, 8080</td>
    <td><span class="dot g"></span>Running</td><td>Default site + Health Monitor</td></tr>
<tr><td>SQL Server 2019 Express</td><td>1433</td>
    <td><span class="dot g"></span>Running</td>
    <td>Instance: SQLEXPRESS | SA: <strong>enabled</strong> | xp_cmdshell: enabled</td></tr>
<tr><td>FTP (IIS)</td><td>21</td>
    <td><span class="dot g"></span>Running</td>
    <td>Anonymous read enabled for /logs directory</td></tr>
<tr><td>SMB File Shares</td><td>445</td>
    <td><span class="dot g"></span>Running</td>
    <td>Company_Docs, IT_Docs (guest read) | HR_Files (auth required)</td></tr>
<tr><td>Remote Desktop</td><td>3389</td>
    <td><span class="dot g"></span>Running</td>
    <td>NLA enabled | m.chen, admin in Remote Desktop Users</td></tr>
<tr><td>WinRM</td><td>5985</td>
    <td><span class="dot g"></span>Running</td>
    <td>HTTP transport | m.chen in Remote Management Users</td></tr>
<tr><td>Windows Defender</td><td>&mdash;</td>
    <td><span class="dot r"></span>Disabled</td>
    <td style="color:#ef4444">Real-time protection OFF since 2024-09-15 (vendor compatibility)</td></tr>
<tr><td>Windows Update</td><td>&mdash;</td>
    <td><span class="dot r"></span>Paused</td>
    <td style="color:#ef4444">Last patch: KB5031361 (2024-08-13) — paused until Q1 2025</td></tr>
</table>
</div>

<div class="card section">
<h3>Recent Authentications</h3>
<table>
<tr><th>User</th><th>Source IP</th><th>Protocol</th><th>Timestamp</th><th>Result</th></tr>
<tr><td>m.chen</td><td>${subnetRef}.20</td><td>RDP</td><td>2024-11-15 08:32</td><td class="ok">Success</td></tr>
<tr><td>admin</td><td>${subnetRef}.20</td><td>WinRM</td><td>2024-11-14 16:45</td><td class="ok">Success</td></tr>
<tr><td>sa</td><td>${subnetRef}.20</td><td>MSSQL</td><td>2024-11-14 11:20</td><td class="ok">Success</td></tr>
<tr><td>ANONYMOUS</td><td>${subnetRef}.10</td><td>FTP</td><td>2024-11-13 14:10</td><td class="ok">Success</td></tr>
<tr><td>guest</td><td>${subnetRef}.10</td><td>SMB</td><td>2024-11-13 09:02</td><td class="ok">Success</td></tr>
<tr><td>j.rodriguez</td><td>${subnetRef}.20</td><td>RDP</td><td>2024-11-12 07:55</td><td class="crit">Failed (3x)</td></tr>
</table>
</div>

<div class="card section">
<h3>Databases</h3>
<table>
<tr><th>Name</th><th>Size</th><th>Tables</th><th>Last Backup</th><th>Notes</th></tr>
<tr><td>hr_database</td><td>24 MB</td><td>4</td><td>2024-11-10</td>
    <td>Employee records, payroll, reviews — <strong>contains PII</strong></td></tr>
<tr><td>app_config</td><td>2 MB</td><td>2</td><td>2024-11-10</td>
    <td>Application settings, system_users table</td></tr>
</table>
<div style="color:#475569;font-size:11px;margin-top:12px">
SQL Server 2019 Express 15.0.4385.2 | SA authentication: enabled<br>
Connection: <code>${WinIP},1433</code> | Credentials in IT_Docs share (server_setup_notes.txt)
</div>
</div>

<div class="card section">
<h3>Scheduled Tasks</h3>
<table>
<tr><th>Task</th><th>Schedule</th><th>Run As</th><th>Script Path</th><th>Last Run</th></tr>
<tr><td>Daily Report Generator</td><td>Every 15 min</td><td>NT AUTHORITY\SYSTEM</td>
    <td><code>C:\Scripts\daily_report.bat</code></td><td>2024-11-15 11:45</td></tr>
<tr><td>Health Check</td><td>Hourly</td><td>MedHealthSvc</td>
    <td><code>C:\Program Files\MedAlliance\Health Monitor\agent.exe</code></td><td>2024-11-15 11:00</td></tr>
<tr><td>Backup Job</td><td>Daily 02:00</td><td>NT AUTHORITY\SYSTEM</td>
    <td><code>C:\Scripts\backup_databases.bat</code></td><td>2024-11-15 02:00</td></tr>
</table>
</div>

</div>
</body>
</html>
"@
        Set-Content -Path "$monitorPath\dashboard.html" -Value $dashboardPage -Encoding UTF8

        # Create/refresh the IIS site on port 8080 (guarded)
        if (Get-Command Get-Website -ErrorAction SilentlyContinue) {
            if (Get-Website -Name "HealthMonitor" -ErrorAction SilentlyContinue) {
                Remove-Website -Name "HealthMonitor" -ErrorAction SilentlyContinue
            }
            New-Website -Name "HealthMonitor" -Port 8080 -PhysicalPath $monitorPath -Force | Out-Null
            Start-Website -Name "HealthMonitor" -ErrorAction SilentlyContinue
            Write-Phase "Health Monitor site (port 8080) created."
        } else {
            Write-Warning "[IIS] Get-Website unavailable — skipping HealthMonitor site creation."
        }

        Write-Phase "[Section] IIS site configuration completed."
    }
} catch {
    Write-Warning "[Section] IIS site configuration failed: $_"
    $script:SectionFailures += ''IIS-Sites''
}

# ═══════════════════════════════════════════════════════════════
#  3. FTP SERVICE (IIS FTP)
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Starting FTP configuration..."

    $ftpRoot = "C:\inetpub\ftproot"
    $ftpLogs = "$ftpRoot\logs"
    if (-not (Test-Path $ftpLogs)) {
        New-Item -Path $ftpLogs -ItemType Directory -Force | Out-Null
    }

    $subnetRef = $WinIP -replace ''\.\d+$'', ''''

    # Fake log files with info leakage
    @"
#Software: MedAlliance Health Monitor v3.1
#Date: 2024-11-15
#Fields: date time s-ip cs-username s-computername s-port cs-method result

2024-11-15 08:32:14 ${WinIP} m.chen MEDALLIANCE-WIN 3389 RDP_CONNECT SUCCESS
2024-11-15 08:45:01 ${WinIP} SYSTEM MEDALLIANCE-WIN 0 TASK_EXEC C:\Scripts\daily_report.bat
2024-11-14 16:45:22 ${subnetRef}.20 admin MEDALLIANCE-WIN 5985 WINRM_CONNECT SUCCESS
2024-11-14 11:20:33 ${subnetRef}.20 sa MEDALLIANCE-WIN 1433 SQL_AUTH SUCCESS
2024-11-13 14:10:05 ${subnetRef}.10 anonymous MEDALLIANCE-WIN 21 FTP_AUTH SUCCESS
2024-11-12 09:00:00 ${subnetRef}.20 m.chen MEDALLIANCE-WIN 445 SMB_CONNECT Company_Docs
2024-11-11 23:59:59 ${WinIP} SYSTEM MEDALLIANCE-WIN 0 BACKUP_SQL hr_database
2024-11-10 15:30:00 ${WinIP} SYSTEM MEDALLIANCE-WIN 0 SERVICE_RESTART MedHealthSvc
2024-11-10 03:00:00 ${WinIP} SYSTEM MEDALLIANCE-WIN 0 SCHTASK daily_report.bat
2024-11-09 14:22:11 ${subnetRef}.20 j.thompson MEDALLIANCE-WIN 445 SMB_CONNECT IT_Docs
"@ | Set-Content -Path "$ftpLogs\monitor_2024-11.log" -Encoding UTF8

    @"
#Software: Microsoft Internet Information Services 10.0
#Date: 2024-11-01
#Fields: date time s-ip cs-method cs-uri-stem s-port cs-username c-ip sc-status

2024-11-15 08:30:22 ${WinIP} GET / 80 - ${subnetRef}.10 200
2024-11-15 08:30:45 ${WinIP} GET /healthmonitor/ 8080 - ${subnetRef}.10 200
2024-11-14 16:00:01 ${WinIP} POST /healthmonitor/login.aspx 8080 admin ${subnetRef}.20 302
2024-11-14 11:15:33 ${WinIP} GET /healthmonitor/dashboard.html 8080 admin ${subnetRef}.20 200
2024-11-13 09:00:00 ${WinIP} GET / 80 - ${subnetRef}.20 200
"@ | Set-Content -Path "$ftpLogs\iis_access_2024-11.log" -Encoding UTF8

    @"
MedAlliance Health Partners — FTP Service
==========================================
Read-only access to system and application logs.
For authenticated file share access, use SMB (\\MEDALLIANCE-WIN).
Contact IT (ext 4200) for access requests.
"@ | Set-Content -Path "$ftpRoot\README.txt" -Encoding UTF8

    # Create FTP site with anonymous access (guarded — FTP cmdlets require WebAdministration + FTP role)
    if (-not (Get-Module -ListAvailable WebAdministration)) {
        Write-Warning "[FTP] WebAdministration module not available — FTP site creation skipped."
        $script:SectionFailures += ''FTP''
    } elseif (-not (Get-Command New-WebFtpSite -ErrorAction SilentlyContinue)) {
        Write-Warning "[FTP] New-WebFtpSite unavailable (FTP feature likely not installed) — FTP site skipped."
        $script:SectionFailures += ''FTP''
    } else {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        if (Get-Website -Name "MedAlliance-FTP" -ErrorAction SilentlyContinue) {
            Remove-WebSite -Name "MedAlliance-FTP" -ErrorAction SilentlyContinue
        }
        New-WebFtpSite -Name "MedAlliance-FTP" -Port 21 -PhysicalPath $ftpRoot -Force | Out-Null

        Set-ItemProperty "IIS:\Sites\MedAlliance-FTP" `
            -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true -ErrorAction SilentlyContinue
        Set-ItemProperty "IIS:\Sites\MedAlliance-FTP" `
            -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $false -ErrorAction SilentlyContinue

        Add-WebConfiguration "/system.ftpServer/security/authorization" `
            -PSPath "IIS:" -Location "MedAlliance-FTP" `
            -Value @{accessType="Allow"; roles=""; permissions="Read"; users="*"} -ErrorAction SilentlyContinue

        Start-Website -Name "MedAlliance-FTP" -ErrorAction SilentlyContinue
        Write-Phase "FTP configured (anonymous read on /logs)."
    }

    Write-Phase "[Section] FTP configuration completed."
} catch {
    Write-Warning "[Section] FTP configuration failed: $_"
    $script:SectionFailures += ''FTP''
}

# ═══════════════════════════════════════════════════════════════
#  4. SQL SERVER CONFIGURATION (optional — auto-detect instance)
# ═══════════════════════════════════════════════════════════════
$sqlService = Get-Service -Name ''MSSQL*'' -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -like ''MSSQL$*'' -or $_.Name -eq ''MSSQLSERVER'' } |
              Select-Object -First 1

if ($SkipSQL -or -not $sqlService) {
    Write-Warning "[SQL] Skipping — no MSSQL service present (or -SkipSQL set). IT_Docs breadcrumb still planted."
    $script:SectionFailures += ''SQL-Skipped''
} else {
    try {
        Write-Phase "[Section] Starting SQL Server configuration (service: $($sqlService.Name))..."

        # Start SQL services
        Start-Service -Name $sqlService.Name -ErrorAction SilentlyContinue
        Set-Service   -Name $sqlService.Name -StartupType Automatic -ErrorAction SilentlyContinue

        if (Get-Service -Name ''SQLBrowser'' -ErrorAction SilentlyContinue) {
            Start-Service -Name ''SQLBrowser'' -ErrorAction SilentlyContinue
            Set-Service   -Name ''SQLBrowser'' -StartupType Automatic -ErrorAction SilentlyContinue
        }

        # Derive instance short name (e.g. "MSSQL$SQLEXPRESS" → "SQLEXPRESS", "MSSQLSERVER" → "MSSQLSERVER")
        $instanceName = if ($sqlService.Name -like ''MSSQL$*'') {
            $sqlService.Name.Substring(6)
        } else {
            ''MSSQLSERVER''
        }
        $sqlServerArg = if ($instanceName -eq ''MSSQLSERVER'') { ''.'' } else { ".\$instanceName" }

        # Enable TCP/IP on port 1433 via WMI (more reliable than registry)
        try {
            $sqlWmi = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer
            $tcp = $sqlWmi.ServerInstances[$instanceName].ServerProtocols[''Tcp'']
            $tcp.IsEnabled = $true
            $tcp.Alter()
            $ipAll = $tcp.IPAddresses | Where-Object { $_.Name -eq ''IPAll'' }
            $ipAll.IPAddressProperties[''TcpPort''].Value = ''1433''
            $ipAll.IPAddressProperties[''TcpDynamicPorts''].Value = ''''
            $tcp.Alter()
            Write-Phase "SQL TCP/IP enabled on port 1433 via WMI."
        } catch {
            Write-Phase "WMI method failed, falling back to registry..."
            $regBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
            $instances = Get-ChildItem "$regBase" -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -match "MSSQL\d+\.$instanceName" }

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
            Write-Phase "SQL TCP/IP configured via registry."
        }

        # Enable mixed-mode auth via registry
        $regBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
        $instances = Get-ChildItem $regBase -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -match "MSSQL\d+\.$instanceName" }
        foreach ($inst in $instances) {
            $serverPath = "$($inst.PSPath)\MSSQLServer"
            if (Test-Path $serverPath) {
                Set-ItemProperty -Path $serverPath -Name "LoginMode" -Value 2 -Force
            }
        }

        # Restart SQL to apply changes
        Restart-Service -Name $sqlService.Name -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 8

        # Find sqlcmd
        $sqlcmd = $null
        $searchPaths = @(
            "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\*\Tools\Binn\SQLCMD.EXE",
            "C:\Program Files\Microsoft SQL Server\*\Tools\Binn\SQLCMD.EXE",
            "C:\Program Files\Microsoft SQL Server\*\SQLCMD.EXE"
        )
        foreach ($pattern in $searchPaths) {
            $found = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) { $sqlcmd = $found.FullName; break }
        }

        if (-not $sqlcmd) {
            Write-Warning "[SQL] sqlcmd not found — SQL data seeding skipped."
            $script:SectionFailures += ''SQL-Seed''
        } else {
            Write-Phase "Found sqlcmd at: $sqlcmd"

            # Change SA password and enable account
            & $sqlcmd -S $sqlServerArg -E -Q "ALTER LOGIN [sa] WITH PASSWORD = N''SQLAdmin2024!''; ALTER LOGIN [sa] ENABLE;" 2>&1 | Out-Null

            # Enable xp_cmdshell (the main exploitation vector)
            & $sqlcmd -S $sqlServerArg -E -Q @"
EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;
EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;
"@ 2>&1 | Out-Null

            # Create HR database
            & $sqlcmd -S $sqlServerArg -E -Q "IF DB_ID(''hr_database'') IS NULL CREATE DATABASE hr_database;" 2>&1 | Out-Null

            # Create tables
            & $sqlcmd -S $sqlServerArg -E -d "hr_database" -Q @"
IF OBJECT_ID(''employees'',''U'') IS NULL
CREATE TABLE employees (
    id INT PRIMARY KEY IDENTITY(1,1),
    first_name NVARCHAR(50), last_name NVARCHAR(50),
    email NVARCHAR(100), ssn CHAR(11),
    department NVARCHAR(50), title NVARCHAR(100),
    salary DECIMAL(10,2), hire_date DATE, manager_id INT NULL
);

IF OBJECT_ID(''payroll'',''U'') IS NULL
CREATE TABLE payroll (
    id INT PRIMARY KEY IDENTITY(1,1),
    employee_id INT, pay_period DATE,
    gross_pay DECIMAL(10,2), tax_withheld DECIMAL(10,2),
    net_pay DECIMAL(10,2), account_last4 CHAR(4)
);

IF OBJECT_ID(''performance_reviews'',''U'') IS NULL
CREATE TABLE performance_reviews (
    id INT PRIMARY KEY IDENTITY(1,1),
    employee_id INT, review_date DATE,
    rating INT, comments NVARCHAR(500), reviewer NVARCHAR(100)
);

IF OBJECT_ID(''system_credentials'',''U'') IS NULL
CREATE TABLE system_credentials (
    id INT PRIMARY KEY IDENTITY(1,1),
    system_name NVARCHAR(100), username NVARCHAR(50),
    credential NVARCHAR(100), notes NVARCHAR(200),
    last_rotated DATE
);
"@ 2>&1 | Out-Null

            # Populate employee data (realistic fake PII)
            & $sqlcmd -S $sqlServerArg -E -d "hr_database" -Q @"
DELETE FROM employees;

INSERT INTO employees (first_name,last_name,email,ssn,department,title,salary,hire_date,manager_id) VALUES
(''Marcus'',''Chen'',''m.chen@medalliance.local'',''458-71-4521'',''IT'',''Network Administrator'',78500.00,''2019-03-15'',NULL),
(''Jennifer'',''Thompson'',''j.thompson@medalliance.local'',''312-55-8834'',''IT'',''Senior Systems Engineer'',92000.00,''2017-06-01'',1),
(''David'',''Park'',''d.park@medalliance.local'',''629-43-1187'',''Finance'',''Financial Analyst'',67000.00,''2020-01-20'',6),
(''Sarah'',''Mitchell'',''s.mitchell@medalliance.local'',''771-28-5593'',''HR'',''HR Director'',95000.00,''2016-09-12'',NULL),
(''Robert'',''Garcia'',''r.garcia@medalliance.local'',''184-66-7742'',''Clinical'',''Clinical Systems Manager'',88000.00,''2018-04-01'',NULL),
(''Amanda'',''Foster'',''a.foster@medalliance.local'',''533-19-6628'',''Finance'',''CFO'',142000.00,''2015-02-28'',NULL),
(''James'',''Wilson'',''j.wilson@medalliance.local'',''847-32-9915'',''IT'',''Help Desk Technician'',52000.00,''2022-08-15'',1),
(''Maria'',''Rodriguez'',''m.rodriguez@medalliance.local'',''265-77-3341'',''Clinical'',''Data Entry Specialist'',44000.00,''2023-01-10'',5),
(''Kevin'',''Brown'',''k.brown@medalliance.local'',''918-54-2267'',''Operations'',''Office Manager'',61000.00,''2019-11-01'',NULL),
(''Lisa'',''Anderson'',''l.anderson@medalliance.local'',''156-88-4479'',''HR'',''Recruiter'',58000.00,''2021-05-20'',4),
(''Thomas'',''Martinez'',''t.martinez@medalliance.local'',''742-31-6653'',''IT'',''Junior Network Tech'',48000.00,''2023-06-01'',1),
(''Rachel'',''Kim'',''r.kim@medalliance.local'',''389-62-1198'',''Clinical'',''Clinical Informatics Analyst'',72000.00,''2020-09-15'',5),
(''Michael'',''Davis'',''m.davis@medalliance.local'',''601-45-8827'',''Finance'',''Accounts Payable'',51000.00,''2021-03-01'',6),
(''Emily'',''Taylor'',''e.taylor@medalliance.local'',''234-17-5544'',''Operations'',''Receptionist'',38000.00,''2022-11-15'',9),
(''Daniel'',''Lee'',''d.lee@medalliance.local'',''876-93-2210'',''IT'',''Security Analyst'',85000.00,''2020-07-01'',1),
(''Jessica'',''Clark'',''j.clark@medalliance.local'',''445-68-9933'',''Clinical'',''EHR Support Specialist'',56000.00,''2021-08-01'',5),
(''Andrew'',''Wright'',''a.wright@medalliance.local'',''567-24-1176'',''Finance'',''Senior Accountant'',74000.00,''2018-12-01'',6),
(''Nicole'',''Harris'',''n.harris@medalliance.local'',''198-53-7782'',''HR'',''Benefits Coordinator'',54000.00,''2022-02-14'',4),
(''Christopher'',''Moore'',''c.moore@medalliance.local'',''713-46-3358'',''Operations'',''Facilities Manager'',63000.00,''2019-05-20'',9),
(''Stephanie'',''White'',''s.white@medalliance.local'',''832-71-4495'',''Clinical'',''Compliance Officer'',91000.00,''2017-10-01'',NULL);
"@ 2>&1 | Out-Null

            # Populate payroll data
            & $sqlcmd -S $sqlServerArg -E -d "hr_database" -Q @"
DELETE FROM payroll;

INSERT INTO payroll (employee_id,pay_period,gross_pay,tax_withheld,net_pay,account_last4) VALUES
(1,''2024-11-01'',3269.23,817.31,2451.92,''4521''),
(2,''2024-11-01'',3833.33,958.33,2875.00,''8834''),
(3,''2024-11-01'',2791.67,697.92,2093.75,''1187''),
(4,''2024-11-01'',3958.33,989.58,2968.75,''5593''),
(5,''2024-11-01'',3666.67,916.67,2750.00,''7742''),
(6,''2024-11-01'',5916.67,1479.17,4437.50,''6628''),
(7,''2024-11-01'',2166.67,541.67,1625.00,''9915''),
(8,''2024-11-01'',1833.33,458.33,1375.00,''3341''),
(9,''2024-11-01'',2541.67,635.42,1906.25,''2267''),
(10,''2024-11-01'',2416.67,604.17,1812.50,''4479'');
"@ 2>&1 | Out-Null

            # System credentials table — breadcrumb for students
            & $sqlcmd -S $sqlServerArg -E -d "hr_database" -Q @"
DELETE FROM system_credentials;

INSERT INTO system_credentials (system_name,username,credential,notes,last_rotated) VALUES
(''MEDALLIANCE-WIN (local)'',''admin'',''admin'',''Health Monitor dashboard — default, never changed'',''2023-01-15''),
(''MEDALLIANCE-WIN (local)'',''m.chen'',''MedAlliance2024!'',''Network admin account — AD synced'',''2024-09-01''),
(''SQL Server (SQLEXPRESS)'',''sa'',''SQLAdmin2024!'',''SA account — used by Health Monitor'',''2024-03-15''),
(''Linux Server (medalliance-lnx)'',''j.thompson'',''Fall2024Med!'',''SSH access to Linux file server'',''2024-10-01''),
(''FTP Service'',''anonymous'',''(no password)'',''Read-only log access'',''2023-06-01''),
(''Backup Service'',''svc_backup'',''Backup#2024Secure'',''Nightly SQL backup job'',''2024-01-15'');
"@ 2>&1 | Out-Null

            # Create app_config database
            & $sqlcmd -S $sqlServerArg -E -Q "IF DB_ID(''app_config'') IS NULL CREATE DATABASE app_config;" 2>&1 | Out-Null

            & $sqlcmd -S $sqlServerArg -E -d "app_config" -Q @"
IF OBJECT_ID(''settings'',''U'') IS NULL
CREATE TABLE settings (
    key_name NVARCHAR(100) PRIMARY KEY,
    value NVARCHAR(500),
    updated DATETIME DEFAULT GETDATE()
);

IF OBJECT_ID(''app_users'',''U'') IS NULL
CREATE TABLE app_users (
    id INT PRIMARY KEY IDENTITY(1,1),
    username NVARCHAR(50), password_hash NVARCHAR(128),
    role NVARCHAR(20), active BIT DEFAULT 1
);

DELETE FROM settings;
INSERT INTO settings (key_name,value) VALUES
(''app.name'',''MedAlliance Health Monitor''),
(''app.version'',''3.1.2''),
(''db.connection'',''Server=localhost\SQLEXPRESS;Database=hr_database;User=sa;Password=SQLAdmin2024!''),
(''backup.path'',''C:\Backups''),
(''backup.schedule'',''0 2 * * *''),
(''smtp.server'',''medalliance-lnx''),
(''smtp.port'',''25'');

DELETE FROM app_users;
INSERT INTO app_users (username,password_hash,role) VALUES
(''admin'',''5f4dcc3b5aa765d61d8327deb882cf99'',''administrator''),
(''m.chen'',''e10adc3949ba59abbe56e057f20f883e'',''viewer''),
(''j.thompson'',''827ccb0eea8a706c4c34a16891f84e7b'',''viewer'');
"@ 2>&1 | Out-Null

            Write-Phase "SQL Server configured: SA enabled, xp_cmdshell on, databases populated."
        }

        Write-Phase "[Section] SQL Server configuration completed."
    } catch {
        Write-Warning "[Section] SQL Server configuration failed: $_"
        $script:SectionFailures += ''SQL''
    }
}

# ═══════════════════════════════════════════════════════════════
#  5. WINRM
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Starting WinRM configuration..."

    # On Win11 client, any adapter on a "Public" profile will cause WinRM Enable-PSRemoting
    # to refuse. Force Public → Private before touching WSMan.
    Get-NetConnectionProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.NetworkCategory -eq ''Public'' } |
        Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue

    Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true -Force -ErrorAction SilentlyContinue
    Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true -Force -ErrorAction SilentlyContinue
    winrm set winrm/config/service ''@{AllowUnencrypted="true"}'' 2>&1 | Out-Null
    winrm set winrm/config/service/auth ''@{Basic="true"}''       2>&1 | Out-Null

    # Ensure WinRM listener exists on HTTP
    $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue
    if (-not ($listeners | Where-Object { $_.Keys -contains "Transport=HTTP" })) {
        New-Item -Path WSMan:\localhost\Listener -Transport HTTP -Address * -Force -ErrorAction SilentlyContinue | Out-Null
    }

    Restart-Service WinRM -ErrorAction SilentlyContinue
    Write-Phase "WinRM configured (port 5985, HTTP, basic auth)."
    Write-Phase "[Section] WinRM configuration completed."
} catch {
    Write-Warning "[Section] WinRM configuration failed: $_"
    $script:SectionFailures += ''WinRM''
}

# ═══════════════════════════════════════════════════════════════
#  6. RDP
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Starting RDP configuration..."

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 0 -Force -ErrorAction SilentlyContinue

    $nlaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    if (Test-Path $nlaPath) {
        Set-ItemProperty -Path $nlaPath -Name "UserAuthentication" -Value 1 -Force -ErrorAction SilentlyContinue
    }

    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

    Write-Phase "RDP enabled (port 3389, NLA on)."
    Write-Phase "[Section] RDP configuration completed."
} catch {
    Write-Warning "[Section] RDP configuration failed: $_"
    $script:SectionFailures += ''RDP''
}

# ═══════════════════════════════════════════════════════════════
#  7. SUMMARY
# ═══════════════════════════════════════════════════════════════
Write-Phase ""
if ($script:SectionFailures.Count -eq 0) {
    Write-Phase "All services configured successfully."
    exit 0
} else {
    Write-Warning "Completed with failures/skips in sections: $($script:SectionFailures -join '', '')"
    exit 1
}
',	'["80", "8080/HTTP", "21/FTP", "1433/MSSQL", "5985/WINRM", "RDP/3389"]',	'{}',	60,	'1',	'2026-04-15 05:30:56.131082+00',	'',	'vulnerable'),
('d2844291-176b-4612-805e-e57c0f33ef52',	'win-dundercorp-full-path-1',	'''Dundercorp'' Full Path 1',	'',	'Custom',	'windows',	'intermediate',	'param(
    [switch]$Setup,
    [switch]$Verify,
    [switch]$Reset
)

$ErrorActionPreference = "Stop"

# ========================================
# Core names
# ========================================
$PathName          = "Path1"
$CompanyRoot       = "C:\ProgramData\DunderCorp"
$Root              = Join-Path $CompanyRoot $PathName

$ServiceName       = "DunderTelemetry"
$TaskName          = "DunderCacheRefresh"
$PersistTaskName   = "DunderUserEnvSync"
$RunValueName      = "DunderOpsUpdate"

$InitialUser       = "USER2"
$InitialPassword   = "User2Pass123!"
$InitialNtlm       = "204CBDF67E606291349B66FD84A06954"

# ========================================
# Paths
# ========================================
$PrivescRoot       = Join-Path $Root "Privesc"
$SvcDir            = Join-Path $PrivescRoot "svc"
$HooksDir          = Join-Path $PrivescRoot "hooks"
$TasksDir          = Join-Path $PrivescRoot "tasks"

$PersistenceRoot   = Join-Path $Root "Persistence"
$PersistBinDir     = Join-Path $PersistenceRoot "bin"
$PersistScriptsDir = Join-Path $PersistenceRoot "scripts"
$PersistLogsDir    = Join-Path $PersistenceRoot "logs"

$ArtifactsRoot     = Join-Path $Root "Artifacts"
$CredsDir          = Join-Path $ArtifactsRoot "Creds"
$LogsDir           = Join-Path $ArtifactsRoot "Logs"
$ConfigsDir        = Join-Path $ArtifactsRoot "Configs"
$ExportsDir        = Join-Path $ArtifactsRoot "Exports"
$NotesDir          = Join-Path $ArtifactsRoot "Notes"
$TranscriptDir     = Join-Path $ArtifactsRoot "Transcripts"

$TelemetryScript   = Join-Path $SvcDir "telemetry_service.ps1"
$PreflightScript   = Join-Path $HooksDir "preflight.ps1"
$RefreshScript     = Join-Path $TasksDir "refresh_cache.ps1"

$OpsHelperVbs      = Join-Path $PersistBinDir "opshelper.vbs"
$UserEnvSyncScript = Join-Path $PersistScriptsDir "userenv_sync.ps1"

$SvcLog            = Join-Path $LogsDir "telemetry_service.log"
$TaskLog           = Join-Path $LogsDir "cache_refresh.log"
$PersistRunLog     = Join-Path $PersistLogsDir "opshelper.log"
$PersistTaskLog    = Join-Path $PersistLogsDir "userenv_sync.log"
$StartupLog        = Join-Path $PersistLogsDir "startup.log"

$StartupCmd        = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\DunderStartup.cmd"

$AgentConf         = Join-Path $ConfigsDir "agent.conf"
$UnattendBackup    = Join-Path $ConfigsDir "staged_unattend.xml.bak"
$SupportHashes     = Join-Path $CredsDir "support_hashes.txt"
$InstallLog        = Join-Path $LogsDir "install.log"
$OpsNotes          = Join-Path $NotesDir "ops_notes.txt"
$TranscriptFile    = Join-Path $TranscriptDir "PowerShell_transcript-DunderOps.txt"

$User2History      = "C:\Users\USER2\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
$AdminHistory      = "C:\Users\ADMIN\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

$LabShare          = "C:\LabShare"
$LabSharePublic    = Join-Path $LabShare "Public"
$LabShareUsers     = Join-Path $LabShare "Users"
$LabShareDrop      = Join-Path $LabShare "Drop"

$VpnExportFile     = Join-Path $LabSharePublic "vpn_export.txt"
$HelpdeskNoteFile  = Join-Path $LabSharePublic "helpdesk_note.txt"

$AdminHome         = "C:\Users\ADMIN"
$User2Home         = "C:\Users\USER2"
$UserHome          = "C:\Users\USER"

$AdminDesktop      = Join-Path $AdminHome "Desktop"
$User2Desktop      = Join-Path $User2Home "Desktop"
$UserDesktop       = Join-Path $UserHome "Desktop"

$AdminDocuments    = Join-Path $AdminHome "Documents"
$User2Documents    = Join-Path $User2Home "Documents"
$UserDocuments     = Join-Path $UserHome "Documents"

# ========================================
# Helpers
# ========================================
function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-IfExists {
    param([string]$Path)
    if (Test-Path $Path) {
        Remove-Item -Path $Path -Recurse -Force
    }
}

function Get-RandomPastDate {
    param(
        [int]$MinDaysAgo = 2,
        [int]$MaxDaysAgo = 35
    )

    $days  = Get-Random -Minimum $MinDaysAgo -Maximum ($MaxDaysAgo + 1)
    $hours = Get-Random -Minimum 0 -Maximum 23
    $mins  = Get-Random -Minimum 0 -Maximum 59

    return (Get-Date).AddDays(-$days).AddHours(-$hours).AddMinutes(-$mins)
}

function Set-BackdatedTimestamp {
    param(
        [string]$Path,
        [int]$MinDaysAgo = 2,
        [int]$MaxDaysAgo = 35
    )

    if (Test-Path $Path) {
        $dt = Get-RandomPastDate -MinDaysAgo $MinDaysAgo -MaxDaysAgo $MaxDaysAgo
        $item = Get-Item $Path -Force
        $item.CreationTime   = $dt
        $item.LastWriteTime  = $dt
        $item.LastAccessTime = $dt
    }
}

function Write-ManagedFile {
    param(
        [string]$Path,
        [string]$Content,
        [string]$Encoding = "UTF8",
        [int]$MinDaysAgo = 2,
        [int]$MaxDaysAgo = 35
    )

    $parent = Split-Path $Path -Parent
    if ($parent) {
        Ensure-Dir $parent
    }

    Set-Content -Path $Path -Value $Content -Encoding $Encoding
    Set-BackdatedTimestamp -Path $Path -MinDaysAgo $MinDaysAgo -MaxDaysAgo $MaxDaysAgo
}

function Ensure-ExpectedHomes {
    Write-Step "Checking expected local profiles"

    foreach ($homePath in @($AdminHome, $User2Home, $UserHome)) {
        if (-not (Test-Path $homePath)) {
            Write-Warning "$homePath does not exist. That profile-specific content will be skipped."
        }
    }
}

function Ensure-BaseLayout {
    foreach ($d in @(
        $CompanyRoot, $Root,
        $PrivescRoot, $SvcDir, $HooksDir, $TasksDir,
        $PersistenceRoot, $PersistBinDir, $PersistScriptsDir, $PersistLogsDir,
        $ArtifactsRoot, $CredsDir, $LogsDir, $ConfigsDir, $ExportsDir, $NotesDir, $TranscriptDir,
        $LabShare, $LabSharePublic, $LabShareUsers, $LabShareDrop
    )) {
        Ensure-Dir $d
    }

    foreach ($d in @(
        $AdminDesktop, $User2Desktop, $UserDesktop,
        $AdminDocuments, $User2Documents, $UserDocuments
    )) {
        if (Test-Path (Split-Path $d -Parent)) {
            Ensure-Dir $d
        }
    }
}

# ========================================
# Initial access
# ========================================
function Ensure-InitialAccessCredential {
    Write-Step "Setting initial-access credential for $InitialUser"

    $userExists = Get-LocalUser -Name $InitialUser -ErrorAction SilentlyContinue
    if (-not $userExists) {
        throw "Local user $InitialUser does not exist."
    }

    net user $InitialUser $InitialPassword | Out-Null
}

function Seed-InitialAccessArtifacts {
    Write-Step "Seeding initial-access artifacts in LabShare\Public"

    Write-ManagedFile -Path $VpnExportFile -MinDaysAgo 6 -MaxDaysAgo 14 -Content @"
Legacy VPN Cache Export
-----------------------
User: $InitialUser
Format: NTLM
Hash: $InitialNtlm

Notes:
- cached during migration validation
- remove after helpdesk confirms remote access
"@

    Write-ManagedFile -Path $HelpdeskNoteFile -MinDaysAgo 3 -MaxDaysAgo 8 -Content @"
Helpdesk Note
-------------
Remote support access for $InitialUser was revalidated during the spring refresh.
Old VPN cache export is still in Public for the migration checklist.
Do not leave temporary auth material on the share longer than needed.
"@
}

# ========================================
# Privesc rails
# ========================================
function Seed-PrivescHelpers {
    Write-Step "Seeding privesc helper scripts"

    Write-ManagedFile -Path $TelemetryScript -Encoding ASCII -MinDaysAgo 4 -MaxDaysAgo 14 -Content @"
`$ErrorActionPreference = ''SilentlyContinue''
"`$(Get-Date -Format s) [SERVICE] DunderTelemetry invoked as `$env:USERNAME" | Out-File "$SvcLog" -Append -Encoding ascii
if (Test-Path "$PreflightScript") {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PreflightScript" *>> "$SvcLog"
}
Start-Sleep -Seconds 2
"@

    Write-ManagedFile -Path $PreflightScript -Encoding ASCII -MinDaysAgo 3 -MaxDaysAgo 10 -Content @"
"`$(Get-Date -Format s) [HOOK] Preflight checks completed" | Out-File "$SvcLog" -Append -Encoding ascii
"`$(Get-Date -Format s) [HOOK] Inventory sync placeholder" | Out-File "$SvcLog" -Append -Encoding ascii
"@

    Write-ManagedFile -Path $RefreshScript -Encoding ASCII -MinDaysAgo 3 -MaxDaysAgo 10 -Content @"
"`$(Get-Date -Format s) [TASK] Cache refresh executed as `$env:USERNAME" | Out-File "$TaskLog" -Append -Encoding ascii
"`$(Get-Date -Format s) [TASK] Pulling staged config from DunderCorp" | Out-File "$TaskLog" -Append -Encoding ascii
"@

    icacls $PreflightScript /grant "Users:(M)" | Out-Null
    icacls $RefreshScript  /grant "Users:(M)" | Out-Null
    icacls $SvcDir         /grant "Users:(RX)" | Out-Null
}

function Ensure-PrivescTask {
    Write-Step "Creating SYSTEM scheduled task rail"

    try {
        schtasks /delete /tn "\$TaskName" /f 2>$null | Out-Null
    } catch {}

    $taskCmd = ''powershell.exe -NoProfile -ExecutionPolicy Bypass -File "'' + $RefreshScript + ''"''

    schtasks /create `
        /tn "\$TaskName" `
        /sc minute `
        /mo 1 `
        /ru SYSTEM `
        /rl HIGHEST `
        /tr $taskCmd `
        /f | Out-Null

    icacls $RefreshScript /grant "Users:(M)" | Out-Null
}

function Ensure-TelemetryService {
    Write-Step "Creating weak SYSTEM service rail"

    try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 1

    $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingSvc) {
        try { & sc.exe delete $ServiceName | Out-Null } catch {}
        Start-Sleep -Seconds 2
    }

    $binPath = ''C:\Windows\System32\cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File "'' + $TelemetryScript + ''"''

    New-Service `
        -Name $ServiceName `
        -BinaryPathName $binPath `
        -DisplayName "DunderCorp Telemetry Service" `
        -Description "Legacy DunderCorp telemetry maintenance runner" `
        -StartupType Manual | Out-Null

    Start-Sleep -Seconds 1

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        throw "Service $ServiceName was not created successfully."
    }

    try {
        $sddl = ''D:(A;;CCLCSWRPWPLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLOCRRC;;;AU)''
        & sc.exe sdset $ServiceName $sddl | Out-Null
    } catch {
        Write-Warning ("Failed to set service SDDL on {0}: {1}" -f $ServiceName, $_.Exception.Message)
    }

    icacls $PreflightScript /grant "Users:(M)" | Out-Null

    $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    try {
        if (-not (Test-Path $svcRegPath)) {
            throw "Service registry path does not exist after creation."
        }

        $acl = Get-Acl $svcRegPath
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "Users",
            "FullControl",
            "ContainerInherit",
            "None",
            "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl -Path $svcRegPath -AclObject $acl
    } catch {
        Write-Warning ("Failed to weaken service registry ACL on {0}: {1}" -f $svcRegPath, $_.Exception.Message)
    }
}

# ========================================
# Persistence
# ========================================
function Seed-PersistenceHelpers {
    Write-Step "Seeding persistence helpers"

    Write-ManagedFile -Path $OpsHelperVbs -Encoding ASCII -MinDaysAgo 5 -MaxDaysAgo 15 -Content @"
Set oShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
logPath = "$PersistRunLog"
Set f = fso.OpenTextFile(logPath, 8, True)
f.WriteLine Now & " [RUNKEY] DunderOpsUpdate launched"
f.Close
"@

    Write-ManagedFile -Path $UserEnvSyncScript -Encoding ASCII -MinDaysAgo 4 -MaxDaysAgo 12 -Content @"
`$ErrorActionPreference = ''SilentlyContinue''
"`$(Get-Date -Format s) [TASK] DunderUserEnvSync executed as `$env:USERNAME" | Out-File "$PersistTaskLog" -Append -Encoding ascii
"`$(Get-Date -Format s) [TASK] Syncing environment markers" | Out-File "$PersistTaskLog" -Append -Encoding ascii
"@

    Write-ManagedFile -Path $StartupCmd -Encoding ASCII -MinDaysAgo 4 -MaxDaysAgo 12 -Content @"
@echo off
echo %date% %time% [STARTUP] Dunder startup helper >> "$StartupLog"
"@

    if (Test-Path $PersistenceRoot) {
        icacls $PersistenceRoot /inheritance:r | Out-Null
        icacls $PersistenceRoot /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" "Users:(OI)(CI)(RX)" | Out-Null
    }

    foreach ($f in @($OpsHelperVbs, $UserEnvSyncScript, $StartupCmd)) {
        if (Test-Path $f) {
            icacls $f /grant:r "SYSTEM:(F)" "Administrators:(F)" "Users:(RX)" | Out-Null
        }
    }
}

function Ensure-RunKey {
    Write-Step "Creating HKLM Run-key persistence"

    New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Force | Out-Null
    New-ItemProperty `
        -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name $RunValueName `
        -Value ("wscript.exe `"{0}`"" -f $OpsHelperVbs) `
        -PropertyType String `
        -Force | Out-Null
}

function Ensure-PersistTask {
    Write-Step "Creating scheduled task persistence"

    try {
        schtasks /delete /tn "\$PersistTaskName" /f 2>$null | Out-Null
    } catch {}

    $taskCmd = ''powershell.exe -NoProfile -ExecutionPolicy Bypass -File "'' + $UserEnvSyncScript + ''"''

    schtasks /create `
        /tn "\$PersistTaskName" `
        /sc onlogon `
        /ru SYSTEM `
        /rl HIGHEST `
        /tr $taskCmd `
        /f | Out-Null
}

# ========================================
# Artifacts / objectives
# ========================================
function Ensure-DesktopFolders {
    Write-Step "Creating realistic desktop folders"

    foreach ($d in @(
        (Join-Path $AdminDesktop "Infra"),
        (Join-Path $AdminDesktop "Quarterly Review"),
        (Join-Path $AdminDesktop "Scripts"),
        (Join-Path $AdminDesktop "To Sort"),
        (Join-Path $AdminDesktop "Archive"),

        (Join-Path $User2Desktop "Tickets"),
        (Join-Path $User2Desktop "Exports"),
        (Join-Path $User2Desktop "Temp"),
        (Join-Path $User2Desktop "VPN"),
        (Join-Path $User2Desktop "Old Notes"),

        (Join-Path $UserDesktop "Projects"),
        (Join-Path $UserDesktop "Downloads To File"),
        (Join-Path $UserDesktop "Screenshots"),
        (Join-Path $UserDesktop "Old"),
        (Join-Path $UserDesktop "Reference")
    )) {
        if ($d -and (Test-Path (Split-Path $d -Parent))) {
            Ensure-Dir $d
            Set-BackdatedTimestamp -Path $d -MinDaysAgo 3 -MaxDaysAgo 28
        }
    }
}

function Seed-ProgramDataArtifacts {
    Write-Step "Seeding ProgramData artifacts"

    Write-ManagedFile -Path $AgentConf -MinDaysAgo 10 -MaxDaysAgo 25 -Content @"
[telemetry]
ServiceName=$ServiceName
TaskName=$TaskName
Mode=legacy
RetrySeconds=30

[internal]
BackupHost=backup-srv01.dundercorp.local
MgmtHost=mgmt-srv01.dundercorp.local
FinanceHost=finance-srv01.dundercorp.local
ProxyHost=proxy01.dundercorp.local

[paths]
HashFile=$SupportHashes
Transcript=$TranscriptFile
StagedUnattend=$UnattendBackup
"@

    Write-ManagedFile -Path $UnattendBackup -MinDaysAgo 18 -MaxDaysAgo 35 -Content @"
<unattend>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup">
      <AutoLogon>
        <Enabled>false</Enabled>
        <Username>svc_deploy</Username>
        <Password>
          <Value>LabDeploy2026!</Value>
          <PlainText>true</PlainText>
        </Password>
      </AutoLogon>
    </component>
  </settings>
</unattend>
"@

    Write-ManagedFile -Path $SupportHashes -Encoding ASCII -MinDaysAgo 7 -MaxDaysAgo 18 -Content @"
# Lab-only hash material
# Format: account:NTLM
svc_backup:DE769E624BFE51CB4109255F0F1E0910
svc_install:51B056A8B2C13AEFE10D95EF051EF70A
legacy_sync:C65FF5F2633515BCA9B3370DD709074A
"@

    Write-ManagedFile -Path $InstallLog -MinDaysAgo 12 -MaxDaysAgo 30 -Content @"
[2026-03-01 14:00:01] INFO  Path 1 maintenance bundle staged
[2026-03-01 14:00:05] INFO  Telemetry service registered as LocalSystem
[2026-03-01 14:00:08] INFO  Cache refresh task registered as SYSTEM
[2026-03-01 14:00:11] INFO  Legacy deployment backup copied to $UnattendBackup
[2026-03-01 14:00:14] INFO  Hash cache staged at $SupportHashes
[2026-03-01 14:00:16] INFO  Export staging path initialized at $ExportsDir
"@

    Write-ManagedFile -Path $OpsNotes -MinDaysAgo 4 -MaxDaysAgo 15 -Content @"
Operations Notes
----------------
- Legacy telemetry still depends on ProgramData paths for hooks and cached exports.
- Cache refresh and telemetry rails should be reviewed before quarterly image refresh.
- Support hashes are for migration validation only and should not remain on production endpoints.
- Old unattended backup should be removed after deployment cleanup.
"@

    Write-ManagedFile -Path $TranscriptFile -MinDaysAgo 3 -MaxDaysAgo 9 -Content @"
**********************
Windows PowerShell transcript start
Start time: 20260323174200
Username  : WINDOWS\ADMIN
RunAs User: WINDOWS\ADMIN
Machine   : WIN11LAB
**********************
PS> schtasks /query /tn $TaskName /v /fo list
PS> sc.exe qc $ServiceName
PS> reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
PS> icacls $PreflightScript
PS> icacls $RefreshScript
PS> Get-Content $SupportHashes
**********************
Windows PowerShell transcript end
**********************
"@

    Write-ManagedFile -Path (Join-Path $ExportsDir "inventory_q1.csv") -MinDaysAgo 8 -MaxDaysAgo 22 -Content @"
Hostname,Owner,Status,Notes
WIN11LAB,IT Ops,Active,Training image
backup-util,Operations,Review,Legacy sync still enabled
web-training,Security,Active,OWASP apps staged
filesrv-old,Infrastructure,Pending cleanup,Review before decom
"@

    Write-ManagedFile -Path (Join-Path $ExportsDir "vpn_approved_hosts.txt") -MinDaysAgo 5 -MaxDaysAgo 14 -Content @"
vpn-gw01.dundercorp.local
backup-srv01.dundercorp.local
finance-srv01.dundercorp.local
mgmt-srv01.dundercorp.local
"@

    Write-ManagedFile -Path (Join-Path $ExportsDir "endpoint_rollup.csv") -MinDaysAgo 6 -MaxDaysAgo 16 -Content @"
Hostname,PrimaryUser,Department,VPN,Notes
WIN11LAB,USER2,Support,Yes,Needs cleanup review
OPS-WS-14,ADMIN,Infrastructure,Yes,Old scripts on desktop
SEC-WS-08,USER,Security,No,Archive pending
"@
}

function Seed-PowerShellHistory {
    Write-Step "Seeding PowerShell history"

    Write-ManagedFile -Path $User2History -MinDaysAgo 2 -MaxDaysAgo 8 -Content @"
whoami /priv
Get-Service $ServiceName
schtasks /query /fo LIST /v
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ChildItem C:\ProgramData\DunderCorp -Recurse
type $AgentConf
"@

    Write-ManagedFile -Path $AdminHistory -MinDaysAgo 2 -MaxDaysAgo 8 -Content @"
sc.exe qc $ServiceName
sc.exe sdshow $ServiceName
schtasks /run /tn $TaskName
Get-Content $SupportHashes
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Get-ChildItem C:\Users\ADMIN\Desktop -Force
"@
}

function Seed-LabShareArtifacts {
    Write-Step "Seeding LabShare artifacts"

    Write-ManagedFile -Path (Join-Path $LabSharePublic "printer_inventory.txt") -MinDaysAgo 11 -MaxDaysAgo 28 -Content @"
Printer Inventory
-----------------
print-core-01   10.20.14.22
print-west-01   10.20.14.23
print-east-01   10.20.14.24
"@

    Write-ManagedFile -Path (Join-Path $LabSharePublic "migration_todo.txt") -MinDaysAgo 5 -MaxDaysAgo 14 -Content @"
Migration TODO
--------------
- verify backup utility host list
- retire old telemetry notes
- confirm admin startup helpers removed after image refresh
"@

    Write-ManagedFile -Path (Join-Path $LabShareUsers "support_contacts.txt") -MinDaysAgo 7 -MaxDaysAgo 18 -Content @"
Support Contacts
----------------
ADMIN
USER
USER2
svc_backup
svc_install
"@

    Write-ManagedFile -Path (Join-Path $LabShareDrop "readme.txt") -MinDaysAgo 2 -MaxDaysAgo 6 -Content @"
Drop Share
----------
Temporary exchange area for support files.
Do not leave long-term exports here.
"@
}

function Seed-AdminDesktopAndDocs {
    Write-Step "Seeding ADMIN desktop and document artifacts"

    if (Test-Path $AdminDesktop) {
        Write-ManagedFile -Path (Join-Path $AdminDesktop "Infra\server_list.txt") -MinDaysAgo 9 -MaxDaysAgo 20 -Content @"
backup-srv01.dundercorp.local
finance-srv01.dundercorp.local
mgmt-srv01.dundercorp.local
proxy01.dundercorp.local
"@

        Write-ManagedFile -Path (Join-Path $AdminDesktop "Infra\host_aliases.csv") -MinDaysAgo 9 -MaxDaysAgo 20 -Content @"
Alias,IP
mgmt-srv01,10.10.10.10
finance-srv01,10.10.10.20
backup-srv01,10.10.10.50
"@

        Write-ManagedFile -Path (Join-Path $AdminDesktop "Scripts\restart-services.ps1") -MinDaysAgo 3 -MaxDaysAgo 8 -Content @"
Get-Service $ServiceName,WinRM,sshd | Restart-Service
"@

        Write-ManagedFile -Path (Join-Path $AdminDesktop "Scripts\collect-logs.ps1") -MinDaysAgo 4 -MaxDaysAgo 10 -Content @"
Get-ChildItem C:\ProgramData\DunderCorp -Recurse -Include *.log,*.txt
"@

        Write-ManagedFile -Path (Join-Path $AdminDesktop "Quarterly Review\action_items.txt") -MinDaysAgo 7 -MaxDaysAgo 15 -Content @"
Q1 Action Items
---------------
- validate backup rotations
- remove old unattend backups from field machines
- confirm telemetry rails before April image push
"@

        Write-ManagedFile -Path (Join-Path $AdminDesktop "Quarterly Review\backup-followup.txt") -MinDaysAgo 6 -MaxDaysAgo 12 -Content @"
Backup Follow-up
----------------
Need final sign-off on legacy sync retirement.
"@

        Write-ManagedFile -Path (Join-Path $AdminDesktop "To Sort\old-ops-notes.txt") -MinDaysAgo 15 -MaxDaysAgo 28 -Content @"
Old Ops Notes
-------------
Need to move remaining hash cache out of ProgramData after migration.
"@

        Write-ManagedFile -Path (Join-Path $AdminDesktop "Archive\old-server-list-2025.txt") -MinDaysAgo 20 -MaxDaysAgo 35 -Content @"
legacy-web-02
legacy-proxy-01
filesrv-old
"@

        Write-ManagedFile -Path (Join-Path $AdminDesktop "todo.txt") -MinDaysAgo 2 -MaxDaysAgo 5 -Content @"
- clear old review notes
- recheck startup helpers
- move exports off desktop
"@
    }

    if (Test-Path $AdminDocuments) {
        Write-ManagedFile -Path (Join-Path $AdminDocuments "Maintenance Notes.txt") -MinDaysAgo 5 -MaxDaysAgo 12 -Content @"
Maintenance Notes
-----------------
Local telemetry and cache-refresh items are still on this workstation for testing.
Check ProgramData before cleanup.
"@

        Write-ManagedFile -Path (Join-Path $AdminDocuments "infra-overview.txt") -MinDaysAgo 8 -MaxDaysAgo 16 -Content @"
Infra Overview
--------------
Primary internal hosts:
- mgmt-srv01.dundercorp.local
- backup-srv01.dundercorp.local
- finance-srv01.dundercorp.local
"@

        Write-ManagedFile -Path (Join-Path $AdminDocuments "review-questions.txt") -MinDaysAgo 3 -MaxDaysAgo 7 -Content @"
Review Questions
----------------
- Why are old support hashes still staged locally?
- Who owns cleanup for telemetry cache?
"@
    }
}

function Seed-User2DesktopAndDocs {
    Write-Step "Seeding USER2 desktop and document artifacts"

    if (Test-Path $User2Desktop) {
        Write-ManagedFile -Path (Join-Path $User2Desktop "Tickets\ticket-1042.txt") -MinDaysAgo 4 -MaxDaysAgo 9 -Content @"
Ticket 1042
-----------
User reports old deployment files still visible under ProgramData.
Escalate if services restart unexpectedly.
"@

        Write-ManagedFile -Path (Join-Path $User2Desktop "Tickets\ticket-1061.txt") -MinDaysAgo 2 -MaxDaysAgo 6 -Content @"
Ticket 1061
-----------
Customer asked whether old backup utility exports can be removed from desktop.
"@

        Write-ManagedFile -Path (Join-Path $User2Desktop "Exports\hosts_to_check.txt") -MinDaysAgo 5 -MaxDaysAgo 11 -Content @"
Hosts To Check
--------------
10.10.10.10
10.10.10.20
10.10.10.50
"@

        Write-ManagedFile -Path (Join-Path $User2Desktop "Exports\printer-export.csv") -MinDaysAgo 4 -MaxDaysAgo 8 -Content @"
Printer,Queue,Status
print-core-01,PRN-204,Active
print-west-01,PRN-221,Review
"@

        Write-ManagedFile -Path (Join-Path $User2Desktop "VPN\vpn_notes.txt") -MinDaysAgo 6 -MaxDaysAgo 13 -Content @"
VPN Notes
---------
Approved destinations:
- backup-srv01.dundercorp.local
- finance-srv01.dundercorp.local
"@

        Write-ManagedFile -Path (Join-Path $User2Desktop "Old Notes\migration.txt") -MinDaysAgo 12 -MaxDaysAgo 24 -Content @"
Migration
---------
Telemetry helper still references old backup naming.
Need to confirm cleanup after deploy.
"@

        Write-ManagedFile -Path (Join-Path $User2Desktop "Temp\desktop-scratch.txt") -MinDaysAgo 1 -MaxDaysAgo 3 -Content @"
scratch:
- ask ADMIN about old startup helper
- move export after review
"@

        Write-ManagedFile -Path (Join-Path $User2Desktop "readme-first.txt") -MinDaysAgo 1 -MaxDaysAgo 4 -Content @"
Desktop Notes
-------------
Most of the useful stuff is either in Tickets, Exports, or ProgramData.
"@
    }

    if (Test-Path $User2Documents) {
        Write-ManagedFile -Path (Join-Path $User2Documents "ticket_queue.csv") -MinDaysAgo 4 -MaxDaysAgo 10 -Content @"
Ticket,Owner,Status
1042,USER2,Open
1049,USER2,Waiting
1057,USER2,Review
"@

        Write-ManagedFile -Path (Join-Path $User2Documents "support_reminders.txt") -MinDaysAgo 2 -MaxDaysAgo 6 -Content @"
Support Reminders
-----------------
- check $ServiceName after patching
- confirm cache task runs after login
- move temp exports off desktop
"@

        Write-ManagedFile -Path (Join-Path $User2Documents "finance-hosts.txt") -MinDaysAgo 7 -MaxDaysAgo 15 -Content @"
finance-srv01.dundercorp.local
finance-db01.dundercorp.local
"@
    }
}

function Seed-UserDesktopAndDocs {
    Write-Step "Seeding USER desktop and document artifacts"

    if (Test-Path $UserDesktop) {
        Write-ManagedFile -Path (Join-Path $UserDesktop "Projects\desktop-shortlist.txt") -MinDaysAgo 5 -MaxDaysAgo 11 -Content @"
Desktop Shortlist
-----------------
- quarterly export cleanup
- archive screenshots
- move notes into Reference
"@

        Write-ManagedFile -Path (Join-Path $UserDesktop "Projects\cleanup-plan.txt") -MinDaysAgo 4 -MaxDaysAgo 9 -Content @"
Cleanup Plan
------------
- move old host notes
- review screenshot folder
- sort export references
"@

        Write-ManagedFile -Path (Join-Path $UserDesktop "Reference\host_aliases.txt") -MinDaysAgo 6 -MaxDaysAgo 15 -Content @"
mgmt-srv01 = 10.10.10.10
finance-srv01 = 10.10.10.20
backup-srv01 = 10.10.10.50
"@

        Write-ManagedFile -Path (Join-Path $UserDesktop "Reference\share-notes.txt") -MinDaysAgo 3 -MaxDaysAgo 7 -Content @"
Public  = broad read
Users   = authenticated read
Drop    = authenticated write
"@

        Write-ManagedFile -Path (Join-Path $UserDesktop "Downloads To File\inbox-review.txt") -MinDaysAgo 2 -MaxDaysAgo 5 -Content @"
Need to file:
- old onboarding notes
- screenshot bundle
- host alias draft
"@

        Write-ManagedFile -Path (Join-Path $UserDesktop "Old\desktop-2025.txt") -MinDaysAgo 16 -MaxDaysAgo 30 -Content @"
2025 leftovers
--------------
- retire onboarding shortcuts
- archive temp notes
"@

        Write-ManagedFile -Path (Join-Path $UserDesktop "reference-todo.txt") -MinDaysAgo 1 -MaxDaysAgo 4 -Content @"
- check WinRM notes
- verify SSH artifacts
- keep LabShare tidy
"@
    }

    if (Test-Path $UserDocuments) {
        Write-ManagedFile -Path (Join-Path $UserDocuments "desktop_tasks.txt") -MinDaysAgo 3 -MaxDaysAgo 7 -Content @"
Desktop Tasks
-------------
- clean ProgramData notes
- verify SMB share list
- review startup helpers
"@

        Write-ManagedFile -Path (Join-Path $UserDocuments "it-onboarding-draft.txt") -MinDaysAgo 8 -MaxDaysAgo 18 -Content @"
Onboarding Draft
----------------
- map core shares
- verify WinRM path
- review SSH defaults
"@
    }
}

# ========================================
# Setup / Verify / Reset
# ========================================
function Setup-Path1 {
    Ensure-ExpectedHomes
    Ensure-BaseLayout
    Ensure-InitialAccessCredential
    Seed-InitialAccessArtifacts
    Ensure-DesktopFolders

    Seed-PrivescHelpers
    Ensure-PrivescTask
    Ensure-TelemetryService

    Seed-PersistenceHelpers
    Ensure-RunKey
    Ensure-PersistTask

    Seed-ProgramDataArtifacts
    Seed-PowerShellHistory
    Seed-LabShareArtifacts
    Seed-AdminDesktopAndDocs
    Seed-User2DesktopAndDocs
    Seed-UserDesktopAndDocs

    Write-Step "Setup complete"
}

function Show-RegistryAcl {
    param([string]$Path)

    try {
        Get-Acl $Path |
            Select-Object -ExpandProperty Access |
            Select-Object IdentityReference, RegistryRights, AccessControlType, IsInherited |
            Format-Table -AutoSize
    } catch {
        Write-Warning "Could not read ACL for $Path"
    }
}

function Verify-Path1 {
    Write-Step "Initial-access artifacts"

    foreach ($f in @($VpnExportFile, $HelpdeskNoteFile)) {
        if (Test-Path $f) {
            Get-Item $f | Select-Object FullName, Length, LastWriteTime | Format-List
        }
    }

    Write-Host ""
    Write-Host "[Expected initial route]"
    Write-Host @"
1. Enumerate SMB shares.
2. Pull:
   - $VpnExportFile
   - $HelpdeskNoteFile
3. Crack USER2 NTLM on Kali.
4. Use recovered credential on:
   - evil-winrm -i <IP> -u USER2 -p <cracked password>
   - ssh USER2@<IP>
"@

    Write-Step "Privesc rails"

    try {
        Get-Service -Name $ServiceName -ErrorAction SilentlyContinue |
            Select-Object Name, Status, StartType |
            Format-Table -AutoSize
    } catch {}

    try {
        & sc.exe qc $ServiceName
        & sc.exe sdshow $ServiceName
    } catch {}

    Write-Host ""
    Write-Host "[Service registry ACL]"
    Show-RegistryAcl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

    Write-Host ""
    Write-Host "[Service/task script ACLs]"
    if (Test-Path $PreflightScript) { icacls $PreflightScript }
    if (Test-Path $RefreshScript)   { icacls $RefreshScript }

    Write-Host ""
    Write-Host "[Scheduled task rail]"
    try { schtasks /query /tn "\$TaskName" /fo LIST /v } catch {}

    Write-Step "Persistence"

    try {
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
            Select-Object $RunValueName |
            Format-List
    } catch {}

    if (Test-Path $StartupCmd) {
        Get-Item $StartupCmd | Select-Object FullName, Length, LastWriteTime | Format-List
        icacls $StartupCmd
    }

    try { schtasks /query /tn "\$PersistTaskName" /fo LIST /v } catch {}

    Write-Step "Artifacts"

    foreach ($f in @($AgentConf,$UnattendBackup,$SupportHashes,$InstallLog,$OpsNotes,$TranscriptFile,$User2History,$AdminHistory)) {
        if (Test-Path $f) {
            Get-Item $f | Select-Object FullName, Length, LastWriteTime | Format-List
        }
    }

    Write-Host ""
    Write-Host "[ProgramData tree]"
    Get-ChildItem $Root -Recurse -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime |
        Format-Table -Wrap -AutoSize

    Write-Host ""
    Write-Host "[Desktop roots]"
    foreach ($desktop in @($AdminDesktop, $User2Desktop, $UserDesktop)) {
        if (Test-Path $desktop) {
            Write-Host ""
            Write-Host "[$desktop]"
            Get-ChildItem $desktop -Force -ErrorAction SilentlyContinue |
                Select-Object Name, Mode, Length, LastWriteTime |
                Format-Table -AutoSize
        }
    }

    Write-Host ""
    Write-Host "[Documents roots]"
    foreach ($docs in @($AdminDocuments, $User2Documents, $UserDocuments)) {
        if (Test-Path $docs) {
            Write-Host ""
            Write-Host "[$docs]"
            Get-ChildItem $docs -Force -ErrorAction SilentlyContinue |
                Select-Object Name, Mode, Length, LastWriteTime |
                Format-Table -AutoSize
        }
    }

    Write-Host ""
    Write-Host "[LabShare]"
    foreach ($dir in @($LabSharePublic, $LabShareUsers, $LabShareDrop)) {
        if (Test-Path $dir) {
            Write-Host ""
            Write-Host "[$dir]"
            Get-ChildItem $dir -Force -ErrorAction SilentlyContinue |
                Select-Object Name, Length, LastWriteTime |
                Format-Table -AutoSize
        }
    }

    Write-Step "Suggested full chain"
    Write-Host @"
1. External enumeration:
   - SMB
   - WinRM
   - SSH
2. Retrieve crackable foothold material:
   - $VpnExportFile
   - $HelpdeskNoteFile
3. Crack USER2 credential on Kali.
4. Foothold as USER2 via WinRM or SSH.
5. Enumerate local rails:
   - service: $ServiceName
   - task: $TaskName
   - weak service registry ACL
   - Run key: $RunValueName
   - persistence task: $PersistTaskName
6. Escalate using one of:
   - writable hook: $PreflightScript
   - writable task script: $RefreshScript
   - writable service registry key under HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName
7. Post-escalation collection:
   - $SupportHashes
   - $AgentConf
   - $UnattendBackup
   - desktop/document data under ADMIN / USER2 / USER
   - LabShare content
"@
}

function Reset-Path1 {
    Write-Step "Removing tasks"
    try { schtasks /delete /tn "\$TaskName" /f 2>$null | Out-Null } catch {}
    try { schtasks /delete /tn "\$PersistTaskName" /f 2>$null | Out-Null } catch {}

    Write-Step "Removing service"
    try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 1
    try { & sc.exe delete $ServiceName | Out-Null } catch {}

    Write-Step "Removing Run key"
    try {
        Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $RunValueName -ErrorAction SilentlyContinue
    } catch {}

    Write-Step "Removing startup artifact"
    Remove-IfExists $StartupCmd

    Write-Step "Removing seeded PowerShell history"
    Remove-IfExists $User2History
    Remove-IfExists $AdminHistory

    Write-Step "Removing LabShare seeded files"
    foreach ($f in @(
        (Join-Path $LabSharePublic "printer_inventory.txt"),
        (Join-Path $LabSharePublic "migration_todo.txt"),
        (Join-Path $LabShareUsers "support_contacts.txt"),
        (Join-Path $LabShareDrop "readme.txt"),
        $VpnExportFile,
        $HelpdeskNoteFile
    )) {
        Remove-IfExists $f
    }

    Write-Step "Removing seeded desktop/document content"
    foreach ($p in @(
        (Join-Path $AdminDesktop "Infra"),
        (Join-Path $AdminDesktop "Quarterly Review"),
        (Join-Path $AdminDesktop "Scripts"),
        (Join-Path $AdminDesktop "To Sort"),
        (Join-Path $AdminDesktop "Archive"),
        (Join-Path $AdminDesktop "todo.txt"),

        (Join-Path $User2Desktop "Tickets"),
        (Join-Path $User2Desktop "Exports"),
        (Join-Path $User2Desktop "Temp"),
        (Join-Path $User2Desktop "VPN"),
        (Join-Path $User2Desktop "Old Notes"),
        (Join-Path $User2Desktop "readme-first.txt"),

        (Join-Path $UserDesktop "Projects"),
        (Join-Path $UserDesktop "Downloads To File"),
        (Join-Path $UserDesktop "Screenshots"),
        (Join-Path $UserDesktop "Old"),
        (Join-Path $UserDesktop "Reference"),
        (Join-Path $UserDesktop "reference-todo.txt"),

        (Join-Path $AdminDocuments "Maintenance Notes.txt"),
        (Join-Path $AdminDocuments "infra-overview.txt"),
        (Join-Path $AdminDocuments "review-questions.txt"),

        (Join-Path $User2Documents "ticket_queue.csv"),
        (Join-Path $User2Documents "support_reminders.txt"),
        (Join-Path $User2Documents "finance-hosts.txt"),

        (Join-Path $UserDocuments "desktop_tasks.txt"),
        (Join-Path $UserDocuments "it-onboarding-draft.txt")
    )) {
        Remove-IfExists $p
    }

    Write-Step "Removing path root"
    Remove-IfExists $Root

    Write-Step "Reset complete"
}

if (-not ($Setup -or $Verify -or $Reset)) {
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\path_1.ps1 -Setup"
    Write-Host "  .\path_1.ps1 -Verify"
    Write-Host "  .\path_1.ps1 -Reset"
    Write-Host ""
    Write-Host "Assumes:"
    Write-Host "  - local users USER, USER2, ADMIN already exist"
    Write-Host "  - SMB share configuration already exists"
    Write-Host "  - WinRM and/or SSH are already enabled if you want remote foothold paths"
    exit 1
}

if ($Reset) {
    Reset-Path1
}

if ($Setup) {
    Setup-Path1
}

if ($Verify) {
    Verify-Path1
}',	'["22/SSH", "445/SMB", "5985/WinRM"]',	'{SSH,SMB,WinRM}',	60,	'1',	'2026-04-15 00:47:03.029773+00',	'-Setup -Verify',	'vulnerable'),
('628f2c41-39f1-40dd-9c0c-78f82560aa1b',	'win-480-artifacts',	'Add 480 Artifacts',	'Plants proof files (unique per student), loot, and breadcrumb data
    on MedAlliance-WIN Tier 1 for grading and discovery.',	'Data Exfiltration',	'windows',	'intermediate',	'<#
.SYNOPSIS
    Plants proof files (unique per student), loot, and breadcrumb data
    on MedAlliance-WIN Tier 1 for grading and discovery.

.NOTES
    Proof files:
      C:\Users\m.chen\Desktop\local.txt                    — user-level proof
      C:\Users\Administrator\Desktop\proof.txt              — admin-level proof
    Both contain a unique hash derived from the student ID so the professor
    can verify screenshots are from the student''s own lane.

    Loot planted:
      Browser saved passwords (simulated via text file)
      RDP connection history in registry
      Payroll spreadsheet in m.chen''s Documents
      Bash-history equivalent (PowerShell console history)
#>

param(
    [Parameter(Mandatory=$true)][string]$StudentId,
    [Parameter(Mandatory=$true)][string]$WinIP
)

$ErrorActionPreference = "Continue"
$script:SectionFailures = @()
$subnetRef = $WinIP -replace ''\.\d+$'', ''''

function Write-Phase {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format ''HH:mm:ss'')][Loot] $Msg"
}

# ── Load deploy-context marker (written by Install-Services.ps1) ──
$ctxPath = "C:\ProgramData\MedAlliance\deploy-context.json"
if (Test-Path $ctxPath) {
    try {
        $ctx = Get-Content $ctxPath -Raw | ConvertFrom-Json
        $script:IsServer = [bool]$ctx.IsServer
    } catch {
        $script:IsServer = ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)
    }
} else {
    $script:IsServer = ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)
}

# ═══════════════════════════════════════════════════════════════
#  1. GENERATE UNIQUE PROOF HASHES
# ═══════════════════════════════════════════════════════════════
#
# Each student gets unique proof.txt and local.txt content so the
# professor can verify screenshots come from the student''s own lane.

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

try {
Write-Phase "[Section] Planting proof files..."

# m.chen''s Desktop — local.txt (user-level access proof)
$mchenDesktop = "C:\Users\m.chen\Desktop"
if (-not (Test-Path $mchenDesktop)) { New-Item -Path $mchenDesktop -ItemType Directory -Force | Out-Null }

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
  - Collect proof.txt from Administrator''s Desktop
"@ | Set-Content "$mchenDesktop\local.txt" -Encoding UTF8

Write-Phase "Planted local.txt on m.chen Desktop ($localHash)"

# Administrator''s Desktop — proof.txt (admin-level access proof).
# Note: on client SKUs the Administrator profile may not exist until first logon.
# Creating the directory preemptively is fine — the file will just sit until the
# student escalates and browses there.
$adminDesktop = "C:\Users\Administrator\Desktop"
if (-not (Test-Path $adminDesktop)) { New-Item -Path $adminDesktop -ItemType Directory -Force | Out-Null }

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
Write-Phase "[Section] Proof files completed."
} catch {
    Write-Warning "[Section] Proof files failed: $_"
    $script:SectionFailures += ''Proof''
}

# ═══════════════════════════════════════════════════════════════
#  3. PLANT LOOT IN m.chen''s PROFILE
# ═══════════════════════════════════════════════════════════════
try {
Write-Phase "[Section] Planting loot in m.chen profile..."

$mchenDocs = "C:\Users\m.chen\Documents"
if (-not (Test-Path $mchenDocs)) { New-Item -Path $mchenDocs -ItemType Directory -Force | Out-Null }

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
Write-Phase "[Section] Loot-in-profile completed."
} catch {
    Write-Warning "[Section] Loot-in-profile failed: $_"
    $script:SectionFailures += ''Loot-Profile''
}

# ═══════════════════════════════════════════════════════════════
#  4. PLANT RDP CONNECTION HISTORY
# ═══════════════════════════════════════════════════════════════
try {
Write-Phase "[Section] Planting RDP connection history..."

# Plant RDP connection history in current user''s registry
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
    if (-not (Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
    Set-ItemProperty -Path $serverPath -Name "UsernameHint" -Value "$($t.Hint)\$($t.User)" -Force
}

# Also set MRU (Most Recently Used) for the RDP client
$mruPath = "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default"
if (-not (Test-Path $mruPath)) { New-Item -Path $mruPath -Force | Out-Null }
Set-ItemProperty -Path $mruPath -Name "MRU0" -Value "${subnetRef}.20" -Force
Set-ItemProperty -Path $mruPath -Name "MRU1" -Value "${subnetRef}.50" -Force

Write-Phase "RDP history planted (shows connections to .20 and .50)."
Write-Phase "[Section] RDP history completed."
} catch {
    Write-Warning "[Section] RDP history failed: $_"
    $script:SectionFailures += ''RDP-History''
}

# ═══════════════════════════════════════════════════════════════
#  5. PLANT POWERSHELL HISTORY (equivalent of .bash_history)
# ═══════════════════════════════════════════════════════════════
try {
Write-Phase "[Section] Planting PowerShell history..."

$psHistoryDir = "C:\Users\m.chen\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
if (-not (Test-Path $psHistoryDir)) { New-Item -Path $psHistoryDir -ItemType Directory -Force | Out-Null }

@"
Get-Service | Where-Object {`$_.Status -eq ''Running''}
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
Write-Phase "[Section] PowerShell history completed."
} catch {
    Write-Warning "[Section] PowerShell history failed: $_"
    $script:SectionFailures += ''PSHistory''
}

# ═══════════════════════════════════════════════════════════════
#  6. PLANT ADDITIONAL BREADCRUMBS
# ═══════════════════════════════════════════════════════════════
try {
Write-Phase "[Section] Planting additional breadcrumbs..."

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

# Plant a file on Administrator''s Desktop too (only visible after privesc)
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
Write-Phase "[Section] Breadcrumbs completed."
} catch {
    Write-Warning "[Section] Breadcrumbs failed: $_"
    $script:SectionFailures += ''Breadcrumbs''
}

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
if ($script:SectionFailures.Count -eq 0) {
    Write-Phase "Plant-Loot completed successfully."
    exit 0
} else {
    Write-Warning "Completed with failures in: $($script:SectionFailures -join '', '')"
    exit 1
}
',	'[]',	'{win-480-config-users}',	60,	'1',	'2026-04-15 07:17:53.478858+00',	'',	'vulnerable'),
('72d89d79-25af-4fbf-8827-e8fdf04af28b',	'win-480-config-users',	'Configure 480 Users',	'Creates m.chen (standard user, RDP + WinRM groups, password MedAlliance2024! matches the Linux loot), MedHealthSvc service account, sets a strong Administrator password only accessible via privesc, and plants a cmdkey saved credential for the stored-creds privesc path. Also drops personal_notes.txt in m.chen''s docs with passwords written down like a real IT admin''s sticky note.',	'User Simulation',	'windows',	'intermediate',	'<#
.SYNOPSIS
    Creates local user accounts and group memberships for MedAlliance-WIN T1.

.NOTES
    Users:
      m.chen         — standard user, RDP + WinRM access, primary student target
      MedHealthSvc   — service account for the Health Monitor service
      Administrator  — built-in, strong-ish password (accessed via privesc only)

    The m.chen password matches credentials planted on the Linux target''s
    /root/.admin_creds.txt — this is the credential-reuse bridge.
#>

$ErrorActionPreference = "Continue"
$script:SectionFailures = @()

function Write-Phase {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format ''HH:mm:ss'')][Users] $Msg"
}

# ── Load deploy-context marker (written by Install-Services.ps1) ──
$ctxPath = "C:\ProgramData\MedAlliance\deploy-context.json"
if (Test-Path $ctxPath) {
    try {
        $ctx = Get-Content $ctxPath -Raw | ConvertFrom-Json
        $script:IsServer = [bool]$ctx.IsServer
        Write-Phase "Loaded deploy context: IsServer=$script:IsServer ($($ctx.OSCaption))"
    } catch {
        $script:IsServer = ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)
    }
} else {
    $script:IsServer = ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)
    Write-Phase "No deploy context marker — detected IsServer=$script:IsServer"
}

# ── Helper: create local user safely (idempotent) ──
# If the user already exists we update password + attributes instead of erroring.
function New-LabUser {
    param(
        [string]$Username,
        [string]$Password,
        [string]$FullName,
        [string]$Description,
        [switch]$PasswordNeverExpires,
        [switch]$CannotChangePassword
    )

    $secPass = ConvertTo-SecureString $Password -AsPlainText -Force
    $existing = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue

    if ($existing) {
        Set-LocalUser -Name $Username -Password $secPass -FullName $FullName -Description $Description -ErrorAction SilentlyContinue
        if ($PasswordNeverExpires) {
            Set-LocalUser -Name $Username -PasswordNeverExpires $true -ErrorAction SilentlyContinue
        }
        Write-Phase "Updated existing user: $Username ($FullName)"
    } else {
        $params = @{
            Name        = $Username
            Password    = $secPass
            FullName    = $FullName
            Description = $Description
        }
        New-LocalUser @params -ErrorAction SilentlyContinue | Out-Null
        if ($PasswordNeverExpires) {
            Set-LocalUser -Name $Username -PasswordNeverExpires $true -ErrorAction SilentlyContinue
        }
        Write-Phase "Created user: $Username ($FullName)"
    }
}

# ── Helper: add to group only if not already a member ──
function Add-LabGroupMember {
    param([string]$Group, [string]$Member)
    try {
        $already = Get-LocalGroupMember -Group $Group -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -like "*\$Member" -or $_.Name -eq $Member }
        if (-not $already) {
            Add-LocalGroupMember -Group $Group -Member $Member -ErrorAction SilentlyContinue
            Write-Phase "  Added $Member to ''$Group''."
        } else {
            Write-Phase "  $Member already in ''$Group''."
        }
    } catch {
        Write-Warning "  Could not add $Member to $Group : $_"
    }
}

# ═══════════════════════════════════════════════════════════════
#  1. SET ADMINISTRATOR PASSWORD
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Setting Administrator password..."

    $adminPass = ConvertTo-SecureString ''MedAll!ance#Adm1n2024'' -AsPlainText -Force
    if (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue) {
        Set-LocalUser -Name "Administrator" -Password $adminPass -PasswordNeverExpires $true -ErrorAction SilentlyContinue
    }
    # Not planted anywhere — students must escalate to find it
    # (or crack from SAM dump after getting SYSTEM)

    Write-Phase "Administrator password set (strong — not planted, must escalate)."
    Write-Phase "[Section] Administrator password completed."
} catch {
    Write-Warning "[Section] Administrator password failed: $_"
    $script:SectionFailures += ''AdminPassword''
}

# ═══════════════════════════════════════════════════════════════
#  2. CREATE m.chen — NETWORK ADMINISTRATOR
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Creating m.chen..."
    New-LabUser -Username "m.chen" `
        -Password "MedAlliance2024!" `
        -FullName "Marcus Chen" `
        -Description "IT Network Admin - MedAlliance Health" `
        -PasswordNeverExpires

    # Add to groups for RDP and WinRM access
    Add-LabGroupMember -Group "Remote Desktop Users"    -Member "m.chen"
    Add-LabGroupMember -Group "Remote Management Users" -Member "m.chen"
    # NOT in Administrators — this is a standard user (privesc required)

    Write-Phase "[Section] m.chen completed."
} catch {
    Write-Warning "[Section] m.chen failed: $_"
    $script:SectionFailures += ''m.chen''
}

# ═══════════════════════════════════════════════════════════════
#  3. CREATE MedHealthSvc — SERVICE ACCOUNT
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Creating MedHealthSvc service account..."
    New-LabUser -Username "MedHealthSvc" `
        -Password "H3althM0n!tor2024" `
        -FullName "Health Monitor Service" `
        -Description "MedAlliance Health Monitor service" `
        -PasswordNeverExpires -CannotChangePassword

    # SeImpersonatePrivilege is granted automatically when the service is created
    # in Plant-Vulns.ps1 (inherent to service accounts running as a service).

    Write-Phase "[Section] MedHealthSvc completed."
} catch {
    Write-Warning "[Section] MedHealthSvc failed: $_"
    $script:SectionFailures += ''MedHealthSvc''
}

# ═══════════════════════════════════════════════════════════════
#  4. ENABLE GUEST ACCOUNT (for SMB anonymous access)
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Enabling Guest account for SMB share access..."

    net user Guest /active:yes 2>&1 | Out-Null

    # Allow network access for Guest (needed for "Everyone" SMB shares)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

    Write-Phase "Guest account enabled."
    Write-Phase "[Section] Guest completed."
} catch {
    Write-Warning "[Section] Guest failed: $_"
    $script:SectionFailures += ''Guest''
}

# ═══════════════════════════════════════════════════════════════
#  5. CONFIGURE SAVED CREDENTIALS (for privesc W-PRIV-04)
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Planting saved credential (cmdkey)..."

    # Store a credential that m.chen can use via runas /savecred
    # This simulates someone having saved RDP creds to the server
    cmdkey /generic:MEDALLIANCE-WIN /user:Administrator /pass:MedAll!ance#Adm1n2024 2>&1 | Out-Null

    # cmdkey stores in the *current* user''s vault. We also schedule a run-as-m.chen
    # task to plant it in m.chen''s vault on first login.
    $labSetup = "C:\LabSetup"
    if (-not (Test-Path $labSetup)) {
        New-Item -Path $labSetup -ItemType Directory -Force | Out-Null
    }

    $plantCredScript = @"
cmdkey /generic:MEDALLIANCE-WIN /user:Administrator /pass:MedAll!ance#Adm1n2024
"@
    Set-Content -Path "$labSetup\plant_cred.bat" -Value $plantCredScript -Encoding ASCII -Force

    # Create a RunOnce task as m.chen to plant the saved cred on first login
    $action   = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\LabSetup\plant_cred.bat"
    $trigger  = New-ScheduledTaskTrigger -AtLogOn -User "m.chen"
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    # Idempotency: remove any prior copy of the task before re-registering.
    Unregister-ScheduledTask -TaskName "PlantCred" -Confirm:$false -ErrorAction SilentlyContinue

    Register-ScheduledTask -TaskName "PlantCred" -Action $action -Trigger $trigger `
        -Settings $settings -User "m.chen" -Password "MedAlliance2024!" `
        -RunLevel Highest -Force -ErrorAction SilentlyContinue | Out-Null

    Write-Phase "Saved credential will be planted on m.chen''s first login."
    Write-Phase "[Section] Saved credential completed."
} catch {
    Write-Warning "[Section] Saved credential failed: $_"
    $script:SectionFailures += ''SavedCred''
}

Write-Phase "Users and groups fully configured."

# ═══════════════════════════════════════════════════════════════
#  6. CREATE USER PROFILE DIRECTORIES AND CONTENT
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Creating user profile content..."

    $mchenProfile = "C:\Users\m.chen"
    $mchenDesktop = "$mchenProfile\Desktop"
    $mchenDocs    = "$mchenProfile\Documents"
    if (-not (Test-Path $mchenDesktop)) { New-Item -Path $mchenDesktop -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path $mchenDocs))    { New-Item -Path $mchenDocs    -ItemType Directory -Force | Out-Null }

    # Plant personal_notes.txt — load-bearing: content referenced in lab guides.
    @"
MedAlliance Health Partners — Personal Notes
=============================================
Marcus Chen — Network Administrator

Todo:
- [ ] Rotate SQL SA password (it''s been the same for 8 months... yikes)
- [ ] Disable xp_cmdshell on SQLEXPRESS (why was this ever enabled??)
- [ ] Fix the Health Monitor service — it keeps running as SYSTEM
- [ ] Talk to j.thompson about the Linux server backups
- [ ] Check if the daily_report.bat script is still world-writable
- [x] Set up RDP access for the new hires
- [x] Configure WinRM for remote management

Passwords I need to remember:
- My Windows login: MedAlliance2024! (same across all systems... I know, I know)
- SQL SA: SQLAdmin2024!
- Health Monitor dashboard: admin/admin (need to change this)
- Linux SSH: j.thompson / Fall2024Med!

Note to self: Stop reusing passwords across systems. Set up a password
manager for the team before the next audit.

Last updated: 2024-11-10
"@ | Set-Content -Path "$mchenDocs\personal_notes.txt" -Encoding UTF8 -Force

    # Grant m.chen ownership of their profile (best-effort)
    try {
        $acl  = Get-Acl $mchenProfile
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "m.chen", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl $mchenProfile $acl -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "  Could not set ACL on $mchenProfile : $_"
    }

    Write-Phase "User profile content planted."
    Write-Phase "[Section] Profile content completed."
} catch {
    Write-Warning "[Section] Profile content failed: $_"
    $script:SectionFailures += ''ProfileContent''
}

# ═══════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════
Write-Phase ""
if ($script:SectionFailures.Count -eq 0) {
    Write-Phase "Configure-Users completed successfully."
    exit 0
} else {
    Write-Warning "Completed with failures in: $($script:SectionFailures -join '', '')"
    exit 1
}
',	'[]',	'{}',	60,	'1',	'2026-04-15 07:10:00.485495+00',	'',	'vulnerable'),
('6f57bf05-8ad8-4029-8b6c-dca00d0177e9',	'win-480-config-shares',	'Configure 480 Shares',	'Creates SMB shares and populates them with realistic documents containing planted credentials, network info, and sensitive data for MedAlliance-WIN T1.',	'Data Exfiltration',	'windows',	'intermediate',	'<#
.SYNOPSIS
    Creates SMB shares and populates them with realistic documents containing
    planted credentials, network info, and sensitive data for MedAlliance-WIN T1.

.NOTES
    Shares:
      Company_Docs  — Guest/Everyone read — org chart, policies, non-sensitive
      IT_Docs       — Guest/Everyone read — network diagrams, server notes (SA password!)
      HR_Files      — m.chen read only    — PII spreadsheets, employee data
      Scripts       — m.chen read/write   — scheduled task scripts (writable = privesc)
#>

param(
    [Parameter(Mandatory=$true)][string]$WinIP
)

$ErrorActionPreference = "Continue"
$script:SectionFailures = @()
$subnetRef = $WinIP -replace ''\.\d+$'', ''''  # e.g., 192.168.10

function Write-Phase {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format ''HH:mm:ss'')][Shares] $Msg"
}

# ── Load deploy-context marker (written by Install-Services.ps1) ──
$ctxPath = "C:\ProgramData\MedAlliance\deploy-context.json"
if (Test-Path $ctxPath) {
    try {
        $ctx = Get-Content $ctxPath -Raw | ConvertFrom-Json
        $script:IsServer = [bool]$ctx.IsServer
        Write-Phase "Loaded deploy context: IsServer=$script:IsServer"
    } catch {
        $script:IsServer = ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)
    }
} else {
    $script:IsServer = ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1)
}

# ═══════════════════════════════════════════════════════════════
#  1. CREATE SHARE DIRECTORIES
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Creating share directories..."
    $shareBase = "C:\Shares"
    $dirs = @(
        "$shareBase\Company_Docs",
        "$shareBase\Company_Docs\Policies",
        "$shareBase\Company_Docs\Templates",
        "$shareBase\IT_Docs",
        "$shareBase\IT_Docs\Network",
        "$shareBase\IT_Docs\Procedures",
        "$shareBase\HR_Files",
        "$shareBase\HR_Files\Onboarding",
        "$shareBase\HR_Files\Payroll"
    )
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
    }
    Write-Phase "Share directories created."
} catch {
    Write-Warning "[Section] Share directories failed: $_"
    $script:SectionFailures += ''ShareDirs''
}
$shareBase = "C:\Shares"

# ═══════════════════════════════════════════════════════════════
#  2. POPULATE COMPANY_DOCS (non-sensitive, but leaks usernames)
# ═══════════════════════════════════════════════════════════════

# Org chart — leaks names, titles, reporting structure
@"
MedAlliance Health Partners — Organization Chart
=================================================
Last Updated: October 2024

EXECUTIVE TEAM
  Amanda Foster          CFO                      a.foster@medalliance.local
  Stephanie White        Compliance Officer        s.white@medalliance.local

IT DEPARTMENT (Reports to: Marcus Chen)
  Marcus Chen            Network Administrator     m.chen@medalliance.local
  Jennifer Thompson      Sr. Systems Engineer      j.thompson@medalliance.local
  Daniel Lee             Security Analyst           d.lee@medalliance.local
  James Wilson           Help Desk Technician       j.wilson@medalliance.local
  Thomas Martinez        Jr. Network Tech           t.martinez@medalliance.local

HR DEPARTMENT (Reports to: Sarah Mitchell)
  Sarah Mitchell         HR Director                s.mitchell@medalliance.local
  Lisa Anderson          Recruiter                  l.anderson@medalliance.local
  Nicole Harris          Benefits Coordinator       n.harris@medalliance.local

FINANCE (Reports to: Amanda Foster)
  David Park             Financial Analyst          d.park@medalliance.local
  Andrew Wright          Senior Accountant          a.wright@medalliance.local
  Michael Davis          Accounts Payable           m.davis@medalliance.local

CLINICAL SYSTEMS (Reports to: Robert Garcia)
  Robert Garcia          Clinical Systems Manager   r.garcia@medalliance.local
  Rachel Kim             Clinical Informatics       r.kim@medalliance.local
  Jessica Clark          EHR Support Specialist     j.clark@medalliance.local
  Maria Rodriguez        Data Entry Specialist      m.rodriguez@medalliance.local

OPERATIONS (Reports to: Kevin Brown)
  Kevin Brown            Office Manager             k.brown@medalliance.local
  Christopher Moore      Facilities Manager         c.moore@medalliance.local
  Emily Taylor           Receptionist               e.taylor@medalliance.local

Total employees: 20
"@ | Set-Content "$shareBase\Company_Docs\org_chart.txt" -Encoding UTF8

# Acceptable use policy
@"
MedAlliance Health Partners
ACCEPTABLE USE POLICY
Version 3.2 — Effective January 2024

1. PURPOSE
This policy defines acceptable use of MedAlliance IT resources including
workstations, servers, network equipment, and cloud services.

2. SCOPE
Applies to all employees, contractors, and third-party users with access
to MedAlliance systems.

3. GENERAL USE
- Company equipment is for business purposes. Limited personal use is permitted.
- Users must not share credentials or use another person''s account.
- All systems require individual login credentials.
- Remote access is permitted via RDP and VPN with MFA where available.

4. PASSWORDS
- Minimum 8 characters with complexity (upper, lower, digit, special).
- Must be changed every 90 days.
- Do not reuse passwords across systems.
  NOTE: We are aware this policy is not consistently enforced.
  A password manager rollout is planned for Q2 2025.

5. DATA HANDLING
- All patient data (PHI) must be handled per HIPAA requirements.
- PHI must not be stored on personal devices or unencrypted media.
- File transfers of PHI must use approved secure methods only.

6. PROHIBITED ACTIVITIES
- Unauthorized scanning or testing of network systems.
- Installation of unauthorized software.
- Sharing of credentials or access tokens.
- Accessing data not required for your role.

7. ENFORCEMENT
Violations may result in disciplinary action up to termination.
Security incidents must be reported to d.lee@medalliance.local or IT at ext 4200.

Approved by: S. White, Compliance Officer
Effective: January 15, 2024
"@ | Set-Content "$shareBase\Company_Docs\Policies\acceptable_use_policy.txt" -Encoding UTF8

# Employee handbook excerpt
@"
MedAlliance Health Partners — Employee Quick Reference
======================================================

IMPORTANT CONTACTS:
  IT Support         ext 4200    it-support@medalliance.local
  HR Department      ext 3100    hr@medalliance.local
  Facilities         ext 2500    facilities@medalliance.local
  Security Incidents ext 4201    d.lee@medalliance.local

SYSTEMS ACCESS:
  New employees receive credentials on day 1 from IT.
  Default password format: [Season][Year][Company abbreviation]!
  Example: Fall2024Med!
  Change immediately upon first login.

  File shares: \\MEDALLIANCE-WIN (connect via Windows Explorer)
  Email: Outlook Web Access at https://medalliance-lnx/webmail
  Remote: RDP to MEDALLIANCE-WIN (ask IT for access)

HIPAA REMINDER:
  You are responsible for protecting patient health information (PHI).
  Report any suspected breaches immediately to Compliance.

WiFi:
  Corporate: MedAlliance-Corp (WPA2-Enterprise, use your credentials)
  Guest: MedAlliance-Guest (posted in lobby, no internal access)

Last updated: September 2024
"@ | Set-Content "$shareBase\Company_Docs\employee_quick_reference.txt" -Encoding UTF8

Write-Phase "Company_Docs populated."

# ═══════════════════════════════════════════════════════════════
#  3. POPULATE IT_DOCS (contains SA password — key breadcrumb)
# ═══════════════════════════════════════════════════════════════

# Server setup notes — THE KEY FILE (contains MSSQL SA password)
@"
MedAlliance IT — Server Configuration Notes
=============================================
Author: Marcus Chen (m.chen)
Last Updated: 2024-09-15

SERVER: MEDALLIANCE-WIN (${WinIP})
  OS: Windows Server 2019 Standard (Desktop Experience)
  Role: Application server, file server, database host
  Hostname: MEDALLIANCE-WIN
  Domain: Workgroup (WORKGROUP) — not domain-joined

INSTALLED SERVICES:
  IIS 10.0
    - Default site on port 80 (corporate landing)
    - Health Monitor dashboard on port 8080 (admin/admin — CHANGE THIS)
    - FTP on port 21 (anonymous read for logs)

  SQL Server 2019 Express (Instance: SQLEXPRESS)
    - Port: 1433
    - SA Account: ENABLED
    - SA Password: SQLAdmin2024!
    - xp_cmdshell: enabled (required by Health Monitor agent for system checks)
    - Databases: hr_database, app_config

    *** TODO: Disable SA and xp_cmdshell once app is migrated to Windows Auth ***
    *** This has been on my todo list for 6 months. I know. ***

  Remote Desktop (port 3389)
    - NLA enabled
    - Authorized users: m.chen, Administrators

  WinRM (port 5985)
    - HTTP transport (no HTTPS yet)
    - Authorized: m.chen, Administrators
    - Basic auth: enabled (for compatibility with monitoring tools)

  Health Monitor Agent
    - Binary: C:\Program Files\MedAlliance\Health Monitor\agent.exe
    - Runs as: MedHealthSvc service account
    - Checks system health hourly
    - NOTE: service path has spaces and is not quoted in registry

SERVER: medalliance-lnx (${subnetRef}.20)
  OS: Ubuntu 22.04 LTS
  Role: Web server, mail, file storage
  SSH: j.thompson / Fall2024Med!  (Marcus: consider key-based auth)
  Web: Apache + PHP patient portal (MySQL backend)
  MySQL: medportal / Welcome2024!

BACKUP SCHEDULE:
  SQL backups: daily at 02:00 via C:\Scripts\backup_databases.bat
  File share backup: weekly Sunday via robocopy to NAS

KNOWN ISSUES:
  - Windows Defender real-time protection disabled (Health Monitor compatibility)
  - Windows Update paused (EMR migration — re-enable after Q1 2025)
  - daily_report.bat is world-writable (low priority — only runs on this server)
  - FTP anonymous access should be restricted to specific IPs
  - SA password has been the same since March 2024
"@ | Set-Content "$shareBase\IT_Docs\server_setup_notes.txt" -Encoding UTF8

# Network diagram (text-based)
@"
MedAlliance Health Partners — Network Topology
===============================================
Last Updated: 2024-09-01 by M. Chen

INTERNAL NETWORK: ${subnetRef}.0/24

  ${subnetRef}.1     Gateway / Router
  ${subnetRef}.10    Kali Linux (Pentest / Admin workstation)
  ${subnetRef}.20    medalliance-lnx    Ubuntu 22.04  (Web, Mail, Files)
  ${subnetRef}.30    MEDALLIANCE-WIN    Win Srv 2019  (Apps, DB, Shares)
  ${subnetRef}.50    MEDALLIANCE-DC     Win Srv 2019  (Domain Controller)

NOTE: The DC at .50 handles Active Directory for the main office.
      MEDALLIANCE-WIN is NOT domain-joined (standalone workgroup server).
      We plan to join it to the domain in Q2 2025.

SERVICES MAP:

  medalliance-lnx (${subnetRef}.20):
    22/tcp   SSH (OpenSSH 8.9)
    21/tcp   FTP (vsftpd)
    25/tcp   SMTP (Postfix)
    80/tcp   HTTP (Apache — Patient Portal)
    445/tcp  SMB (Samba)
    3306/tcp MySQL
    161/udp  SNMP

  MEDALLIANCE-WIN (${subnetRef}.30):
    21/tcp   FTP (IIS FTP)
    80/tcp   HTTP (IIS — Corporate landing)
    445/tcp  SMB (Windows shares)
    1433/tcp MSSQL (SQL Server 2019 Express)
    3389/tcp RDP
    5985/tcp WinRM
    8080/tcp HTTP (Health Monitor dashboard)

FIREWALL: None between internal hosts (flat network).
          Perimeter firewall at gateway — not in scope for this engagement.
"@ | Set-Content "$shareBase\IT_Docs\Network\network_diagram.txt" -Encoding UTF8

# IT procedures
@"
MedAlliance IT — New Server Deployment Checklist
=================================================
Author: Jennifer Thompson (j.thompson)

1. [ ] Install OS from approved image
2. [ ] Apply latest Windows Updates
3. [ ] Set hostname per naming convention (MEDALLIANCE-[ROLE])
4. [ ] Create service accounts with unique passwords
5. [ ] Configure Windows Firewall rules
6. [ ] Enable and configure WinRM for remote management
7. [ ] Install required services (IIS, SQL, etc.)
8. [ ] Configure SQL with Windows Authentication (NOT mixed mode)
9. [ ] Disable SA account after initial setup
10.[ ] Disable xp_cmdshell unless absolutely required
11.[ ] Enable Windows Defender real-time protection
12.[ ] Enable audit logging (Security, System, Application)
13.[ ] Schedule automated backups
14.[ ] Document configuration in IT_Docs share
15.[ ] Notify Security Analyst (d.lee) for baseline scan

NOTE: As of 2024-11-10, MEDALLIANCE-WIN does NOT comply with steps
3, 5, 6, 8, 9, 10, 11, or 12. This is a known gap. — J.T.
"@ | Set-Content "$shareBase\IT_Docs\Procedures\new_server_checklist.txt" -Encoding UTF8

@"
MedAlliance IT — Password Rotation Schedule
============================================

System                  Account         Last Rotated    Next Due       Status
----------------------  ----------      ------------    ----------     ------
MEDALLIANCE-WIN         Administrator   2024-01-15      2024-04-15     OVERDUE
MEDALLIANCE-WIN         m.chen          2024-09-01      2024-12-01     Current
MEDALLIANCE-WIN         MedHealthSvc    2024-01-15      2024-04-15     OVERDUE
SQL Server (SA)         sa              2024-03-15      2024-06-15     OVERDUE
medalliance-lnx         j.thompson      2024-10-01      2025-01-01     Current
medalliance-lnx         root            NEVER           ASAP           CRITICAL
FTP Service             anonymous       N/A             N/A            N/A

Notes:
- MedHealthSvc and SA passwords are both overdue. Schedule for next maintenance window.
- root password on Linux has never been rotated. Escalate to M. Chen.
- m.chen uses the same password on Windows and Linux. Accepted risk until
  password manager rollout (Q2 2025).
"@ | Set-Content "$shareBase\IT_Docs\Procedures\password_rotation.txt" -Encoding UTF8

Write-Phase "IT_Docs populated (contains SA password in server_setup_notes.txt)."

# ═══════════════════════════════════════════════════════════════
#  4. POPULATE HR_FILES (requires m.chen auth — PII data)
# ═══════════════════════════════════════════════════════════════

@"
CONFIDENTIAL — MedAlliance Health Partners
Employee Contact Directory (HR Internal Use Only)
===================================================

Name                  Dept        Phone           Personal Email              Emergency Contact
----                  ----        -----           --------------              -----------------
Marcus Chen           IT          (555) 234-5678  marcus.chen84@gmail.com     Linda Chen (wife)
Jennifer Thompson     IT          (555) 345-6789  jthompson_home@yahoo.com    Mark Thompson (husband)
David Park            Finance     (555) 456-7890  dpark92@outlook.com         Yuna Park (mother)
Sarah Mitchell        HR          (555) 567-8901  sarahm_az@gmail.com         Tom Mitchell (spouse)
Robert Garcia         Clinical    (555) 678-9012  rgarcia.personal@gmail.com  Maria Garcia (wife)
Amanda Foster         Finance     (555) 789-0123  afoster_exec@icloud.com     James Foster (husband)
James Wilson          IT          (555) 890-1234  jwilson.tech@gmail.com      Patricia Wilson (mother)
Maria Rodriguez       Clinical    (555) 901-2345  maria.r.2001@hotmail.com    Carlos Rodriguez (father)
Kevin Brown           Operations  (555) 012-3456  kbrown_ops@gmail.com        Diana Brown (wife)
Lisa Anderson         HR          (555) 123-4567  lisaanderson@yahoo.com      Michael Anderson (brother)

*** DO NOT DISTRIBUTE OUTSIDE HR DEPARTMENT ***
*** HIPAA/PII — Handle per data classification policy ***
"@ | Set-Content "$shareBase\HR_Files\employee_directory_CONFIDENTIAL.txt" -Encoding UTF8

@"
MedAlliance Health Partners — New Hire Onboarding
==================================================
IT Setup Checklist for New Employees

1. Create Windows account (standard user)
   - Default password: [Season][Year]Med!  (e.g., Fall2024Med!)
   - User must change at first login
   - Add to "Remote Desktop Users" if remote worker

2. Create email account on medalliance-lnx
   - Format: [first initial].[lastname]@medalliance.local

3. Grant share access:
   - Company_Docs: all employees (read)
   - Department share: per manager request
   - HR_Files: HR staff only

4. Issue hardware:
   - Laptop (Dell Latitude 5540 from IT closet)
   - Badge (request from Facilities)

5. Schedule HIPAA training within first 2 weeks.
6. Add to company org chart (Company_Docs share).
"@ | Set-Content "$shareBase\HR_Files\Onboarding\it_setup_checklist.txt" -Encoding UTF8

Write-Phase "HR_Files populated."

# ═══════════════════════════════════════════════════════════════
#  5. CREATE SMB SHARES WITH PERMISSIONS
# ═══════════════════════════════════════════════════════════════
try {
    Write-Phase "[Section] Creating SMB shares..."

    if (-not (Get-Command New-SmbShare -ErrorAction SilentlyContinue)) {
        Write-Warning "[Shares] New-SmbShare unavailable — SMB share creation skipped."
        $script:SectionFailures += ''SMB-Shares''
    } else {
        # Remove existing shares (idempotent)
        foreach ($shareName in @("Company_Docs", "IT_Docs", "HR_Files")) {
            if (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue) {
                Remove-SmbShare -Name $shareName -Force -ErrorAction SilentlyContinue
            }
        }

        # Company_Docs — Everyone read (including Guest/anonymous)
        New-SmbShare -Name "Company_Docs" -Path "$shareBase\Company_Docs" `
            -ReadAccess "Everyone" -Description "Company documents — all staff" `
            -FullAccess "Administrators" -ErrorAction SilentlyContinue | Out-Null

        # IT_Docs — Everyone read (intentionally too open — a finding)
        New-SmbShare -Name "IT_Docs" -Path "$shareBase\IT_Docs" `
            -ReadAccess "Everyone" -Description "IT documentation and procedures" `
            -FullAccess "Administrators" -ErrorAction SilentlyContinue | Out-Null

        # HR_Files — only m.chen and Administrators (dept-level restriction)
        New-SmbShare -Name "HR_Files" -Path "$shareBase\HR_Files" `
            -ReadAccess "m.chen" -Description "HR confidential files" `
            -FullAccess "Administrators" -ErrorAction SilentlyContinue | Out-Null

        # Verify shares
        Get-SmbShare | Where-Object { $_.Name -notin @(''ADMIN$'',''C$'',''IPC$'') } |
            Format-Table Name, Path, Description -AutoSize | Out-String | Write-Host

        Write-Phase "SMB shares created and permissioned."
    }
    Write-Phase "[Section] SMB shares completed."
} catch {
    Write-Warning "[Section] SMB shares failed: $_"
    $script:SectionFailures += ''SMB-Shares''
}

# ═══════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════
Write-Phase ""
if ($script:SectionFailures.Count -eq 0) {
    Write-Phase "Configure-Shares completed successfully."
    exit 0
} else {
    Write-Warning "Completed with failures in: $($script:SectionFailures -join '', '')"
    exit 1
}
',	'[]',	'{win-install-480-services}',	60,	'1',	'2026-04-15 18:22:39.152619+00',	'',	'vulnerable'),
('dc199d42-60d2-4833-b557-518742609d5c',	'win-start-ssh',	'Start SSH',	'Standalone SSH Service, no vulnerabilities built in',	'Network Services',	'windows',	'beginner',	'Write-Host "==> Configuring SSH"
Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service sshd -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name "DefaultShell" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null
Write-Host "==> SSH Status:"
Get-Service sshd | Select-Object Status, StartType | Format-Table -AutoSize
$listener = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 22 }
Write-Host "Port 22: $(if ($listener) { ''LISTENING'' } else { ''NOT LISTENING'' })"
',	'["22/SSH"]',	'{}',	60,	'1',	'2026-04-15 00:43:33.227957+00',	'',	'baseline'),
('344cf57e-80be-4a46-bf65-67c0c1e9a2ef',	'win-owasp-start',	'Start OWASP Juiceshop',	'',	'Web Server',	'windows',	'intermediate',	'$ErrorActionPreference = "Stop"

$LabRoot    = "C:\LabApps"
$StateDir   = Join-Path $LabRoot "state"
$LogsDir    = Join-Path $LabRoot "logs"
$VulnDir    = Join-Path $LabRoot "targets\VulnServer"
$ConfigPath = Join-Path $StateDir "runtime.json"

$ProgressLog = "C:\LabApps\progress.log"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
    Add-Content -Path $ProgressLog -Value "[$(Get-Date -Format ''HH:mm:ss'')] $Message" -ErrorAction SilentlyContinue
}

# Load config
if (-not (Test-Path $ConfigPath)) { throw "No config found. Run owasp-setup first." }
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

if (-not (Test-Path $config.JavaExe)) { throw "Java not found at $($config.JavaExe)" }
$nodeExe = $config.NodeExe
if (-not (Test-Path $nodeExe)) {
    # Try system PATH (installed via MSI)
    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    if ($nodeCmd) { $nodeExe = $nodeCmd.Source } else {
        if (Test-Path "C:\Program Files\nodejs\node.exe") { $nodeExe = "C:\Program Files\nodejs\node.exe" }
    }
}
if (-not (Test-Path $nodeExe)) { throw "Node not found" }
$config | Add-Member -NotePropertyName NodeExe -NotePropertyValue $nodeExe -Force -ErrorAction SilentlyContinue
if (-not (Test-Path $config.WebGoatJar)) { throw "WebGoat not found at $($config.WebGoatJar)" }
if (-not (Test-Path $config.VulnServerExe)) { throw "VulnServer not found at $($config.VulnServerExe)" }

if (-not (Test-Path $LogsDir)) { New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null }

# Stop any existing processes
Write-Step "Stopping existing services"
foreach ($port in @(8080, 9091, 3000, 9999)) {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq $port } |
        ForEach-Object {
            if ($_.OwningProcess -gt 4) {
                try { Stop-Process -Id $_.OwningProcess -Force } catch {}
            }
        }
}

# Create launchers
$wgLauncher = Join-Path $StateDir "start_webgoat.ps1"
Set-Content $wgLauncher @"
`$ErrorActionPreference = ''Stop''
& ''$($config.JavaExe)'' -jar ''$($config.WebGoatJar)'' --webgoat.port=8080 --webwolf.port=9091 *>> ''$LogsDir\webgoat.log''
"@ -Encoding UTF8

$jsLauncher = Join-Path $StateDir "start_juiceshop.ps1"
Set-Content $jsLauncher @"
`$ErrorActionPreference = ''Stop''
Set-Location ''$($config.JuiceRoot)''
& ''$($config.NodeExe)'' build/app *>> ''$LogsDir\juiceshop.log''
"@ -Encoding UTF8

$vsLauncher = Join-Path $StateDir "start_vulnserver.ps1"
Set-Content $vsLauncher @"
`$ErrorActionPreference = ''Stop''
Set-Location ''$VulnDir''
& ''$($config.VulnServerExe)'' 9999 *>> ''$LogsDir\vulnserver.log''
"@ -Encoding UTF8

# Start services
Write-Step "Starting WebGoat (port 8080)"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$wgLauncher -WindowStyle Hidden

Write-Step "Starting Juice Shop (port 3000)"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$jsLauncher -WindowStyle Hidden

Write-Step "Starting VulnServer (port 9999)"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$vsLauncher -WindowStyle Hidden

Write-Step "Waiting for services..."
Start-Sleep -Seconds 10

# Check
$wg = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 8080 }
$js = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 3000 }
$vs = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 9999 }

Write-Host ""
Write-Host "=== Services Status ==="
Write-Host "WebGoat 8080:    $(if ($wg) { ''LISTENING'' } else { ''STARTING (Java is slow, wait 30-60s)'' })"
Write-Host "Juice Shop 3000: $(if ($js) { ''LISTENING'' } else { ''STARTING (wait 15s)'' })"
Write-Host "VulnServer 9999: $(if ($vs) { ''LISTENING'' } else { ''STARTING'' })"
',	'["3000", "8080"]',	'{}',	60,	'1',	'2026-04-13 20:50:02.642516+00',	'-Start',	'baseline');
-- 2026-04-24 01:32:32 UTC
