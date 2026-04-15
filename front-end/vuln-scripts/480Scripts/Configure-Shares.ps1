<#
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
$subnetRef = $WinIP -replace '\.\d+$', ''  # e.g., 192.168.10

function Write-Phase {
    param([string]$Msg)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')][Shares] $Msg"
}

# ═══════════════════════════════════════════════════════════════
#  1. CREATE SHARE DIRECTORIES
# ═══════════════════════════════════════════════════════════════
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
foreach ($d in $dirs) { New-Item -Path $d -ItemType Directory -Force | Out-Null }

Write-Phase "Share directories created."

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
- Users must not share credentials or use another person's account.
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
Write-Phase "Creating SMB shares..."

# Remove existing shares (idempotent)
"Company_Docs", "IT_Docs", "HR_Files" | ForEach-Object {
    Remove-SmbShare -Name $_ -Force -ErrorAction SilentlyContinue
}

# Company_Docs — Everyone read (including Guest/anonymous)
New-SmbShare -Name "Company_Docs" -Path "$shareBase\Company_Docs" `
    -ReadAccess "Everyone" -Description "Company documents — all staff" `
    -FullAccess "Administrators"

# IT_Docs — Everyone read (this is intentionally too open — a finding)
New-SmbShare -Name "IT_Docs" -Path "$shareBase\IT_Docs" `
    -ReadAccess "Everyone" -Description "IT documentation and procedures" `
    -FullAccess "Administrators"

# HR_Files — only m.chen and Administrators (simulates dept-level restriction)
New-SmbShare -Name "HR_Files" -Path "$shareBase\HR_Files" `
    -ReadAccess "m.chen" -Description "HR confidential files" `
    -FullAccess "Administrators"

# Verify shares
Get-SmbShare | Where-Object { $_.Name -notin @('ADMIN$','C$','IPC$') } |
    Format-Table Name, Path, Description -AutoSize | Out-String | Write-Host

Write-Phase "SMB shares created and permissioned."
