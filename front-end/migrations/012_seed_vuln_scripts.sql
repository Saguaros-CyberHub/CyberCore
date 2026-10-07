-- ============================================================================
-- Migration 012: Seed initial vulnerability scripts
-- These are placeholder entries — full script content should be loaded
-- via the admin UI or a separate seed script.
-- ============================================================================

INSERT INTO vuln_scripts (slug, name, description, category, os_target, difficulty, script_content, services_exposed, depends_on, estimated_runtime_sec) VALUES

-- Initial Setup
('init-setup', 'Initial Setup', 'Set execution policy, enable ICMP, configure firewall basics', 'Initial Setup', 'windows', 'beginner',
 '# Placeholder — load full script via admin UI',
 '[]', '{}', 30),

-- Compile Tools
('compile-chain', 'LLVM/MinGW Compile Chain', 'Install llvm-mingw toolchain for building exploits', 'Compile Tools', 'windows', 'advanced',
 '# Placeholder — load full script via admin UI',
 '[]', '{init-setup}', 120),

-- Network Services
('smb-config', 'SMB Shares & Null Session', 'Configure Public/Users/Drop SMB shares with optional null session access', 'Network Services', 'windows', 'beginner',
 '# Placeholder — load full script via admin UI',
 '["445/SMB"]', '{init-setup}', 30),

('ssh-config', 'OpenSSH Server & Artifacts', 'Install OpenSSH, seed SSH artifacts (known_hosts, keys, PuTTY sessions)', 'Network Services', 'windows', 'beginner',
 '# Placeholder — load full script via admin UI',
 '["22/SSH"]', '{init-setup}', 60),

('winrm-config', 'WinRM HTTP Listener', 'Enable WinRM HTTP listener for remote management', 'Network Services', 'windows', 'intermediate',
 '# Placeholder — load full script via admin UI',
 '["5985/WinRM"]', '{init-setup}', 30),

-- Web Applications
('owasp-vulnserver', 'OWASP Apps & VulnServer', 'Deploy WebGoat (8080), Juice Shop (3000), and VulnServer (9999)', 'Web Applications', 'windows', 'intermediate',
 '# Placeholder — load full script via admin UI',
 '["8080/WebGoat", "3000/JuiceShop", "9999/VulnServer"]', '{init-setup}', 300),

-- Web Server
('iis-config', 'IIS Web Server', 'Install and configure IIS with vulnerable web applications', 'Web Server', 'windows', 'intermediate',
 '# Placeholder — load full script via admin UI',
 '["80/HTTP", "443/HTTPS"]', '{init-setup}', 120),

-- User Simulation
('life-artifacts', 'User Simulation & Artifacts', 'Create USER2/ADMIN accounts, seed documents, CSV files, scripts across profiles and shares', 'User Simulation', 'windows', 'beginner',
 '# Placeholder — load full script via admin UI',
 '[]', '{init-setup}', 30),

-- Privilege Escalation
('weak-services', 'Weak Service Permissions', 'Create services with weak ACLs, unquoted paths, writable binaries', 'Privilege Escalation', 'windows', 'intermediate',
 '# Placeholder — load full script via admin UI',
 '[]', '{init-setup,life-artifacts}', 30),

('weak-tasks', 'Weak Scheduled Tasks', 'Create scheduled tasks with exploitable permissions for privilege escalation', 'Privilege Escalation', 'windows', 'intermediate',
 '# Placeholder — load full script via admin UI',
 '[]', '{init-setup,life-artifacts}', 30),

-- Persistence
('persistence-mechanisms', 'Persistence Mechanisms', 'Set up run keys, startup folder items, and scheduled task persistence', 'Persistence', 'windows', 'advanced',
 '# Placeholder — load full script via admin UI',
 '[]', '{init-setup,life-artifacts}', 30),

-- Defense Evasion
('defender-exclusions', 'Defender Exclusions', 'Add exclusion paths and reduce Defender protection for lab stability', 'Defense Evasion', 'windows', 'beginner',
 '# Placeholder — load full script via admin UI',
 '[]', '{init-setup}', 15)

ON CONFLICT (slug) DO NOTHING;

-- Seed one example challenge template
INSERT INTO challenge_templates (name, description, difficulty, vm_specs, phantom_assets, metadata) VALUES
('DunderCorp Network - Standard', 'Corporate Windows network with web services, SMB, SSH, and privilege escalation opportunities',
 'intermediate',
 '[
   {
     "name": "dc01",
     "role": "Domain Controller",
     "os": "Windows Server 2022",
     "template_vmid": null,
     "type": "qemu",
     "vm_offset": 600000,
     "default_scripts": ["init-setup", "smb-config", "ssh-config", "life-artifacts"],
     "services": ["53/DNS", "88/Kerberos", "389/LDAP", "445/SMB"]
   },
   {
     "name": "web01",
     "role": "Web/App Server",
     "os": "Windows 11 25H2",
     "template_vmid": null,
     "type": "qemu",
     "vm_offset": 610000,
     "default_scripts": ["init-setup", "owasp-vulnserver", "iis-config", "ssh-config", "weak-services"],
     "services": ["80/HTTP", "443/HTTPS", "8080/WebGoat", "3000/JuiceShop", "9999/VulnServer", "22/SSH"]
   },
   {
     "name": "files01",
     "role": "File Server",
     "os": "Windows Server 2022",
     "template_vmid": null,
     "type": "qemu",
     "vm_offset": 620000,
     "default_scripts": ["init-setup", "smb-config", "life-artifacts", "weak-tasks", "persistence-mechanisms"],
     "services": ["445/SMB", "5985/WinRM"]
   }
 ]'::jsonb,
 '[
   {"hostname": "filesrv-old", "ip": "10.20.14.15", "role": "Legacy File Server", "os": "Windows Server 2016", "notes": "Pending migration"},
   {"hostname": "backup-util", "ip": "10.30.5.18", "role": "Backup Utility Host", "os": "Ubuntu 22.04", "notes": "Review pending"},
   {"hostname": "print-core", "ip": "10.20.14.22", "role": "Print Server", "os": "Windows Server 2019", "notes": "Active"},
   {"hostname": "web-training", "ip": "10.30.5.41", "role": "Training Web Node", "os": "CentOS 8", "notes": "Active"},
   {"hostname": "vpn-gw01", "ip": "10.10.1.1", "role": "VPN Concentrator", "os": "Cisco ASA", "notes": "Primary"},
   {"hostname": "vpn-gw02", "ip": "10.10.1.2", "role": "VPN Concentrator", "os": "Cisco ASA", "notes": "Failover"},
   {"hostname": "erp-prod01", "ip": "10.50.10.5", "role": "ERP Application Server", "os": "Windows Server 2019", "notes": "Critical"}
 ]'::jsonb,
 '{"week_alignment": {"2": "Enumerate all services", "3": "Exploit VulnServer or web apps", "4": "Privilege escalation", "5": "Data exfiltration", "6": "Stealth and persistence", "7": "OWASP testing"}, "learning_objectives": ["Service enumeration", "Vulnerability exploitation", "Privilege escalation", "Lateral movement", "Data exfiltration"]}'::jsonb
)
ON CONFLICT DO NOTHING;
