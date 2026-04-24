$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

# Baseline WinRM: HTTPS listener with self-signed cert, Kerberos/Negotiate only,
# no Basic auth, no unencrypted. Use winrm-http.ps1 for the unencrypted variant.

Write-Step "Starting WinRM service"
Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name WinRM -ErrorAction SilentlyContinue

Write-Step "Bootstrapping PSRemoting (SkipNetworkProfileCheck)"
Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue | Out-Null

Write-Step "Creating self-signed certificate for HTTPS listener"
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$env:COMPUTERNAME" -and $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1' } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -ErrorAction SilentlyContinue
}

Write-Step "Configuring HTTPS listener on 5986"
if ($cert) {
    # Remove existing HTTPS listeners to avoid conflicts, then recreate
    & winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null | Out-Null
    & winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`";CertificateThumbprint=`"$($cert.Thumbprint)`"}" 2>$null | Out-Null
}

# Delete the default HTTP listener created by Enable-PSRemoting
& winrm delete winrm/config/Listener?Address=*+Transport=HTTP 2>$null | Out-Null

Write-Step "Hardening auth: Kerberos/Negotiate only, no Basic, no unencrypted"
& winrm set winrm/config/service           '@{AllowUnencrypted="false"}' 2>$null | Out-Null
& winrm set winrm/config/service/auth      '@{Basic="false";Kerberos="true";Negotiate="true";CredSSP="false"}' 2>$null | Out-Null
& winrm set winrm/config/client            '@{AllowUnencrypted="false"}' 2>$null | Out-Null
& winrm set winrm/config/client/auth       '@{Basic="false";Kerberos="true";Negotiate="true"}' 2>$null | Out-Null

Write-Step "Opening TCP/5986 (HTTPS) in firewall; removing 5985 if present"
New-NetFirewallRule -DisplayName "Lab-WinRM-5986-Allow" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
Get-NetFirewallRule -DisplayName "Lab-WinRM-5985-Allow" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== winrm-baseline complete ==="
Write-Host "HTTPS listener : 5986/TCP (self-signed cert)"
Write-Host "HTTP listener  : removed"
Write-Host "Auth           : Kerberos + Negotiate (no Basic)"
Write-Host "Unencrypted    : denied"
