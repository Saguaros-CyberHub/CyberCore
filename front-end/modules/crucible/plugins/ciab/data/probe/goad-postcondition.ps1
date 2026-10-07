<#
================================================================================
goad-postcondition.ps1 - assert what is ACTUALLY TRUE in a baked GOAD lab.
================================================================================

WHY THIS FILE EXISTS
GOAD's deploy is 16 separate ansible-playbook invocations and roughly 90 minutes.
Nothing in a host's vulnerabilities is even PARSED until ~95% of that. Worse, an
audit of the pinned tree found 20 places where a task reports SUCCESS and did
nothing at all. Three of those are shipped vulnerabilities that are silently not
there after a fully green run:

  vulns/adcs_esc7      `if (Get-Module -ListAvailable -Name PSPKI)` is INVERTED
                       (the grant lives in the else branch) and the task right
                       before it installs PSPKI - so the guard is always true and
                       ManageCA is never granted.
  move_to_ou           `$target_ou = Get-ADOrganizationalUnit -Identity $ou_path
                       > $null` sends the success stream to $null, so $target_ou
                       is ALWAYS null; and a bad OU path throws
                       ADIdentityNotFoundException straight into a typed catch
                       that sets Changed=$false and returns green.
  vulns/no_ldap_signing writes HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
                       LDAPServerSigningRequirements - a path Windows does not
                       read. Its sibling no_ldap_integrity writes the path
                       Windows DOES read (NTDS\Parameters).

Tree-wide, `changed_when` appears exactly TWICE and `error_action: stop` SIX
times. So neither Ansible's "changed" flag nor its exit code carries information
about whether the lab is actually vulnerable. The only thing that does is asking
the deployed environment directly. That is this script.

WHAT IT DOES AND DELIBERATELY DOES NOT DO
It asserts PRECONDITIONS the intended attack chain needs - an ACE exists, an SPN
exists, a file is on disk, a computer is under the OU - not exploits. Executing a
chain needs tooling, credentials, network position and time, and when it fails it
tells you "the chain broke" rather than WHERE. A precondition probe is cheaper by
orders of magnitude and names the exact missing fact.

CONTRACT WITH THE CALLER (utils/goad-postcondition-probe.js)
  in : -ExpectationPath  JSON expectation set (NEVER contains a secret; see the
                         SECRETS note below), -RunOn the inventory host key whose
                         checks this invocation owns.
  out: ONE JSON document at -ResultPath. Nothing this script prints to stdout is
       parsed by the caller - stdout belongs to Ansible.

THIS SCRIPT REPORTS OBSERVATIONS, NOT VERDICTS. Every result carries `present`
(did the precondition hold, in the POSITIVE sense) and never `ok`. Inversion for
negative probes (expect: absent) is done by the Node parser, which ignores any
`ok` this script might emit. That split is deliberate: a probe that graded itself
could hardcode a pass, and the entire premise of this component is that "it said
green" is not evidence.

SECRETS
The expectation set is staged as a file and may be readable by anyone who can
reach it, so it carries CREDENTIAL REFERENCES (opaque names), never passwords.
Credentials arrive separately via -CredentialJson, which the caller passes
through win_powershell's `parameters:` (marshalled by the module, no command
line) under `no_log: true`, or via -CredentialPath for a controller-local run.
Nothing in this script ever echoes a credential into a result: values that ARE
secrets (autologon DefaultPassword) are probed for EXISTENCE only, via the
per-check `redact` flag.

PS 5.1 TRAPS THIS FILE IS WRITTEN AROUND
  * ConvertTo-Json defaults to -Depth 2 and silently renders anything deeper as a
    type name. Every conversion here passes an explicit -Depth.
  * ConvertTo-Json on a ONE-element array emits a bare object, not an array. All
    result collections are forced with @( ) and the Node parser normalises the
    single-element case anyway, because both halves have to be right.
  * Out-File / > default to UTF-16LE on 5.1. The result is written with an
    explicit no-BOM UTF8Encoding via [System.IO.File]::WriteAllText.
  * Reading a missing property off a ConvertFrom-Json PSCustomObject is a silent
    $null (or a throw under StrictMode). Every field read goes through Get-Prop,
    which is also how optional expectation fields get their defaults.
  * THIS FILE IS PURE ASCII, AND MUST STAY THAT WAY. Windows PowerShell 5.1 reads
    a BOM-less .ps1 as the ANSI code page, not UTF-8. An em dash (U+2014) then
    decodes from its UTF-8 bytes as three cp1252 characters ending in a RIGHT
    DOUBLE QUOTATION MARK - which PowerShell accepts as a string delimiter. So one
    em dash inside a double-quoted string TERMINATES THAT STRING EARLY and the
    rest of the function parses as garbage. It is caught by the ASCII assertion in
    ciab-goad-postcondition-probe.test.js; do not "fix" that test by allowing a
    dash you like the look of. Adding a BOM is not the alternative either: the
    playbook inlines this file with lookup('file', ...) into win_powershell's
    `script:`, and a BOM would ride along as a stray leading character.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ExpectationPath,
    [Parameter(Mandatory = $true)][string] $ResultPath,
    [Parameter(Mandatory = $true)][string] $RunOn,
    # Either of these may supply credentials for the checks that need to act AS a
    # principal. Both optional: with neither, those checks report inconclusive
    # rather than silently passing.
    [string] $CredentialPath = '',
    [string] $CredentialJson = ''
)

# The probe never aborts the run. Every check is individually wrapped, and a
# thrown error becomes DATA on that check - a query that blew up observed
# nothing, which must never read as "the precondition holds".
$ErrorActionPreference = 'Stop'

$PROBE_VERSION = '1.0.0'
$SCHEMA_VERSION = 1

# -- plumbing ----------------------------------------------------------------

# ConvertFrom-Json yields PSCustomObject; reading a missing property off one is a
# silent $null in normal mode and a throw under StrictMode, so neither raw form
# is safe to read directly. This is the only sanctioned accessor.
function Get-Prop {
    param($Object, [string] $Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $Default }
    if ($null -eq $p.Value) { return $Default }
    return $p.Value
}

function Read-JsonFile {
    param([string] $Path)
    # -Raw so a multi-line document arrives as one string; Get-Content handles a
    # UTF-8 or UTF-16 BOM transparently, which matters because the file may have
    # been written by win_copy from a Linux controller.
    $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    return ($text | ConvertFrom-Json)
}

$script:Results = New-Object System.Collections.ArrayList

function Add-Observation {
    param(
        [string] $Id,
        [bool]   $Present,
        $Actual = $null,
        [string] $Detail = '',
        [string] $ErrorText = '',
        [bool]   $Inconclusive = $false
    )
    # No `ok` field, on purpose - see the header. `present` is the raw
    # observation; the caller decides what it means.
    [void] $script:Results.Add([ordered]@{
        id           = $Id
        present      = $Present
        actual       = $Actual
        detail       = $Detail
        error        = $ErrorText
        inconclusive = $Inconclusive
    })
}

# -- credentials -------------------------------------------------------------

$script:CredMap = @{}
try {
    $credRaw = $null
    if ($CredentialJson -and $CredentialJson.Trim().Length -gt 0) {
        $credRaw = $CredentialJson | ConvertFrom-Json
    } elseif ($CredentialPath -and (Test-Path -LiteralPath $CredentialPath)) {
        $credRaw = Read-JsonFile -Path $CredentialPath
    }
    if ($null -ne $credRaw) {
        foreach ($prop in $credRaw.PSObject.Properties) {
            $u = Get-Prop $prop.Value 'username' ''
            $p = Get-Prop $prop.Value 'password' ''
            if ($u -and $p) {
                $sec = ConvertTo-SecureString $p -AsPlainText -Force
                $script:CredMap[$prop.Name] = New-Object System.Management.Automation.PSCredential($u, $sec)
            }
        }
    }
} catch {
    # A malformed credential blob must not take the whole probe down: the
    # credential-free checks are still worth running, and the ones that need a
    # credential report inconclusive below.
    $script:CredMap = @{}
}

function Get-ProbeCredential {
    param([string] $Ref)
    if ($Ref -and $script:CredMap.ContainsKey($Ref)) { return $script:CredMap[$Ref] }
    return $null
}

# -- AD helpers --------------------------------------------------------------

$script:AdLoaded = $false
function Use-ActiveDirectory {
    if (-not $script:AdLoaded) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $script:AdLoaded = $true
    }
}

<#
Resolve a principal string to a SID the same way GOAD's own acl role does, so
that a check agrees with the role about WHO the ACE was supposed to be for.

  "NT AUTHORITY\..."  -> NTAccount translate (these have no AD object)
  "DOMAIN\sam"        -> strip the NetBIOS prefix, look up by sAMAccountName
  "sam" / "host$"     -> look up by sAMAccountName

Returns $null when the principal does not resolve, which is itself a finding: an
ACE cannot exist for a principal that does not exist.
#>
function Resolve-PrincipalSid {
    param([string] $Principal)
    Use-ActiveDirectory
    if ($Principal.StartsWith('NT AUTHORITY', [StringComparison]::OrdinalIgnoreCase) -or
        $Principal.StartsWith('BUILTIN', [StringComparison]::OrdinalIgnoreCase)) {
        $nt = New-Object System.Security.Principal.NTAccount $Principal
        return $nt.Translate([System.Security.Principal.SecurityIdentifier])
    }
    $sam = $Principal
    if ($sam.Contains('\')) { $sam = $sam.Split('\')[-1] }
    $obj = Get-ADObject -Filter "SamAccountName -eq '$sam'" -Properties objectSid -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $obj) { return $obj.objectSid }
    # Well-known names that are NOT domain objects ("Authenticated Users",
    # "Everyone") still translate through NTAccount. This branch is what makes
    # the over-grant negative probes able to name their principal at all.
    try {
        $nt = New-Object System.Security.Principal.NTAccount $Principal
        return $nt.Translate([System.Security.Principal.SecurityIdentifier])
    } catch { return $null }
}

<#
Resolve an ACL target to a distinguishedName. GOAD accepts either a literal DN or
a sAMAccountName in the same `to` field, so this mirrors that: try the DN first,
fall back to a sAMAccountName lookup.
#>
function Resolve-TargetDn {
    param([string] $Target)
    Use-ActiveDirectory
    $t = $Target
    $server = $null
    if ($t.Contains('\')) { $server = $t.Split('\')[0]; $t = $t.Split('\')[1] }
    if ($t -match '^(CN|OU|DC)=') {
        $probe = Get-ADObject -Identity $t -ErrorAction SilentlyContinue
        if ($null -ne $probe) { return $probe.DistinguishedName }
        return $null
    }
    $extra = @{}
    if ($server) { $extra.Server = $server }
    $obj = Get-ADObject -Filter "SamAccountName -eq '$t'" @extra -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $obj) { return $null }
    return $obj.DistinguishedName
}

# -- per-kind probes ---------------------------------------------------------

<#
ACL - the ACE must exist on the target's DACL, for the intended SID, carrying the
intended right. For an extended right the ObjectType GUID must match too: GOAD
writes ExtendedRight/WriteProperty/Self ACEs whose MEANING is entirely in the
GUID, so an ACE with the right flag and the wrong (or empty) GUID grants
something else and would read as a pass on a rights-only comparison.

The rights test is a flags test (-band), not equality: an ACE granting GenericAll
satisfies an intended GenericWrite, and that is a true statement about the
environment even though the two ACEs differ.
#>
function Test-AclCheck {
    param($Check)
    $principal = Get-Prop $Check 'principal' ''
    $target    = Get-Prop $Check 'target' ''
    $right     = Get-Prop $Check 'right' ''
    $adRight   = Get-Prop $Check 'ad_right' $right
    $objType   = Get-Prop $Check 'object_type' ''

    Use-ActiveDirectory
    $dn = Resolve-TargetDn -Target $target
    if ($null -eq $dn) {
        Add-Observation -Id $Check.id -Present $false -Actual $null `
            -Detail "ACL target '$target' does not resolve to a directory object"
        return
    }
    $sid = Resolve-PrincipalSid -Principal $principal
    if ($null -eq $sid) {
        Add-Observation -Id $Check.id -Present $false -Actual $null `
            -Detail "principal '$principal' does not resolve to a SID"
        return
    }

    $acl = Get-Acl -Path ("AD:\" + $dn) -ErrorAction Stop
    $wanted = [System.DirectoryServices.ActiveDirectoryRights] $adRight
    $wantGuid = [guid]::Empty
    if ($objType) { $wantGuid = [guid] $objType }

    $matched = @()
    $held = @()
    foreach ($ace in $acl.Access) {
        $aceSid = $ace.IdentityReference
        try { $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) } catch { }
        if ("$aceSid" -ne "$sid") { continue }
        # Everything this principal holds on the object, matching or not. "no ACE
        # at all" and "an ACE with the wrong right" are different bugs with
        # different fixes, and the difference is invisible from a bare false.
        $held += [ordered]@{
            type        = "$($ace.AccessControlType)"
            rights      = "$($ace.ActiveDirectoryRights)"
            object_type = "$($ace.ObjectType)"
            inheritance = "$($ace.InheritanceType)"
        }
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ((($ace.ActiveDirectoryRights -band $wanted) -ne $wanted)) { continue }
        if ($objType -and ($ace.ObjectType -ne $wantGuid)) { continue }
        $matched += $held[-1]
    }

    if ($matched.Count -gt 0) {
        Add-Observation -Id $Check.id -Present $true -Actual @($matched) `
            -Detail "$($matched.Count) matching Allow ACE(s) for '$principal' on $dn"
        return
    }
    $extra = ''
    if ($objType) { $extra = " / $objType" }
    Add-Observation -Id $Check.id -Present $false -Actual @($held) `
        -Detail "no Allow ACE for '$principal' with $adRight$extra on $dn"
}

<#
Kerberoast - the account must actually carry an SPN (no SPN, no TGS to roast),
and, when declared, the intended msDS-SupportedEncryptionTypes. The password
itself is verified by a bind AS the account, which needs a credential; with no
credential the check reports SPN presence and marks itself inconclusive rather
than claiming the password is right.
#>
function Test-KerberoastCheck {
    param($Check)
    Use-ActiveDirectory
    $user = Get-Prop $Check 'user' ''
    $wantSpns = @(Get-Prop $Check 'spns' @())
    $wantEnc  = Get-Prop $Check 'supported_encryption_types' $null
    $credRef  = Get-Prop $Check 'credential_ref' ''

    $u = Get-ADUser -Identity $user -Properties servicePrincipalName, 'msDS-SupportedEncryptionTypes' -ErrorAction SilentlyContinue
    if ($null -eq $u) {
        Add-Observation -Id $Check.id -Present $false -Actual $null -Detail "user '$user' not found"
        return
    }
    $haveSpns = @($u.servicePrincipalName)
    $enc = $u.'msDS-SupportedEncryptionTypes'
    $actual = [ordered]@{ spns = $haveSpns; supported_encryption_types = $enc }

    if ($haveSpns.Count -eq 0) {
        Add-Observation -Id $Check.id -Present $false -Actual $actual -Detail "'$user' has no SPN - nothing to roast"
        return
    }
    $missing = @($wantSpns | Where-Object { $haveSpns -notcontains $_ })
    if ($missing.Count -gt 0) {
        Add-Observation -Id $Check.id -Present $false -Actual $actual `
            -Detail "'$user' is missing SPN(s): $($missing -join ', ')"
        return
    }
    if ($null -ne $wantEnc -and "$enc" -ne "$wantEnc") {
        Add-Observation -Id $Check.id -Present $false -Actual $actual `
            -Detail "msDS-SupportedEncryptionTypes is '$enc', expected '$wantEnc'"
        return
    }

    if (-not $credRef) {
        # No credential_ref DECLARED: the expectation is the SPN alone, and the
        # SPN is there. Conclusive. This is the distinction that keeps a
        # credential-free run from being a wall of "unproven" - the caller says
        # what it wants proven, and unasked is not the same as unanswerable.
        Add-Observation -Id $Check.id -Present $true -Actual $actual `
            -Detail "'$user' carries the declared SPN(s)"
        return
    }
    $cred = Get-ProbeCredential -Ref $credRef
    if ($null -eq $cred) {
        # A credential WAS asked for and did not arrive. The SPN is there; the
        # weak password is UNVERIFIED. Say so - a roastable SPN on an account
        # whose password was rotated is still not a solvable step.
        Add-Observation -Id $Check.id -Present $true -Actual $actual -Inconclusive $true `
            -Detail "SPN present; password not verified (no credential supplied for '$credRef')"
        return
    }
    # Bind as the account. Success proves the intended password is live; the
    # password itself never enters the result.
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::Domain,
            $env:USERDNSDOMAIN)
        $bound = $ctx.ValidateCredentials($cred.UserName, $cred.GetNetworkCredential().Password)
        $actual.password_valid = [bool] $bound
        $why = 'SPN present but the intended password no longer binds'
        if ($bound) { $why = 'SPN present and the intended password binds' }
        Add-Observation -Id $Check.id -Present ([bool] $bound) -Actual $actual -Detail $why
    } catch {
        Add-Observation -Id $Check.id -Present $true -Actual $actual -Inconclusive $true `
            -ErrorText $_.Exception.Message -Detail 'SPN present; credential validation failed to run'
    }
}

<# AS-REP - DoesNotRequirePreAuth on the user object. #>
function Test-AsrepCheck {
    param($Check)
    Use-ActiveDirectory
    $user = Get-Prop $Check 'user' ''
    $u = Get-ADUser -Identity $user -Properties DoesNotRequirePreAuth -ErrorAction SilentlyContinue
    if ($null -eq $u) {
        Add-Observation -Id $Check.id -Present $false -Actual $null -Detail "user '$user' not found"
        return
    }
    $v = [bool] $u.DoesNotRequirePreAuth
    Add-Observation -Id $Check.id -Present $v -Actual @{ does_not_require_preauth = $v } `
        -Detail "DoesNotRequirePreAuth = $v on '$user'"
}

<#
Delegation - unconstrained (TrustedForDelegation), constrained
(msDS-AllowedToDelegateTo) and protocol transition (TrustedToAuthForDelegation)
are three different edges with three different abuse paths, so they are asserted
independently rather than folded into one "delegation is configured" boolean.
#>
function Test-DelegationCheck {
    param($Check)
    Use-ActiveDirectory
    $principal = Get-Prop $Check 'principal' ''
    $flavour   = Get-Prop $Check 'delegation' 'constrained'
    $wantTo    = @(Get-Prop $Check 'allowed_to_delegate_to' @())

    $props = @('TrustedForDelegation', 'TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo')
    $sam = $principal
    if ($sam.Contains('\')) { $sam = $sam.Split('\')[-1] }
    $obj = Get-ADObject -Filter "SamAccountName -eq '$sam'" -Properties $props -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $obj) {
        Add-Observation -Id $Check.id -Present $false -Actual $null -Detail "principal '$principal' not found"
        return
    }
    $to = @($obj.'msDS-AllowedToDelegateTo')
    $actual = [ordered]@{
        trusted_for_delegation         = [bool] $obj.TrustedForDelegation
        trusted_to_auth_for_delegation = [bool] $obj.TrustedToAuthForDelegation
        allowed_to_delegate_to         = $to
    }
    switch ($flavour) {
        'unconstrained' {
            Add-Observation -Id $Check.id -Present ([bool] $obj.TrustedForDelegation) -Actual $actual `
                -Detail "TrustedForDelegation = $([bool] $obj.TrustedForDelegation) on '$principal'"
        }
        'protocol_transition' {
            Add-Observation -Id $Check.id -Present ([bool] $obj.TrustedToAuthForDelegation) -Actual $actual `
                -Detail "TrustedToAuthForDelegation = $([bool] $obj.TrustedToAuthForDelegation) on '$principal'"
        }
        default {
            $missing = @($wantTo | Where-Object { $to -notcontains $_ })
            $ok = ($to.Count -gt 0) -and ($missing.Count -eq 0)
            $why = "msDS-AllowedToDelegateTo missing: $($missing -join ', ')"
            if ($ok) { $why = 'msDS-AllowedToDelegateTo covers every declared SPN' }
            Add-Observation -Id $Check.id -Present $ok -Actual $actual -Detail $why
        }
    }
}

<#
Share / file readable AS THE INTENDED PRINCIPAL.

This is the check most likely to be written wrongly, and the wrong version is
worse than none: reading the path from the probe's own session tests SYSTEM (or
whatever domain admin Ansible connected as) - and a share only SYSTEM can read is
not a finding a student can make. So a credential is mandatory here; with none,
the check is INCONCLUSIVE, never a pass.

  via 'smb'   - a UNC path, mounted with New-PSDrive -Credential. This is the
                real mechanic for a share: it exercises the share ACL and the
                NTFS ACL together, as that principal.
  via 'winrm' - a local path on the target, reached with New-PSSession
                -Credential. Note the ambiguity, and that it is REPORTED rather
                than hidden: an ordinary domain user cannot open a PSSession
                without Remote Management Users, so a failure to establish the
                session is marked inconclusive, not "unreadable".
#>
function Test-ShareReadCheck {
    param($Check)
    $path    = Get-Prop $Check 'path' ''
    $via     = Get-Prop $Check 'via' 'smb'
    $credRef = Get-Prop $Check 'credential_ref' ''
    $target  = Get-Prop $Check 'target_host' $env:COMPUTERNAME
    $cred = Get-ProbeCredential -Ref $credRef

    if ($null -eq $cred) {
        Add-Observation -Id $Check.id -Present $false -Inconclusive $true -Actual $null `
            -Detail "no credential supplied for '$credRef' - readability AS the intended principal was not tested"
        return
    }

    if ($via -eq 'winrm') {
        $session = $null
        try {
            $session = New-PSSession -ComputerName $target -Credential $cred -ErrorAction Stop
        } catch {
            Add-Observation -Id $Check.id -Present $false -Inconclusive $true -Actual $null `
                -ErrorText $_.Exception.Message `
                -Detail "could not open a PSSession as '$credRef' - this may be missing Remote Management Users rather than an unreadable path"
            return
        }
        try {
            $seen = Invoke-Command -Session $session -ScriptBlock {
                param($p)
                if (-not (Test-Path -LiteralPath $p)) { return $null }
                @(Get-ChildItem -LiteralPath $p -Force -ErrorAction Stop | Select-Object -First 5 -ExpandProperty Name)
            } -ArgumentList $path
            $ok = ($null -ne $seen)
            $why = "'$path' is not readable as '$credRef'"
            if ($ok) { $why = "'$path' is readable as '$credRef'" }
            Add-Observation -Id $Check.id -Present $ok -Actual @{ entries = @($seen) } -Detail $why
        } catch {
            Add-Observation -Id $Check.id -Present $false -Actual $null -ErrorText $_.Exception.Message `
                -Detail "'$path' is not readable as '$credRef'"
        } finally {
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }
        return
    }

    # via smb. A random drive name because a probe may run more than once in one
    # session and New-PSDrive refuses a name that is already mapped.
    $drive = 'ccp' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
    try {
        New-PSDrive -Name $drive -PSProvider FileSystem -Root $path -Credential $cred -ErrorAction Stop | Out-Null
        $entries = @(Get-ChildItem -LiteralPath ($drive + ':\') -Force -ErrorAction Stop |
            Select-Object -First 5 -ExpandProperty Name)
        Add-Observation -Id $Check.id -Present $true -Actual @{ entries = $entries } `
            -Detail "'$path' is readable as '$credRef'"
    } catch {
        Add-Observation -Id $Check.id -Present $false -Actual $null -ErrorText $_.Exception.Message `
            -Detail "'$path' is not readable as '$credRef'"
    } finally {
        Remove-PSDrive -Name $drive -Force -ErrorAction SilentlyContinue
    }
}

<#
Local group membership. Get-LocalGroupMember throws on a group containing an
orphaned SID (a long-standing Windows bug), which would otherwise turn a
legitimate "member is present" into an error, so `net localgroup` is the fallback
- it still prints names where the cmdlet gives up.
#>
function Test-LocalGroupCheck {
    param($Check)
    $group  = Get-Prop $Check 'group' 'Administrators'
    $member = Get-Prop $Check 'member' ''
    $wanted = $member
    if ($wanted.Contains('\')) { $wanted = $wanted.Split('\')[-1] }

    $names = @()
    try {
        $names = @(Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object { "$($_.Name)" })
    } catch {
        $raw = & net localgroup "$group" 2>$null
        $names = @($raw | Where-Object { $_ -and ($_ -notmatch '^(Alias name|Comment|Members|-+|The command completed)') } |
            ForEach-Object { $_.Trim() })
    }
    $hit = @($names | Where-Object {
        $n = "$_"
        ($n -eq $member) -or ($n.Split('\')[-1] -eq $wanted)
    })
    Add-Observation -Id $Check.id -Present ($hit.Count -gt 0) -Actual @{ members = $names } `
        -Detail "'$member' in local group '$group': $($hit.Count -gt 0)"
}

<#
AD group membership, including nesting. -Recursive is NOT used: the expectation
says whether the membership is direct or nested, and collapsing the two would let
a direct grant satisfy a check whose whole point was that the path runs through a
nested group (and vice versa).
#>
function Test-GroupMemberCheck {
    param($Check)
    Use-ActiveDirectory
    $group  = Get-Prop $Check 'group' ''
    $member = Get-Prop $Check 'member' ''
    $sam = $member
    if ($sam.Contains('\')) { $sam = $sam.Split('\')[-1] }

    $members = @()
    try {
        $members = @(Get-ADGroupMember -Identity $group -ErrorAction Stop |
            ForEach-Object { "$($_.SamAccountName)" })
    } catch {
        Add-Observation -Id $Check.id -Present $false -Actual $null -ErrorText $_.Exception.Message `
            -Detail "group '$group' could not be read"
        return
    }
    $hit = @($members | Where-Object { $_ -eq $sam })
    Add-Observation -Id $Check.id -Present ($hit.Count -gt 0) -Actual @{ members = $members } `
        -Detail "'$sam' is a direct member of '$group': $($hit.Count -gt 0)"
}

<#
OU placement - THE move_to_ou CATCH.

The role's own idea of "already in place" is

    $actual_location -eq "CN=Computers," + $target_ou.DistinguishedName
      -Or $actual_location -eq $target_ou.DistinguishedName

and $target_ou is ALWAYS null there because of the `> $null` on the assignment.
This check computes the same parent DN and compares it against the intended
parents the CALLER derived from config.json - the comparison the role meant to
make and never does.
#>
function Test-OuPlacementCheck {
    param($Check)
    Use-ActiveDirectory
    $computer = Get-Prop $Check 'computer' ''
    $accepted = @(Get-Prop $Check 'accepted_parents' @())

    $c = Get-ADComputer -Identity $computer -ErrorAction SilentlyContinue
    if ($null -eq $c) {
        Add-Observation -Id $Check.id -Present $false -Actual $null -Detail "computer '$computer' not found in AD"
        return
    }
    # Parent DN = the DN with its own RDN removed. Same expression the role uses.
    $parent = (($c.DistinguishedName.Split(',') | Select-Object -Skip 1) -join ',')
    $hit = @($accepted | Where-Object { $_ -and ("$_".ToLower() -eq $parent.ToLower()) })
    Add-Observation -Id $Check.id -Present ($hit.Count -gt 0) `
        -Actual @{ distinguished_name = $c.DistinguishedName; parent = $parent } `
        -Detail "'$computer' sits under '$parent'"
}

<#
Registry - THE no_ldap_signing CATCH.

The expectation names the path WINDOWS READS, not the path the role wrote. Where
those differ the expectation also carries written_path/written_name purely so the
failure message can name what the role touched; nothing here reads the written
path, because a value sitting there proves only that the role ran.

`data` is an exact match; `data_not_equal` covers the settings whose vulnerable
state is a range rather than a single value. `redact` suppresses the value
entirely - used for DefaultPassword, where existence is the whole assertion and
the value is a secret that must never reach a result file.
#>
function Test-RegistryCheck {
    param($Check)
    $path   = Get-Prop $Check 'path' ''
    $name   = Get-Prop $Check 'name' ''
    $want   = Get-Prop $Check 'data' $null
    $wantNe = Get-Prop $Check 'data_not_equal' $null
    $redact = [bool] (Get-Prop $Check 'redact' $false)

    if (-not (Test-Path -LiteralPath $path)) {
        Add-Observation -Id $Check.id -Present $false -Actual $null -Detail "registry key '$path' does not exist"
        return
    }
    $item = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
    if ($null -eq $item -or $null -eq $item.PSObject.Properties[$name]) {
        Add-Observation -Id $Check.id -Present $false -Actual $null `
            -Detail "value '$name' does not exist under '$path'"
        return
    }
    $value = $item.PSObject.Properties[$name].Value
    $shown = $value
    if ($redact) { $shown = '<redacted>' }

    if ($null -ne $want) {
        Add-Observation -Id $Check.id -Present ("$value" -eq "$want") -Actual @{ value = $shown } `
            -Detail "$path\$name = $shown (expected $want)"
        return
    }
    if ($null -ne $wantNe) {
        Add-Observation -Id $Check.id -Present ("$value" -ne "$wantNe") -Actual @{ value = $shown } `
            -Detail "$path\$name = $shown (must not be $wantNe)"
        return
    }
    Add-Observation -Id $Check.id -Present $true -Actual @{ value = $shown } -Detail "$path\$name exists"
}

<#
CA rights - THE adcs_esc7 CATCH.

Note the guard direction. GOAD's role does `if (Get-Module -ListAvailable -Name
PSPKI) { no-op } else { grant }` - inverted, so the grant never runs. Here the
module being available is the PRECONDITION for probing at all, and its absence is
reported as inconclusive rather than as a pass or a silent skip.
#>
function Test-CaRightCheck {
    param($Check)
    $principal = Get-Prop $Check 'principal' ''
    $right     = Get-Prop $Check 'right' 'ManageCA'
    $sam = $principal
    if ($sam.Contains('\')) { $sam = $sam.Split('\')[-1] }

    if (-not (Get-Module -ListAvailable -Name PSPKI)) {
        Add-Observation -Id $Check.id -Present $false -Inconclusive $true -Actual $null `
            -Detail 'PSPKI is not installed on this host, so the CA ACL could not be read'
        return
    }
    Import-Module PSPKI -ErrorAction Stop
    $ca = Get-CertificationAuthority | Select-Object -First 1
    if ($null -eq $ca) {
        Add-Observation -Id $Check.id -Present $false -Actual $null `
            -Detail 'no Certification Authority found on this host'
        return
    }
    $acl = $ca | Get-CertificationAuthorityAcl
    $entries = @()
    foreach ($ace in $acl.Access) {
        $entries += [ordered]@{
            identity = "$($ace.IdentityReference)"
            rights   = "$($ace.Rights)"
            type     = "$($ace.AccessType)"
        }
    }
    $hit = @($entries | Where-Object {
        ($_.identity.Split('\')[-1] -eq $sam) -and ($_.type -match 'Allow') -and ($_.rights -match $right)
    })
    Add-Observation -Id $Check.id -Present ($hit.Count -gt 0) -Actual @($entries) `
        -Detail "'$principal' holds $right on CA '$($ca.DisplayName)': $($hit.Count -gt 0)"
}

<#
File artifact - the cheapest check here and one of the most valuable.

An edge can be perfectly present in AD and still unreachable because the files
role's `dest` prefix was wrong and the scheduled task's script was never
delivered. Nothing in AD reflects that; only the filesystem does.
#>
function Test-FileCheck {
    param($Check)
    $path = Get-Prop $Check 'path' ''
    $isDir = [bool] (Get-Prop $Check 'is_directory' $false)
    if (-not (Test-Path -LiteralPath $path)) {
        Add-Observation -Id $Check.id -Present $false -Actual $null -Detail "'$path' does not exist"
        return
    }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    $actuallyDir = [bool] $item.PSIsContainer
    if ($isDir -ne $actuallyDir) {
        $what = 'file'
        if ($actuallyDir) { $what = 'directory' }
        Add-Observation -Id $Check.id -Present $false `
            -Actual @{ exists = $true; is_directory = $actuallyDir } `
            -Detail "'$path' exists but is a $what"
        return
    }
    $len = $null
    if (-not $actuallyDir) { $len = $item.Length }
    Add-Observation -Id $Check.id -Present $true `
        -Actual @{ exists = $true; is_directory = $actuallyDir; length = $len } `
        -Detail "'$path' exists"
}

# -- driver ------------------------------------------------------------------

$startedAt = (Get-Date).ToUniversalTime().ToString('o')
$expectation = $null
$fatal = ''
try {
    $expectation = Read-JsonFile -Path $ExpectationPath
} catch {
    $fatal = "expectation set unreadable: $($_.Exception.Message)"
}

if ($null -ne $expectation) {
    # @( ) because a one-check set round-trips through ConvertTo-Json as a bare
    # object, and foreach over an object iterates it once as a scalar - which
    # happens to work, but only by accident. Force the array.
    $checks = @(Get-Prop $expectation 'checks' @())
    foreach ($check in $checks) {
        $runOn = Get-Prop $check 'run_on' ''
        # Each invocation owns exactly the checks addressed to its host. The whole
        # set ships to every host so that a mismatch between -RunOn and the set is
        # visible (that host reports nothing, and the parser names every missing
        # id) rather than silently partial.
        if ($runOn -and ($runOn -ne $RunOn)) { continue }
        $kind = Get-Prop $check 'kind' ''
        try {
            switch ($kind) {
                'acl'          { Test-AclCheck         -Check $check }
                'kerberoast'   { Test-KerberoastCheck  -Check $check }
                'asrep'        { Test-AsrepCheck       -Check $check }
                'delegation'   { Test-DelegationCheck  -Check $check }
                'share_read'   { Test-ShareReadCheck   -Check $check }
                'local_group'  { Test-LocalGroupCheck  -Check $check }
                'group_member' { Test-GroupMemberCheck -Check $check }
                'ou_placement' { Test-OuPlacementCheck -Check $check }
                'registry'     { Test-RegistryCheck    -Check $check }
                'ca_right'     { Test-CaRightCheck     -Check $check }
                'file'         { Test-FileCheck        -Check $check }
                default {
                    # An unknown kind is version skew between this script and the
                    # module that built the set. Reporting it as not-present keeps
                    # the run fail-closed; the parser turns it into a named failure.
                    Add-Observation -Id (Get-Prop $check 'id' '?') -Present $false -Actual $null `
                        -Detail "this probe does not implement check kind '$kind'"
                }
            }
        } catch {
            # The query threw. That is an OBSERVATION OF NOTHING, never a pass -
            # and for a negative probe (expect: absent) a swallowed error reading
            # as 'absent' would be the exact silent-success bug this component
            # exists to catch. present:$false plus a non-empty error is how the
            # parser knows to fail EITHER polarity.
            Add-Observation -Id (Get-Prop $check 'id' '?') -Present $false -Actual $null `
                -ErrorText $_.Exception.Message -Detail "check '$kind' raised"
        }
    }
}

$document = [ordered]@{
    schema_version = $SCHEMA_VERSION
    probe_version  = $PROBE_VERSION
    run_on         = $RunOn
    started_at     = $startedAt
    finished_at    = (Get-Date).ToUniversalTime().ToString('o')
    fatal          = $fatal
    results        = @($script:Results)
}

# -Depth well past the deepest `actual` (ACE lists inside an array inside the
# document) - the 5.1 default of 2 renders them as type names, and the truncation
# is SILENT.
$json = $document | ConvertTo-Json -Depth 10

# WriteAllText with a no-BOM UTF8Encoding: Out-File/Set-Content on 5.1 write
# UTF-16LE or a BOM, and the controller reads this back through `cat`.
$dir = Split-Path -Parent $ResultPath
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
[System.IO.File]::WriteAllText($ResultPath, $json, (New-Object System.Text.UTF8Encoding($false)))

# Exit 0 even when checks failed. A failing precondition is DATA, and the caller
# reads the result document for it; a non-zero exit here would make Ansible abort
# the play and destroy the very report we came for.
exit 0
