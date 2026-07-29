$ErrorActionPreference = "Stop"

Write-Host "Removing unwanted AppX packages"

$PackagesToRemove = @(
    "Microsoft.BingNews"
    "Microsoft.BingWeather"
    "Microsoft.GamingApp"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.People"
    "Microsoft.PowerAutomateDesktop"
    "Microsoft.Todos"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Clipchamp.Clipchamp"
)

$Failures = @()

foreach ($PackageName in $PackagesToRemove) {
    Write-Host "Processing $PackageName"

    # Order matters. Removing the provisioned copy first stops the package being
    # reinstalled for accounts created later; leaving a package installed for a
    # user but not provisioned is the classic cause of Sysprep failing with
    # SYSPRP "package was installed for a user, but not provisioned for all
    # users" hours after this script has already reported success.
    try {
        Get-AppxProvisionedPackage -Online |
            Where-Object DisplayName -eq $PackageName |
            Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction Stop |
            Out-Null
    }
    catch {
        $Failures += "provisioned:$PackageName -- $($_.Exception.Message)"
    }

    try {
        Get-AppxPackage -AllUsers -Name $PackageName |
            Remove-AppxPackage -AllUsers -ErrorAction Stop
    }
    catch {
        $Failures += "installed:$PackageName -- $($_.Exception.Message)"
    }
}

# Report rather than throw: a package that was not present in this image is not
# an error, but a package that resisted removal will bite at Sysprep time and
# needs to be visible in the build log.
if ($Failures) {
    Write-Host ""
    Write-Host "The following AppX removals did not complete cleanly:"

    foreach ($Failure in $Failures) {
        Write-Host "  $Failure"
    }
}

Write-Host ""
Write-Host "Verifying no package is installed-but-unprovisioned"

$Provisioned = (Get-AppxProvisionedPackage -Online).DisplayName

$Orphaned = Get-AppxPackage -AllUsers |
    Where-Object {
        $PackagesToRemove -contains $_.Name -and $Provisioned -notcontains $_.Name
    }

if ($Orphaned) {
    Write-Host "WARNING: these packages remain installed without a provisioned copy and will fail Sysprep:"

    foreach ($Package in $Orphaned) {
        Write-Host "  $($Package.PackageFullName)"
    }
}
else {
    Write-Host "None found"
}
