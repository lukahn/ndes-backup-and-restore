#Requires -Version 5.1
<#
.SYNOPSIS
    Takes the T0 (pre-install) baseline for the NDES lab capture.

.DESCRIPTION
    Run this on each of the three VMs immediately before you install NDES.
    It records the state of every instrumented area and the USN journal
    cursor so Stop-NdesCapture.ps1 can reconstruct exactly what changed.

.EXAMPLE
    .\Start-NdesCapture.ps1 -Label ndes

    Then, after the NDES install finishes on that same VM:

    .\Stop-NdesCapture.ps1 -Label ndes
#>
[CmdletBinding()]
param(
    [string]$Root = 'C:\NdesCapture',
    [string]$Label = 'capture',
    [string]$SettingsPath,
    [string]$Scenario,
    [ValidateSet('Default', 'Full')]
    [string]$RegistryScope = 'Default',
    [switch]$IncludeUserHives,
    [switch]$IncludeUserStore,
    [switch]$FileAuditing,
    [switch]$NoDirectoryAuditing,
    [switch]$NoFileAuditing,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'lib\NdesCapture.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw @"
Module not found: $modulePath

The scripts need their folder structure beside them - copy the whole folder,
not just the .ps1 files:

  <folder>\
    Start-NdesCapture.ps1
    Stop-NdesCapture.ps1
    Compare-NdesCapture.ps1
    Enable-AdDirectoryAuditing.ps1
    lib\NdesCapture.psm1
    config\capture-settings.psd1
"@
}
Import-Module $modulePath -Force

if (-not $SettingsPath) { $SettingsPath = Join-Path $PSScriptRoot 'config\capture-settings.psd1' }
$settings = Import-CaptureSettings -Path $SettingsPath -Scenario $Scenario

$hostDir = Join-Path $Root $env:COMPUTERNAME
$outDir = Join-Path $hostDir "T0-$Label"
$statePath = Join-Path $hostDir "state-$Label.json"

if ((Test-Path -LiteralPath $outDir) -and -not $Force) {
    throw "Baseline already exists: $outDir. Re-run with -Force to overwrite, or use a different -Label."
}
if ((Test-Path -LiteralPath $outDir) -and $Force) { Remove-Item -LiteralPath $outDir -Recurse -Force }

New-Item -ItemType Directory -Path $outDir -Force | Out-Null
# Snapshot the settings so this capture can be re-diffed faithfully later, even
# if the source config is edited or the folder is copied to another machine.
if ($SettingsPath -and (Test-Path -LiteralPath $SettingsPath)) {
    Copy-Item -LiteralPath $SettingsPath -Destination (Join-Path $outDir 'capture-settings.psd1') -Force
}
Set-CaptureLogPath -Path (Join-Path $hostDir "capture-$Label.log") -Truncate

Write-CaptureLog ('NDES capture baseline - {0} - label {1}' -f $env:COMPUTERNAME, $Label)
if ($settings.Contains('Scenario')) {
    Write-CaptureLog ('scenario: {0} - {1}' -f $settings.Scenario.Name, $settings.Scenario.Description)
}
Write-CaptureLog ('output: {0}' -f $outDir)

$startedUtc = (Get-Date).ToUniversalTime()

$isElevated = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isElevated) {
    Write-CaptureLog 'not elevated - USN journal reads will fail; file evidence falls back to metadata inventory' -Level WARN
}

# Resolved once, before anything that branches on it.
$isDc = Test-IsDomainController

if ($settings.Contains('Scenario') -and $isDc -and $settings.Scenario.IncludeConfigurationNc) {
    Write-CaptureLog 'this scenario writes to the Configuration partition - enable auditing with: Enable-AdDirectoryAuditing.ps1 -Apply -Scenario <name>' -Level WARN
}

# Journal cursor first: everything after this point is "the install window".
$usnState = $null
try {
    $usnState = Get-UsnJournalState -Volume $settings.Files.Volume
    Write-CaptureLog ('USN baseline: journal {0}, next USN {1}' -f $usnState.JournalId, $usnState.NextUsn)
}
catch {
    Write-CaptureLog ("USN journal unavailable ({0}) - file capture will use inventory mode" -f $_.Exception.Message) -Level WARN
}

$statuses = New-Object System.Collections.Generic.List[object]

$statuses.Add((Invoke-CaptureStep -Name 'systeminfo' -Action { Export-SystemInfo -OutDir $outDir | Out-Null }))

$isDc = Test-IsDomainController

# Preflight: attribution is a separate switch-on step. Report its state now so
# a missing SACL is visible up front rather than as a gap in the final report.
if ($isDc) {
    Write-CaptureLog 'preflight: directory attribution' -Level STEP
    $enabledByCapture = $false
    if ($NoDirectoryAuditing) {
        Write-CaptureLog '  skipped (-NoDirectoryAuditing) - the report will not show which account changed what' -Level WARN
    }
    else {
        try {
            Enable-CapturePrivilege
            Set-DirectoryAuditPolicy -Enabled $true
            $contexts = Get-DirectoryNamingContexts
            $targets = @(@($contexts.Domain, $contexts.Configuration) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            foreach ($nc in $targets) {
                $added = Enable-DirectoryAuditSacl -DistinguishedName $nc
                if ($added) {
                    Write-CaptureLog ('  {0}: audit SACL applied' -f $nc)
                    $enabledByCapture = $true
                }
                else {
                    Write-CaptureLog ('  {0}: audit SACL already present' -f $nc)
                }
            }
        }
        catch {
            Write-CaptureLog ('  could not enable directory auditing: {0}' -f $_.Exception.Message) -Level WARN
            Write-CaptureLog '  the report will show WHAT changed but not WHICH ACCOUNT - run elevated as Domain/Enterprise Admin' -Level WARN
        }
    }
    $directoryAuditingByCapture = $enabledByCapture
}
else {
    $directoryAuditingByCapture = $false
}

if ($FileAuditing) {
    Write-CaptureLog 'preflight: file attribution' -Level STEP
    $wanted = @(@($settings.FileAudit.Paths) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $fileAuditByCapture = $false
    try {
        if ($NoFileAuditing) {
            Write-CaptureLog '  skipped (-NoFileAuditing) - 4663 collection will find nothing' -Level WARN
        }
        else {
            foreach ($p in $wanted) {
                if (-not (Test-Path -LiteralPath $p)) { Write-CaptureLog ('  {0}: path not present' -f $p) -Level WARN; continue }
                Enable-FileSystemAudit -Paths @($p) -Principal $settings.FileAudit.AuditPrincipal
                Write-CaptureLog ('  {0}: audit SACL applied' -f $p)
                $fileAuditByCapture = $true
            }
        }
    }
    catch {
        Write-CaptureLog ('  could not enable file auditing: {0}' -f $_.Exception.Message) -Level WARN
    }
    $fileAuditingByCapture = $fileAuditByCapture
}
else {
    $fileAuditingByCapture = $false
}
if ($isDc) {
    $statuses.Add((Invoke-CaptureStep -Name 'ad' -Action { Export-AdSnapshot -Settings $settings -OutDir $outDir }))
}
else {
    Write-CaptureLog 'ad: not a domain controller, skipped' -Level WARN
    $statuses.Add([pscustomobject]@{ Collector = 'ad'; Status = 'NotApplicable'; Detail = 'Host is not a domain controller' })
}

$statuses.Add((Invoke-CaptureStep -Name 'registry' -Action {
            Export-RegistrySnapshot -Settings $settings -OutDir $outDir -Scope $RegistryScope -IncludeUserHives:$IncludeUserHives
        }))

$fileMode = $settings.Files.Mode
if (-not $isElevated -and $fileMode -ne 'Inventory') {
    Write-CaptureLog ('file mode {0} downgraded to Inventory (needs elevation)' -f $fileMode) -Level WARN
    $fileMode = 'Inventory'
}
$statuses.Add((Invoke-CaptureStep -Name 'files' -Action {
            Export-FileSnapshot -Settings $settings -OutDir $outDir -Mode $fileMode -Volume $settings.Files.Volume
        }))

if (Test-HasIis) {
    $statuses.Add((Invoke-CaptureStep -Name 'iis' -Action { Export-IisSnapshot -OutDir $outDir }))
}
else {
    Write-CaptureLog 'iis: IIS not installed, skipped' -Level WARN
    $statuses.Add([pscustomobject]@{ Collector = 'iis'; Status = 'NotApplicable'; Detail = 'IIS not installed' })
}

$statuses.Add((Invoke-CaptureStep -Name 'features' -Optional -Action { Export-FeatureSnapshot -OutDir $outDir }))
$statuses.Add((Invoke-CaptureStep -Name 'services' -Action { Export-ServiceSnapshot -OutDir $outDir }))
$statuses.Add((Invoke-CaptureStep -Name 'certificates' -Action { Export-CertificateSnapshot -OutDir $outDir -IncludeCurrentUser:$IncludeUserStore }))
$statuses.Add((Invoke-CaptureStep -Name 'firewall' -Optional -Action { Export-FirewallSnapshot -OutDir $outDir }))
$statuses.Add((Invoke-CaptureStep -Name 'tasks' -Optional -Action { Export-ScheduledTaskSnapshot -OutDir $outDir }))

$statuses | Export-Csv -LiteralPath (Join-Path $outDir 'collectors.csv') -NoTypeInformation -Encoding UTF8

$state = [ordered]@{
    SchemaVersion      = 1
    Host               = $env:COMPUTERNAME
    Label              = $Label
    Root               = $Root
    SettingsPath       = $SettingsPath
    StartedUtc         = $startedUtc.ToString('o')
    Usn                = $usnState
    FileMode           = $fileMode
    Scenario           = $(if ($settings.Contains('Scenario')) { $settings.Scenario.Name } else { '' })
    FileAuditing       = [bool]$FileAuditing
    DirectoryAuditingEnabledByCapture = [bool]$directoryAuditingByCapture
    FileAuditingEnabledByCapture      = [bool]$fileAuditingByCapture
    IsDomainController = $isDc
    HasIis             = (Test-HasIis)
    Collectors         = $statuses
}
Save-CaptureState -Path $statePath -State $state

$failed = @($statuses | Where-Object Status -eq 'Failed')
Write-CaptureLog ('baseline complete - {0} collector(s) failed' -f $failed.Count) -Level $(if ($failed.Count -gt 0) { 'WARN' } else { 'INFO' })
Write-CaptureLog ('state: {0}' -f $statePath)
