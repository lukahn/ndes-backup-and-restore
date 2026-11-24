#Requires -Version 5.1
<#
.SYNOPSIS
    Takes the T1 (post-install) capture and bundles it with the T0 baseline.

.DESCRIPTION
    Run on the same VM that Start-NdesCapture.ps1 was run on, after the change
    you want to observe has been applied. Nothing is diffed yet - use
    Compare-NdesCapture.ps1 for that.
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
    [switch]$KeepAuditing,
    [switch]$Zip,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'lib\NdesCapture.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Module not found: $modulePath - copy the whole kit folder, including lib\ and config\."
}
Import-Module $modulePath -Force

$hostDir = Join-Path $Root $env:COMPUTERNAME
$statePath = Join-Path $hostDir "state-$Label.json"
$state = Get-CaptureState -Path $statePath

if (-not $SettingsPath) { $SettingsPath = $state.SettingsPath }
if (-not $SettingsPath) { $SettingsPath = Join-Path $PSScriptRoot 'config\capture-settings.psd1' }
if (-not $Scenario -and ($state.PSObject.Properties.Name -contains 'Scenario')) { $Scenario = $state.Scenario }
$settings = Import-CaptureSettings -Path $SettingsPath -Scenario $Scenario

$outDir = Join-Path $hostDir "T1-$Label"
if ((Test-Path -LiteralPath $outDir) -and -not $Force) {
    throw "Post-install snapshot already exists: $outDir. Re-run with -Force to overwrite."
}
if ((Test-Path -LiteralPath $outDir) -and $Force) { Remove-Item -LiteralPath $outDir -Recurse -Force }
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
if ($SettingsPath -and (Test-Path -LiteralPath $SettingsPath)) {
    Copy-Item -LiteralPath $SettingsPath -Destination (Join-Path $outDir 'capture-settings.psd1') -Force
}

Set-CaptureLogPath -Path (Join-Path $hostDir "capture-$Label.log")
Write-CaptureLog ('NDES capture post-install - {0} - label {1}' -f $env:COMPUTERNAME, $Label)

$startedUtc = [datetime]::Parse($state.StartedUtc, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
$elapsed = ((Get-Date).ToUniversalTime() - $startedUtc)
Write-CaptureLog ('capture window: {0:u} -> now ({1:N1} min)' -f $startedUtc, $elapsed.TotalMinutes)

$sinceUsn = $null
$sinceJournalId = $null
if ($null -ne $state.Usn) {
    $sinceUsn = [int64]$state.Usn.NextUsn
    $sinceJournalId = [string]$state.Usn.JournalId
}

$fileMode = $settings.Files.Mode
if ($state.PSObject.Properties.Name -contains 'FileMode' -and $state.FileMode) { $fileMode = $state.FileMode }
if ($fileMode -eq 'Auto') {
    if ($null -ne $sinceUsn) { $fileMode = 'Usn' } else { $fileMode = 'Inventory' }
}

$statuses = New-Object System.Collections.Generic.List[object]

$statuses.Add((Invoke-CaptureStep -Name 'systeminfo' -Action { Export-SystemInfo -OutDir $outDir | Out-Null }))

if ($state.IsDomainController) {
    $statuses.Add((Invoke-CaptureStep -Name 'ad' -Action {
                Export-AdSnapshot -Settings $settings -OutDir $outDir -SinceUtc $startedUtc.ToLocalTime()
            }))
    $statuses.Add((Invoke-CaptureStep -Name 'ad-audit' -Optional -Action {
                Export-AdAuditEvents -OutDir $outDir -SinceUtc $startedUtc.ToLocalTime() -MaxEvents $settings.Ad.MaxAuditEvents
            }))
}
else {
    $statuses.Add([pscustomobject]@{ Collector = 'ad'; Status = 'NotApplicable'; Detail = 'Host is not a domain controller' })
}

$statuses.Add((Invoke-CaptureStep -Name 'registry' -Action {
            Export-RegistrySnapshot -Settings $settings -OutDir $outDir -Scope $RegistryScope -IncludeUserHives:$IncludeUserHives
        }))

$statuses.Add((Invoke-CaptureStep -Name 'files' -Action {
            Export-FileSnapshot -Settings $settings -OutDir $outDir -Mode $fileMode -Volume $settings.Files.Volume `
                -SinceUsn $sinceUsn -SinceJournalId $sinceJournalId
        }))

if (Test-HasIis) {
    $statuses.Add((Invoke-CaptureStep -Name 'iis' -Action { Export-IisSnapshot -OutDir $outDir }))
}
else {
    $statuses.Add([pscustomobject]@{ Collector = 'iis'; Status = 'NotApplicable'; Detail = 'IIS not installed' })
}

$statuses.Add((Invoke-CaptureStep -Name 'features' -Optional -Action { Export-FeatureSnapshot -OutDir $outDir }))
$statuses.Add((Invoke-CaptureStep -Name 'services' -Action { Export-ServiceSnapshot -OutDir $outDir }))
$statuses.Add((Invoke-CaptureStep -Name 'certificates' -Action { Export-CertificateSnapshot -OutDir $outDir -IncludeCurrentUser:$IncludeUserStore }))
$statuses.Add((Invoke-CaptureStep -Name 'firewall' -Optional -Action { Export-FirewallSnapshot -OutDir $outDir }))
$statuses.Add((Invoke-CaptureStep -Name 'tasks' -Optional -Action { Export-ScheduledTaskSnapshot -OutDir $outDir }))

$fileAuditingWanted = $FileAuditing
if (-not $fileAuditingWanted -and ($state.PSObject.Properties.Name -contains 'FileAuditing')) {
    $fileAuditingWanted = [bool]$state.FileAuditing
}
if ($fileAuditingWanted) {
    $statuses.Add((Invoke-CaptureStep -Name 'fileaudit' -Optional -Action {
                Export-FileAuditEvents -OutDir $outDir -SinceUtc $startedUtc.ToLocalTime() `
                    -Paths @($settings.FileAudit.Paths) -MaxEvents $settings.FileAudit.MaxEvents
            }))
}
else {
    $statuses.Add([pscustomobject]@{ Collector = 'fileaudit'; Status = 'Skipped'; Detail = 'not requested (-FileAuditing)' })
}

$statuses | Export-Csv -LiteralPath (Join-Path $outDir 'collectors.csv') -NoTypeInformation -Encoding UTF8

# Undo the auditing Start switched on, so it does not keep logging indefinitely.
# Done after the 5136/4663 collectors have run, so this cleanup cannot appear in
# its own capture window.
if (-not $KeepAuditing) {
    $enabledDir = ($state.PSObject.Properties.Name -contains 'DirectoryAuditingEnabledByCapture') -and $state.DirectoryAuditingEnabledByCapture
    $enabledFile = ($state.PSObject.Properties.Name -contains 'FileAuditingEnabledByCapture') -and $state.FileAuditingEnabledByCapture

    if ($enabledDir -or $enabledFile) {
        Write-CaptureLog 'postflight: restoring auditing to its previous state' -Level STEP
        try { Enable-CapturePrivilege } catch { Write-CaptureLog ('  {0}' -f $_.Exception.Message) -Level WARN }

        if ($enabledFile) {
            try {
                Disable-FileSystemAudit -Paths @($settings.FileAudit.Paths) -Principal $settings.FileAudit.AuditPrincipal
                Write-CaptureLog '  file auditing turned off'
            }
            catch { Write-CaptureLog ('  could not turn file auditing off: {0}' -f $_.Exception.Message) -Level WARN }
        }

        if ($enabledDir) {
            try {
                $contexts = Get-DirectoryNamingContexts
                $targets = @(@($contexts.Domain, $contexts.Configuration) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                foreach ($nc in $targets) {
                    $removed = Disable-DirectoryAuditSacl -DistinguishedName $nc
                    Write-CaptureLog ('  {0}: removed {1} audit entr(y/ies)' -f $nc, $removed)
                }
                Set-DirectoryAuditPolicy -Enabled $false
                Write-CaptureLog '  directory auditing turned off'
            }
            catch { Write-CaptureLog ('  could not turn directory auditing off: {0}' -f $_.Exception.Message) -Level WARN }
        }
    }
}

$state | Add-Member -NotePropertyName FinishedUtc -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
$state | Add-Member -NotePropertyName ElapsedMinutes -NotePropertyValue ([math]::Round($elapsed.TotalMinutes, 1)) -Force
$state | Add-Member -NotePropertyName T1Dir -NotePropertyValue $outDir -Force
Save-CaptureState -Path $statePath -State $state

$failed = @($statuses | Where-Object Status -eq 'Failed')
Write-CaptureLog ('post-install snapshot complete - {0} collector(s) failed' -f $failed.Count) -Level $(if ($failed.Count -gt 0) { 'WARN' } else { 'INFO' })

if ($Zip) {
    $zipPath = Join-Path $Root ("{0}-{1}.zip" -f $env:COMPUTERNAME, $Label)
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    $items = @()
    foreach ($name in @("T0-$Label", "T1-$Label", "state-$Label.json", "capture-$Label.log")) {
        $candidate = Join-Path $hostDir $name
        if (Test-Path -LiteralPath $candidate) { $items += $candidate }
    }
    Compress-Archive -Path $items -DestinationPath $zipPath -CompressionLevel Optimal
    Write-CaptureLog ('bundle: {0}' -f $zipPath)
}
