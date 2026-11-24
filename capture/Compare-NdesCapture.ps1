#Requires -Version 5.1
<#
.SYNOPSIS
    Diffs the T0/T1 capture for a host and writes a triaged report.

.DESCRIPTION
    Reads <Root>\<Host>\T0-<Label> and T1-<Label>, produces:
      report.md          triaged human report (start here)
      changes.csv        every change, machine readable
      high-signal.csv    just the changes that matter for NDES

    -HostName lets you analyse another machine's bundle from an analyst box
    (copy C:\NdesCapture\<Host> across and point -Root at it).

.EXAMPLE
    .\Compare-NdesCapture.ps1 -Label ndes
.EXAMPLE
    .\Compare-NdesCapture.ps1 -Root D:\bundles -HostName NDES01 -Label ndes -IncludeNoise
#>
[CmdletBinding()]
param(
    [string]$Root = 'C:\NdesCapture',
    [string]$HostName = $env:COMPUTERNAME,
    [string]$Label = 'capture',
    [string]$SettingsPath,
    [string]$OutDir,
    [string]$Scenario,
    [switch]$IncludeNoise,
    [int]$MaxRowsPerSection = 40
)

$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'lib\NdesCapture.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Module not found: $modulePath - copy the whole kit folder, including lib\ and config\."
}
Import-Module $modulePath -Force

$hostDir = Join-Path $Root $HostName
$t0 = Join-Path $hostDir "T0-$Label"
$t1 = Join-Path $hostDir "T1-$Label"
$statePath = Join-Path $hostDir "state-$Label.json"

if (-not (Test-Path -LiteralPath $t0)) { throw "Baseline not found: $t0" }
if (-not (Test-Path -LiteralPath $t1)) { throw "Post-install capture not found: $t1" }

if (-not $SettingsPath) {
    if (Test-Path -LiteralPath $statePath) {
        $recorded = (Get-CaptureState -Path $statePath).SettingsPath
        if ($recorded -and (Test-Path -LiteralPath $recorded)) { $SettingsPath = $recorded }
    }
}
# Fall back to the copy saved beside the capture, so a bundle moved to another
# machine still diffs the same way it did originally.
if (-not $SettingsPath) {
    $snapshot = Join-Path $t0 'capture-settings.psd1'
    if (Test-Path -LiteralPath $snapshot) { $SettingsPath = $snapshot }
}
if (-not $SettingsPath) { $SettingsPath = Join-Path $PSScriptRoot 'config\capture-settings.psd1' }

if (-not $Scenario -and (Test-Path -LiteralPath $statePath)) {
    $stateForScenario = Get-CaptureState -Path $statePath
    if ($stateForScenario.PSObject.Properties.Name -contains 'Scenario') { $Scenario = $stateForScenario.Scenario }
}

$settings = Import-CaptureSettings -Path $SettingsPath -Scenario $Scenario
Write-CaptureLog ('settings: {0}' -f $SettingsPath)
if ($settings.Contains('Scenario')) {
    Write-CaptureLog ('scenario: {0}' -f $settings.Scenario.Name)
}

if (-not $OutDir) { $OutDir = Join-Path $hostDir "report-$Label" }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Set-CaptureLogPath -Path (Join-Path $OutDir 'compare.log') -Truncate

Write-CaptureLog ('comparing {0} / {1}' -f $HostName, $Label)
Write-CaptureLog ('  T0: {0}' -f $t0)
Write-CaptureLog ('  T1: {0}' -f $t1)

$all = New-Object System.Collections.Generic.List[object]

function Add-Results {
    param($Results, [string]$Area, [string]$Partition = '')
    if ($null -eq $Results) { return }
    $rows = @($Results | ForEach-Object { $_ })
    foreach ($r in $rows) {
        if ($null -eq $r) { continue }
        $r | Add-Member -NotePropertyName Partition -NotePropertyValue $Partition -Force
        $r | Add-Member -NotePropertyName Signal -NotePropertyValue (Get-ChangeSignal -Area $r.Area -Target $r.Target -Name $r.Name -Settings $settings) -Force
        $all.Add($r)
    }
    Write-CaptureLog ('  {0}: {1} change(s)' -f $Area, $rows.Count)
}

# --- per-area diffs (each is skipped silently when the artefact is absent) ---
$steps = @(
    @{ Name = 'registry'; Action = { Compare-RegistrySnapshot -BeforeDir (Join-Path $t0 'registry') -AfterDir (Join-Path $t1 'registry') } }
    @{ Name = 'files-usn'; Action = { Compare-UsnJournal -BeforeDir (Join-Path $t0 'files') -AfterDir (Join-Path $t1 'files') } }
    @{ Name = 'files-inventory'; Action = { Compare-FileInventory -BeforeDir (Join-Path $t0 'files') -AfterDir (Join-Path $t1 'files') } }
    @{ Name = 'files-hashes'; Action = { Compare-FileHashes -BeforeDir (Join-Path $t0 'files') -AfterDir (Join-Path $t1 'files') } }
    @{ Name = 'file-audit'; Action = { Compare-FileAuditEvents -BeforeDir (Join-Path $t0 'files') -AfterDir (Join-Path $t1 'files') } }
    @{ Name = 'iis'; Action = { Compare-IisSnapshot -BeforeDir (Join-Path $t0 'iis') -AfterDir (Join-Path $t1 'iis') } }
    @{ Name = 'features'; Action = { Compare-FeatureSnapshot -BeforeDir (Join-Path $t0 'features') -AfterDir (Join-Path $t1 'features') } }
    @{ Name = 'services'; Action = { Compare-ServiceSnapshot -BeforeDir (Join-Path $t0 'services') -AfterDir (Join-Path $t1 'services') } }
    @{ Name = 'certificates'; Action = { Compare-CertificateSnapshot -BeforeDir (Join-Path $t0 'certs') -AfterDir (Join-Path $t1 'certs') } }
    @{ Name = 'ad-domain'; Partition = 'Domain'; Action = { Compare-LdifSnapshot -BeforeFile (Join-Path $t0 'ad\domain.ldf') -AfterFile (Join-Path $t1 'ad\domain.ldf') } }
    @{ Name = 'ad-configuration'; Partition = 'Configuration'; Action = { Compare-LdifSnapshot -BeforeFile (Join-Path $t0 'ad\configuration.ldf') -AfterFile (Join-Path $t1 'ad\configuration.ldf') } }
)

foreach ($step in $steps) {
    try {
        $results = & $step.Action
        Add-Results -Results $results -Area $step.Name -Partition $step.Partition
    }
    catch {
        Write-CaptureLog ('  {0}: failed - {1}' -f $step.Name, $_.Exception.Message) -Level WARN
    }
}

# De-duplicate: USN, inventory and hash passes can report the same path, and
# registry/IIS emit several rows per target. Files are identified by path only,
# registry/AD rows by key + value name.
$byKey = [ordered]@{}
foreach ($change in $all) {
    $identity = [string]$change.Target
    if ($change.Area -eq 'Registry' -or $change.Area -eq 'AD') { $identity = $identity + [char]31 + [string]$change.Name }
    # File-audit rows are individual events, not state: two writes to the same
    # file by the same account are two distinct facts.
    if ($change.Area -eq 'FileAudit') { $identity = $identity + [char]31 + [string]$change.Name + [char]31 + [string]$change.After }
    $key = ([string]$change.Area + [char]31 + $identity)

    if (-not $byKey.Contains($key)) {
        $byKey[$key] = $change
        continue
    }
    $existing = $byKey[$key]
    $rank = @{ 'Noise' = 0; 'Review' = 1; 'High' = 2 }
    if ($rank[$change.Signal] -gt $rank[$existing.Signal]) { $byKey[$key] = $change }
}

$changes = @($byKey.Values)
if (-not $IncludeNoise) { $changes = @($changes | Where-Object { $_.Signal -ne 'Noise' }) }

$changes | Select-Object Area, Partition, Change, Signal, Target, Name, Before, After |
    Sort-Object Signal, Area, Target, Name |
    Export-Csv -LiteralPath (Join-Path $OutDir 'changes.csv') -NoTypeInformation -Encoding UTF8

$high = @($changes | Where-Object { $_.Signal -eq 'High' })
$high | Select-Object Area, Partition, Change, Signal, Target, Name, Before, After |
    Sort-Object Area, Target, Name |
    Export-Csv -LiteralPath (Join-Path $OutDir 'high-signal.csv') -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------- report ---

function Format-Cell {
    param($Value, [int]$Width = 180)
    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    $text = $text -replace "`r`n", ' / ' -replace "`n", ' / '
    $text = $text -replace '\|', '\|'
    if ($text.Length -gt $Width) { $text = $text.Substring(0, $Width) + ' ...' }
    return $text
}

function Add-Table {
    param(
        [System.Collections.Generic.List[string]]$Lines,
        [string]$Title,
        $Rows,
        [string[]]$Columns
    )
    # NB: @($list) throws "Argument types do not match" for List[object]
    # (PS 5.1 and 7.x); piping first enumerates it safely.
    $rowArray = @($Rows | ForEach-Object { $_ })
    if ($rowArray.Count -eq 0) { return }
    $Lines.Add("")
    $Lines.Add("### $Title")
    $Lines.Add("")
    $Lines.Add('| ' + ($Columns -join ' | ') + ' |')
    $Lines.Add('|' + (($Columns | ForEach-Object { ' --- ' }) -join '|') + '|')
    foreach ($row in $rowArray) {
        $cells = foreach ($col in $Columns) { Format-Cell $row.$col }
        $Lines.Add('| ' + ($cells -join ' | ') + ' |')
    }
}

$lines = New-Object System.Collections.Generic.List[string]
$state = $null
if (Test-Path -LiteralPath $statePath) { $state = Get-CaptureState -Path $statePath }

$title = 'NDES install'
if ($settings.Contains('Scenario')) { $title = $settings.Scenario.Name }
$lines.Add("# $title diff - $HostName ($Label)")
$lines.Add('')
if ($null -ne $state) {
    $lines.Add(('- capture window: {0} -> {1} ({2} min)' -f $state.StartedUtc, $state.FinishedUtc, $state.ElapsedMinutes))
}
$lines.Add(('- source: `{0}` (T0/T1 evidence for host {1})' -f $hostDir, $HostName))
$lines.Add(('- settings: `{0}`' -f $SettingsPath))
$lines.Add(('- changes captured: {0} (high-signal: {1})' -f $changes.Count, $high.Count))
if (-not $IncludeNoise) { $lines.Add('- noise-filtered rows are excluded; re-run with -IncludeNoise to see them') }
$lines.Add('')

$lines.Add('## Summary by area')
$lines.Add('')
$lines.Add('| Area | Added | Modified | Removed | High |')
$lines.Add('| --- | --- | --- | --- | --- |')
foreach ($area in ($changes | Group-Object Area | Sort-Object Name)) {
    $areaRows = $area.Group
    $added = @($areaRows | Where-Object { $_.Change -match 'Added' }).Count
    $modified = @($areaRows | Where-Object { $_.Change -match 'Modified' }).Count
    $removed = @($areaRows | Where-Object { $_.Change -match 'Removed' }).Count
    $highCount = @($areaRows | Where-Object { $_.Signal -eq 'High' }).Count
    $lines.Add(('| {0} | {1} | {2} | {3} | {4} |' -f $area.Name, $added, $modified, $removed, $highCount))
}

# High-signal, grouped
$lines.Add('')
$lines.Add('## High-signal changes')
foreach ($area in ($high | Group-Object Area | Sort-Object Name)) {
    $rows = @($area.Group | Sort-Object Target, Name | Select-Object -First $MaxRowsPerSection)
    Add-Table -Lines $lines -Title ("{0} ({1})" -f $area.Name, $area.Count) -Rows $rows -Columns @('Change', 'Target', 'Name', 'Before', 'After')
    if ($area.Count -gt $MaxRowsPerSection) {
        $lines.Add('')
        $lines.Add(('_{0} more rows in changes.csv_' -f ($area.Count - $MaxRowsPerSection)))
    }
}
if ($high.Count -eq 0) { $lines.Add(''); $lines.Add('_No high-signal changes matched the configured patterns._') }

# Everything that is neither high-signal nor noise still needs to be visible.
$review = @($changes | Where-Object { $_.Signal -eq 'Review' })
if ($review.Count -gt 0) {
    $lines.Add('')
    $lines.Add(('## Other changes for review ({0})' -f $review.Count))
    foreach ($area in ($review | Group-Object Area | Sort-Object Name)) {
        $rows = @($area.Group | Sort-Object Target, Name | Select-Object -First $MaxRowsPerSection)
        Add-Table -Lines $lines -Title ("{0} ({1})" -f $area.Name, $area.Count) -Rows $rows -Columns @('Partition', 'Change', 'Target', 'Name', 'Before', 'After')
        if ($area.Count -gt $MaxRowsPerSection) {
            $lines.Add('')
            $lines.Add(('_{0} more rows in changes.csv_' -f ($area.Count - $MaxRowsPerSection)))
        }
    }
}

if ($IncludeNoise) {
    $noiseRows = @($changes | Where-Object { $_.Signal -eq 'Noise' })
    if ($noiseRows.Count -gt 0) {
        $lines.Add('')
        $lines.Add(('## Filtered noise ({0})' -f $noiseRows.Count))
        foreach ($area in ($noiseRows | Group-Object Area | Sort-Object Name)) {
            $rows = @($area.Group | Sort-Object Target, Name | Select-Object -First $MaxRowsPerSection)
            Add-Table -Lines $lines -Title ("{0} ({1})" -f $area.Name, $area.Count) -Rows $rows -Columns @('Partition', 'Change', 'Target', 'Name', 'Before', 'After')
            if ($area.Count -gt $MaxRowsPerSection) {
                $lines.Add('')
                $lines.Add(('_{0} more rows in changes.csv_' -f ($area.Count - $MaxRowsPerSection)))
            }
        }
    }
}

# Role / feature delta - this is the install list for the rebuild script.
$lines.Add('')
$lines.Add('## Roles and features')
$featureRows = @($changes | Where-Object { $_.Area -eq 'Features' -or $_.Area -eq 'DismFeature' -or $_.Area -eq 'DismPackage' })
if ($featureRows.Count -gt 0) {
    $lines.Add('')
    $lines.Add('| Change | Area | Feature / package | Before | After |')
    $lines.Add('| --- | --- | --- | --- | --- |')
    foreach ($row in ($featureRows | Sort-Object Area, Target)) {
        $lines.Add(('| {0} | {1} | {2} | {3} | {4} |' -f (Format-Cell $row.Change 20), (Format-Cell $row.Area 20), (Format-Cell $row.Target 100), (Format-Cell $row.Before 24), (Format-Cell $row.After 24)))
    }
}
else {
    $lines.Add('')
    $lines.Add('_No role/feature state changes detected._')
}

$installedRolesFile = Join-Path $t1 'features\installed-roles.txt'
if (Test-Path -LiteralPath $installedRolesFile) {
    $lines.Add('')
    $lines.Add('Paste-ready install list for this host (roles and role services as captured at T1):')
    $lines.Add('')
    $lines.Add('```powershell')
    foreach ($installLine in (Get-Content -LiteralPath $installedRolesFile)) { $lines.Add($installLine) }
    $lines.Add('```')
}

# MSCEP final state - directly useful for the restore script
$mscepValues = @()
$regCsv = Join-Path $t1 'registry'
if (Test-Path -LiteralPath $regCsv) {
    foreach ($csv in Get-ChildItem -LiteralPath $regCsv -Filter '*.values.csv' -ErrorAction SilentlyContinue) {
        $mscepValues += Import-Csv -LiteralPath $csv.FullName | Where-Object { $_.Key -match 'MSCEP' }
    }
}
if ($mscepValues.Count -gt 0) {
    $lines.Add('')
    $lines.Add('## MSCEP configuration as installed')
    $lines.Add('')
    $lines.Add('| Key | Name | Value |')
    $lines.Add('| --- | --- | --- |')
    foreach ($row in ($mscepValues | Sort-Object Key, Name)) {
        $lines.Add(('| {0} | {1} | {2} |' -f (Format-Cell $row.Key 120), (Format-Cell $row.Name 60), (Format-Cell $row.Data 160)))
    }
}

# Full paths, untruncated - easier to review and hand to someone else than a table.
$fileRows = @($changes | Where-Object { $_.Area -eq 'Files' -and -not [string]::IsNullOrWhiteSpace($_.Target) })
if ($fileRows.Count -gt 0) {
    $lines.Add('')
    $lines.Add(('## Changed files ({0})' -f $fileRows.Count))
    $lines.Add('')
    $lines.Add('```')
    foreach ($row in ($fileRows | Sort-Object Target | Select-Object -First $MaxRowsPerSection)) {
        $lines.Add(('{0,-9} {1}' -f $row.Change, $row.Target))
    }
    $lines.Add('```')
    if ($fileRows.Count -gt $MaxRowsPerSection) {
        $lines.Add('')
        $lines.Add(('_{0} more paths in changes.csv (Target column)_' -f ($fileRows.Count - $MaxRowsPerSection)))
    }
}

# Scenario focus: the AD writes this operation is expected to make.
if ($settings.Contains('Scenario') -and @($settings.Scenario.AdFocusPatterns).Count -gt 0) {
    $focusPatterns = @($settings.Scenario.AdFocusPatterns)
    $focus = @($changes | Where-Object { $_.Area -eq 'AD' -and (Test-AdFocus -Target $_.Target -Patterns $focusPatterns) })

    $lines.Add('')
    $lines.Add(('## {0} focus - AD objects' -f $settings.Scenario.Name))
    $lines.Add('')

    if ($focus.Count -eq 0) {
        $lines.Add('_No changes matched the focus containers. Check that the capture window covered the')
        $lines.Add('operation, and that `Ad.ExportConfigurationNc` is enabled._')
    }
    else {
        # Group by the well-known container so the report reads like the AD layout.
        $containers = [ordered]@{
            'Enrollment Services'      = 'CN=Enrollment Services'
            'Certification Authorities' = 'CN=Certification Authorities'
            'NTAuthCertificates'       = 'CN=NTAuthCertificates'
            'Certificate Templates'    = 'CN=Certificate Templates'
            'Cert Publishers'          = 'CN=Cert Publishers'
            'AIA'                      = 'CN=AIA'
            'CDP'                      = 'CN=CDP'
            'KRA'                      = 'CN=KRA'
            'OID'                      = 'CN=OID'
        }
        foreach ($container in $containers.Keys) {
            $needle = $containers[$container]
            $rows = @($focus | Where-Object { $_.Target -match [regex]::Escape($needle) })
            if ($rows.Count -eq 0) { continue }
            Add-Table -Lines $lines -Title ("{0} ({1})" -f $container, $rows.Count) -Rows `
                ($rows | Sort-Object Target, Name | Select-Object -First $MaxRowsPerSection) `
                -Columns @('Partition', 'Change', 'Target', 'Name', 'Before', 'After')
        }

        $other = @($focus | Where-Object {
                $dn = $_.Target
                -not ($containers.Values | Where-Object { $dn -match [regex]::Escape($_) })
            })
        if ($other.Count -gt 0) {
            Add-Table -Lines $lines -Title ("Other focus objects ({0})" -f $other.Count) -Rows `
                ($other | Sort-Object Target, Name | Select-Object -First $MaxRowsPerSection) `
                -Columns @('Partition', 'Change', 'Target', 'Name', 'Before', 'After')
        }
    }

    # Binary cACertificate values are unreadable as base64 - decode them.
    $decoded = New-Object System.Collections.Generic.List[object]
    foreach ($row in $focus) {
        if ($row.Name -notmatch '^cACertificate$|^userCertificate$') { continue }
        $value = $row.After
        if ([string]::IsNullOrWhiteSpace($value)) { $value = $row.Before }
        $cert = ConvertFrom-LdifCertificateValue -Value $value
        if ($null -ne $cert) {
            $decoded.Add([pscustomobject]@{
                    Change     = $row.Change
                    Target     = $row.Target
                    Subject    = $cert.Subject
                    Issuer     = $cert.Issuer
                    Thumbprint = $cert.Thumbprint
                    NotAfter   = $cert.NotAfter
                })
        }
    }
    if ($decoded.Count -gt 0) {
        Add-Table -Lines $lines -Title 'Certificates published to AD (decoded)' -Rows $decoded `
            -Columns @('Change', 'Target', 'Subject', 'Issuer', 'Thumbprint', 'NotAfter')
    }

    # Attribution: which account actually performed these writes.
    $auditPath = Join-Path $t1 'ad\ds-change-events-5136.csv'
    if (Test-Path -LiteralPath $auditPath) {
        $focusedAudit = @(Import-Csv -LiteralPath $auditPath |
            Where-Object { Test-AdFocus -Target $_.ObjectDN -Patterns $focusPatterns })
        if ($focusedAudit.Count -gt 0) {
            $lines.Add('')
            $lines.Add('### Accounts that performed the focus writes')
            $lines.Add('')
            $lines.Add('| Account | Writes | Objects |')
            $lines.Add('| --- | --- | --- |')
            foreach ($group in ($focusedAudit | Group-Object { '{0}\{1}' -f $_.SubjectDomainName, $_.SubjectUserName } | Sort-Object Count -Descending)) {
                $objects = @($group.Group | ForEach-Object { $_.ObjectDN } | Sort-Object -Unique).Count
                $lines.Add(('| {0} | {1} | {2} |' -f (Format-Cell $group.Name 40), $group.Count, $objects))
            }
        }
    }
}

# AD object-level view (touched objects + attributed writes)
$touchedFile = Join-Path $t1 'ad\changed-objects.csv'
if (Test-Path -LiteralPath $touchedFile) {
    $touched = @(Import-Csv -LiteralPath $touchedFile)
    $lines.Add('')
    $lines.Add(('## AD objects touched ({0})' -f $touched.Count))
    $lines.Add('')
    $lines.Add('| Object | Class | WhenChanged |')
    $lines.Add('| --- | --- | --- |')
    foreach ($row in ($touched | Sort-Object WhenChanged | Select-Object -First $MaxRowsPerSection)) {
        $lines.Add(('| {0} | {1} | {2} |' -f (Format-Cell $row.DistinguishedName 140), (Format-Cell $row.ObjectClass 60), (Format-Cell $row.WhenChanged 40)))
    }
    if ($touched.Count -gt $MaxRowsPerSection) { $lines.Add(''); $lines.Add(('_{0} more rows in ad\changed-objects.csv_' -f ($touched.Count - $MaxRowsPerSection))) }
}

$auditFile = Join-Path $t1 'ad\ds-change-events-5136.csv'
if (Test-Path -LiteralPath $auditFile) {
    $audit = @(Import-Csv -LiteralPath $auditFile)
    $lines.Add('')
    $lines.Add(('## AD writes attributed by account ({0} events)' -f $audit.Count))
    $lines.Add('')
    $lines.Add('| Subject | Operation | DN | Attribute | Value |')
    $lines.Add('| --- | --- | --- | --- | --- |')
    foreach ($row in ($audit | Sort-Object Time | Select-Object -First $MaxRowsPerSection)) {
        $subject = '{0}\{1}' -f $row.SubjectDomainName, $row.SubjectUserName
        $lines.Add(('| {0} | {1} | {2} | {3} | {4} |' -f (Format-Cell $subject 40), (Format-Cell $row.OperationType 20), (Format-Cell $row.ObjectDN 120), (Format-Cell $row.AttributeLDAPDisplayName 30), (Format-Cell $row.AttributeValue 80)))
    }
    if ($audit.Count -gt $MaxRowsPerSection) { $lines.Add(''); $lines.Add(('_{0} more rows in ad\ds-change-events-5136.csv_' -f ($audit.Count - $MaxRowsPerSection))) }

    # Per-account breakdown: the "what exactly did this account do?" view.
    $lines.Add('')
    $lines.Add('### What each account changed')
    $lines.Add('')
    foreach ($group in ($audit | Group-Object { '{0}\{1}' -f $_.SubjectDomainName, $_.SubjectUserName } | Sort-Object Count -Descending)) {
        $objects = @($group.Group | ForEach-Object { $_.ObjectDN } | Sort-Object -Unique)
        $attributes = @($group.Group | ForEach-Object { $_.AttributeLDAPDisplayName } | Sort-Object -Unique)
        $lines.Add(('**{0}** - {1} write(s) across {2} object(s)' -f $group.Name, $group.Count, $objects.Count))
        $lines.Add('')
        $lines.Add(('Attributes: {0}' -f (($attributes | Where-Object { $_ }) -join ', ')))
        $lines.Add('')
        foreach ($object in ($objects | Select-Object -First 15)) {
            $lines.Add(('- `{0}`' -f $object))
        }
        if ($objects.Count -gt 15) { $lines.Add(('- _(and {0} more object(s) - see ad\ds-change-events-5136.csv)_' -f ($objects.Count - 15))) }
        $lines.Add('')
    }
}
else {
    # No SACL means no attribution. Say so, rather than letting the reader
    # assume the report is showing everything.
    $lines.Add('')
    $lines.Add('## Changes by account')
    $lines.Add('')
    $lines.Add('_Not available: `T1-<label>\ad\ds-change-events-5136.csv` was not produced, so the report')
    $lines.Add('shows WHAT changed (LDIF diff) but not WHICH ACCOUNT changed it._')
    $lines.Add('')
    $lines.Add('To get attribution, apply the SACL before the baseline:')
    $lines.Add('')
    $lines.Add('```powershell')
    $lines.Add('.\Enable-AdDirectoryAuditing.ps1 -Apply -Scenario EnterpriseCA')
    $lines.Add('```')
}

# File modifications attributed to an account (4663). Separate from the USN
# list because it answers a different question: not "what changed" but "who".
$fileAuditCsv = Join-Path $t1 'files\file-access-4663.csv'
if (Test-Path -LiteralPath $fileAuditCsv) {
    $fileAudit = @(Import-Csv -LiteralPath $fileAuditCsv)
    $lines.Add('')
    $lines.Add(('## File modifications by account ({0} event(s))' -f $fileAudit.Count))
    $lines.Add('')

    if ($fileAudit.Count -eq 0) {
        $lines.Add('_No 4663 events in the window: auditing was on but nothing modified the audited paths._')
    }
    else {
        foreach ($group in ($fileAudit | Group-Object Account | Sort-Object Count -Descending)) {
            $paths = @($group.Group | ForEach-Object { $_.Path } | Sort-Object -Unique)
            $processes = @($group.Group | ForEach-Object { $_.ProcessName } | Sort-Object -Unique)
            $lines.Add(('**{0}** - {1} event(s) across {2} file(s)' -f $group.Name, $group.Count, $paths.Count))
            $lines.Add('')
            $lines.Add(('Processes: {0}' -f ((($processes | Where-Object { $_ }) | ForEach-Object { Split-Path -Leaf $_ }) -join ', ')))
            $lines.Add('')
            foreach ($row in ($group.Group | Sort-Object Time | Select-Object -First 20)) {
                $lines.Add(('- `{0}` - {1}' -f $row.Path, $row.Access))
            }
            if ($group.Count -gt 20) {
                $lines.Add(('- _(and {0} more - see T1-<label>\files\file-access-4663.csv)_' -f ($group.Count - 20)))
            }
            $lines.Add('')
        }
    }
}
elseif ($null -ne $state -and ($state.PSObject.Properties.Name -contains 'FileAuditing') -and $state.FileAuditing) {
    $lines.Add('')
    $lines.Add('## File modifications by account')
    $lines.Add('')
    $lines.Add('_Requested with -FileAuditing, but no `files\file-access-4663.csv` was produced._')
    $lines.Add('_Check `T1-<label>\collectors.csv` for the `fileaudit` row, and confirm the SACLs_')
    $lines.Add('_were applied with `Enable-FileAuditing.ps1 -Status`._')
}

$lines.Add('')
$lines.Add('## Evidence')
$lines.Add('')
$lines.Add('- `changes.csv` - every change, all areas')
$lines.Add('- `high-signal.csv` - filtered to the configured high-signal patterns')
$lines.Add('- `T1-<label>\registry\*.reg` - raw exports; these are also the restore source')
$lines.Add('- `T1-<label>\files\changed-usn.csv` - raw USN change list')
$lines.Add('- `T1-<label>\features\installed-roles.txt` - paste-ready `Install-WindowsFeature` list')
$lines.Add('- `T1-<label>\features\dism-packages.txt` - component-level payload list')
$lines.Add('- `T1-<label>\iis\applicationHost.config` - IIS config as installed')

Set-Content -LiteralPath (Join-Path $OutDir 'report.md') -Value ($lines -join "`r`n") -Encoding UTF8

Write-CaptureLog ('report: {0}' -f (Join-Path $OutDir 'report.md'))
Write-CaptureLog ('changes: {0} (high-signal {1})' -f $changes.Count, $high.Count)
