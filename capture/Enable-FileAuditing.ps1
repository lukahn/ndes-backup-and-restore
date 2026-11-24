#Requires -Version 5.1
<#
.SYNOPSIS
    Turns on (or off) file system auditing for specific paths, so the capture
    can report WHICH ACCOUNT modified WHICH FILE.

.DESCRIPTION
    The USN journal records what changed on a volume, never who. To attribute
    file changes to an account you need:
        1. the "Audit File System" audit subcategory enabled (success), and
        2. an inheritable SACL on the folder(s) of interest.

    That combination produces event 4663, which records the account, the file,
    the access type and the process responsible.

    Enable this before Start-NdesCapture.ps1, then pass -FileAuditing to
    Start/Stop so the events are collected for the window.

    Scope it narrowly. Auditing a whole system volume on a domain controller
    produces events faster than you can read them; one or two folders is the
    intended use.

    -Status shows current state, -Revert removes the SACLs again.

.NOTES
    Lab instrumentation. Needs SeSecurityPrivilege - run elevated as a member
    of Domain Admins (or an account with the backup/security privileges).

.EXAMPLE
    .\Enable-FileAuditing.ps1 -Apply -Path C:\Windows\System32\CertLog

.EXAMPLE
    .\Enable-FileAuditing.ps1 -Apply -PathFile .\audit-paths.txt

.EXAMPLE
    .\Enable-FileAuditing.ps1 -Status

.EXAMPLE
    .\Enable-FileAuditing.ps1 -Revert -Path C:\Windows\System32\CertLog
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Apply')][switch]$Apply,
    [Parameter(ParameterSetName = 'Revert')][switch]$Revert,
    [Parameter(ParameterSetName = 'Status')][switch]$Status,

    [string[]]$Path,
    [string]$PathFile,
    [string]$AuditPrincipal = 'Everyone',
    [string]$SettingsPath
)

$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot 'lib\NdesCapture.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "Module not found: $modulePath - copy the whole kit folder, including lib\ and config\."
}
Import-Module $modulePath -Force

# Paths come from three places: -Path, -PathFile, or the defaults in the settings.
$targets = New-Object System.Collections.Generic.List[string]
foreach ($p in @($Path)) {
    if (-not [string]::IsNullOrWhiteSpace($p)) { $targets.Add($p) }
}
if ($PathFile -and (Test-Path -LiteralPath $PathFile)) {
    foreach ($line in (Get-Content -LiteralPath $PathFile)) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) { continue }
        $targets.Add($trimmed)
    }
}
if ($targets.Count -eq 0) {
    if (-not $SettingsPath) { $SettingsPath = Join-Path $PSScriptRoot 'config\capture-settings.psd1' }
    if (Test-Path -LiteralPath $SettingsPath) {
        $settings = Import-CaptureSettings -Path $SettingsPath
        if ($settings.Contains('FileAudit')) {
            foreach ($p in @($settings.FileAudit.Paths)) {
                if (-not [string]::IsNullOrWhiteSpace($p)) { $targets.Add($p) }
            }
        }
    }
}

if ($targets.Count -eq 0 -and $PSCmdlet.ParameterSetName -ne 'Status') {
    throw 'No paths specified. Use -Path or -PathFile, or configure FileAudit.Paths in config\capture-settings.psd1.'
}

function Test-Exists {
    param([string]$p)
    if (Test-Path -LiteralPath $p) { return $true }
    Write-Host ('  skipped (not present): {0}' -f $p) -ForegroundColor Yellow
    return $false
}

switch ($PSCmdlet.ParameterSetName) {
    'Apply' {
        Enable-CapturePrivilege
        Set-FileSystemAuditPolicy -Enabled $true
        Write-Host 'Enabled audit subcategory: File System (success)'
        Write-Host ('Auditing principal: {0}' -f $AuditPrincipal)
        Write-Host ''

        foreach ($target in $targets) {
            if (-not (Test-Exists $target)) { continue }
            try {
                Add-FileAuditRule -Path $target -Principal $AuditPrincipal
                Write-Host ('Added inheritable audit entry: {0}' -f $target)
            }
            catch {
                throw ('Failed to write SACL on {0}: {1}' -f $target, $_.Exception.Message)
            }
        }

        Write-Host ''
        Write-Host '4663 events will now record, for these paths:'
        Write-Host '  - the account that modified the file'
        Write-Host '  - the file name and the access type'
        Write-Host '  - the process responsible'
        Write-Host ''
        Write-Host 'Now run:  .\Start-NdesCapture.ps1 -Label <label> -FileAuditing'
    }

    'Revert' {
        Enable-CapturePrivilege
        foreach ($target in $targets) {
            if (-not (Test-Exists $target)) { continue }
            $removed = Remove-FileAuditRule -Path $target -Principal $AuditPrincipal
            Write-Host ('Removed {0} audit entr(y/ies) from: {1}' -f $removed, $target)
        }
        Set-FileSystemAuditPolicy -Enabled $false
        Write-Host 'Disabled audit subcategory: File System'
    }

    default {
        Write-Host 'File System audit policy:'
        Get-FileSystemAuditPolicy | ForEach-Object { Write-Host ('  {0}' -f $_) }

        try { Enable-CapturePrivilege } catch { Write-Host ('  warning: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }
        $sid = $null
        try {
            $sid = (New-Object System.Security.Principal.NTAccount($AuditPrincipal)).Translate([System.Security.Principal.SecurityIdentifier])
        }
        catch { Write-Host ('  warning: cannot resolve {0}' -f $AuditPrincipal) -ForegroundColor Yellow }

        if ($targets.Count -eq 0) { Write-Host "`nNo paths configured - pass -Path to inspect a specific folder." ; return }

        foreach ($target in $targets) {
            Write-Host "`nAudit entries on: $target"
            if (-not (Test-Path -LiteralPath $target)) { Write-Host '  (path not present)' -ForegroundColor Yellow; continue }
            try {
                $rules = @(Get-FileAuditRules -Path $target -Identity $sid)
                if ($rules.Count -eq 0) { Write-Host ('  (none for {0})' -f $AuditPrincipal) }
                foreach ($rule in $rules) {
                    Write-Host ('  {0} -> {1} [{2}] inherit={3}' -f $AuditPrincipal, $rule.FileSystemRights, $rule.AuditFlags, $rule.InheritanceFlags)
                }
            }
            catch { Write-Host ('  could not read SACL: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }
        }
    }
}
