#Requires -Version 5.1
<#
.SYNOPSIS
    Turns on (or off) the directory-change auditing that makes 5136 events
    available, so the capture can tell you *which account* wrote what to AD.

.DESCRIPTION
    The LDIF diff already proves what changed. This adds attribution: every
    attribute write is logged with the subject, object and old/new value -
    which is how you answer "what did the NDES installer need Enterprise
    Admin for?" without guessing.

    Run on a domain controller, elevated, before Start-NdesCapture.ps1.
    -Status shows current state, -Revert removes the SACL again.

.NOTES
    This is lab instrumentation. In production, set the equivalent through
    Group Policy (Advanced Audit Policy > DS Access > Audit Directory Service
    Changes) plus a SACL, and expect a larger Security log.
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Apply')][switch]$Apply,
    [Parameter(ParameterSetName = 'Revert')][switch]$Revert,
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    [string]$DomainDistinguishedName,
    [switch]$IncludeConfigurationNc,
    [string]$Scenario,
    [string]$AuditPrincipal = 'Authenticated Users'
)

$ErrorActionPreference = 'Stop'

# Scenarios that write to the Configuration partition need the SACL there too.
if ($Scenario) {
    $settingsPath = Join-Path $PSScriptRoot 'config\capture-settings.psd1'
    if (Test-Path -LiteralPath $settingsPath) {
        $all = Import-PowerShellDataFile -LiteralPath $settingsPath
        if ($all.ContainsKey('Scenarios') -and $all.Scenarios.ContainsKey($Scenario)) {
            $scenarioConfig = $all.Scenarios[$Scenario]
            if ($scenarioConfig.ContainsKey('IncludeConfigurationNc') -and $scenarioConfig.IncludeConfigurationNc) {
                $IncludeConfigurationNc = $true
            }
        }
        else {
            throw ("Unknown scenario '{0}'. Available: {1}" -f $Scenario, (@($all.Scenarios.Keys) -join ', '))
        }
    }
}

$dsChangeSubcategory = '{0CCE923F-69AE-11D9-BED3-505054503030}'  # Directory Service Changes

# The AD ACE types live in System.DirectoryServices (not System.Security.AccessControl);
# load it explicitly so the type literals below always resolve.
try { Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop } catch {
    throw ('System.DirectoryServices could not be loaded: {0}' -f $_.Exception.Message)
}

# ------------------------------------------------------------------ helpers ---

$privilegeSource = @'
using System;
using System.Runtime.InteropServices;

public static class NdesPrivilege
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAll, ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    public static bool Enable(string name)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out token)) { return false; }
        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, name, out luid)) { return false; }
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privilege.Luid = luid;
            tp.Privilege.Attributes = 0x00000002;
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) { return false; }
            return Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(token); }
    }
}
'@

function Enable-SecurityPrivilege {
    if (-not ('NdesPrivilege' -as [type])) {
        Add-Type -TypeDefinition $privilegeSource -Language CSharp -ErrorAction Stop
    }
    if (-not [NdesPrivilege]::Enable('SeSecurityPrivilege')) {
        throw 'Could not enable SeSecurityPrivilege. Run elevated as a member of Domain Admins.'
    }
}

function Get-RootDseValue {
    param([string]$Name)
    $rootDse = $null
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $value = $rootDse.Properties[$Name].Value
        if ($null -eq $value) { return $null }
        return [string]$value
    }
    catch { return $null }
    finally {
        # Close() throws on an unreachable domain; don't let it mask the result.
        if ($null -ne $rootDse) { try { $rootDse.Close() } catch { } }
    }
}

function Get-ConfigurationNc {
    return Get-RootDseValue -Name 'configurationNamingContext'
}

function Get-AuditTargets {
    $targets = New-Object System.Collections.Generic.List[string]
    $domainDn = $DomainDistinguishedName
    if (-not $domainDn) { $domainDn = Get-RootDseValue -Name 'defaultNamingContext' }
    if ([string]::IsNullOrWhiteSpace($domainDn)) {
        throw 'No domain naming context found. This script must run on a domain controller in a domain-joined forest.'
    }
    $targets.Add($domainDn)
    if ($IncludeConfigurationNc) {
        $configNc = Get-ConfigurationNc
        if (-not [string]::IsNullOrWhiteSpace($configNc)) { $targets.Add($configNc) }
    }
    return $targets
}

function Get-AuditRuleTemplate {
    $sid = New-Object System.Security.Principal.NTAccount($AuditPrincipal)
    $rights = [System.DirectoryServices.ActiveDirectoryRights]'WriteProperty, CreateChild, DeleteChild, Delete, WriteDacl, WriteOwner'
    $flags = [System.Security.AccessControl.AuditFlags]'Success, Failure'
    # AD ACEs use ActiveDirectorySecurityInheritance (Self/Children/Descendents/All),
    # not InheritanceFlags/PropagationFlags. 'All' = this object plus every child.
    $inherit = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    return New-Object System.DirectoryServices.ActiveDirectoryAuditRule($sid, $rights, $flags, $inherit)
}

function Get-AuditPrincipalSid {
    # ACEs come back with a SecurityIdentifier, never an NTAccount, so all
    # comparisons are done on SID strings.
    try {
        $account = New-Object System.Security.Principal.NTAccount($AuditPrincipal)
        return $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw ("Could not resolve audit principal '{0}': {1}" -f $AuditPrincipal, $_.Exception.Message)
    }
}

function Get-AuditRulesAsSid {
    param([Parameter(Mandatory)]$Security)
    return @($Security.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
}

function Get-AuditableDescriptor {
    <#
        Reads the security descriptor INCLUDING the SACL.

        DirectoryEntry does not request the SACL (and its Options.SecurityMasks
        config is unavailable through PowerShell), so the search-result path is
        used instead: DirectorySearcher.SecurityMasks is honoured, and the
        returned binary descriptor is decoded into a modifiable
        ActiveDirectorySecurity object.
    #>
    param([string]$DistinguishedName)

    $rootEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DistinguishedName")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    try {
        $searcher.SearchRoot = $rootEntry
        $searcher.Filter = '(objectClass=*)'
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Owner, Group, Dacl, Sacl'

        $result = $searcher.FindOne()
        if ($null -eq $result) { throw "Object not found: $DistinguishedName" }

        $bytes = $result.Properties['nTSecurityDescriptor'][0]
        if ($null -eq $bytes -or $bytes.Length -lt 20) {
            throw 'Security descriptor could not be read. Ensure SeSecurityPrivilege is held (elevated Domain Admin/Enterprise Admin).'
        }
    }
    finally {
        $searcher.Dispose()
        try { $rootEntry.Close() } catch { }
    }

    $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $security.SetSecurityDescriptorBinaryForm($bytes)

    # A separate entry is used for the write side of the operation.
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DistinguishedName")
    return [pscustomobject]@{ Entry = $entry; Security = $security }
}

# --------------------------------------------------------------------- modes ---

function Show-Status {
    Write-Host 'Directory Service Changes audit policy:'
    $auditOutput = & auditpol.exe /get /subcategory:$dsChangeSubcategory 2>&1
    $auditOutput | ForEach-Object { Write-Host "  $_" }

    # Reading a SACL needs SeSecurityPrivilege; enable it for this process or the
    # read silently reports nothing.
    try { Enable-SecurityPrivilege }
    catch { Write-Host ('  warning: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }

    $principalSid = $null
    try { $principalSid = Get-AuditPrincipalSid } catch { Write-Host ('  warning: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }

    foreach ($target in (Get-AuditTargets)) {
        Write-Host "`nSACL audit entries on: $target"
        try {
            $descriptor = Get-AuditableDescriptor -DistinguishedName $target
            try {
                $rules = Get-AuditRulesAsSid -Security $descriptor.Security
                $matching = @($rules | Where-Object { $principalSid -and $_.IdentityReference.Value -eq $principalSid })
                if ($matching.Count -eq 0) {
                    Write-Host ('  (none for {0} - SID {1})' -f $AuditPrincipal, $principalSid)
                }
                foreach ($rule in $matching) {
                    Write-Host ('  {0} ({1}) -> {2} [{3}] inherit={4}' -f $AuditPrincipal, $rule.IdentityReference.Value, $rule.ActiveDirectoryRights, $rule.AuditFlags, $rule.InheritanceType)
                }
                $others = $rules.Count - $matching.Count
                if ($others -gt 0) { Write-Host ("  ({0} other audit entr(y/ies) present, left alone)" -f $others) }
            }
            finally { $descriptor.Entry.Close() }
        }
        catch {
            Write-Host ('  could not read SACL: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}

function Enable-Auditing {
    Enable-SecurityPrivilege

    & auditpol.exe /set /subcategory:$dsChangeSubcategory /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol failed to enable Directory Service Changes.' }
    Write-Host "Enabled audit subcategory: Directory Service Changes"

    $template = Get-AuditRuleTemplate

    foreach ($target in (Get-AuditTargets)) {
        $descriptor = Get-AuditableDescriptor -DistinguishedName $target
        try {
            $security = $descriptor.Security
            $security.AddAuditRule($template)
            $descriptor.Entry.ObjectSecurity = $security
            $descriptor.Entry.CommitChanges()
            Write-Host "Added SACL audit entry on: $target"
        }
        catch {
            $hint = ''
            if ($_.Exception.Message -match 'access is denied|0x5') {
                $hint = ' (needs SeSecurityPrivilege, i.e. an elevated Domain Admin/Enterprise Admin session)'
            }
            throw ("Failed to write SACL on {0}: {1}{2}" -f $target, $_.Exception.Message, $hint)
        }
        finally { $descriptor.Entry.Close() }
    }

    Write-Host ''
    Write-Host 'Directory-change auditing is on. 5136 events will now record:'
    Write-Host '  - the account that made the write'
    Write-Host '  - the object DN and attribute'
    Write-Host '  - the value written'
}

function Disable-Auditing {
    Enable-SecurityPrivilege
    $principalSid = Get-AuditPrincipalSid

    foreach ($target in (Get-AuditTargets)) {
        $descriptor = Get-AuditableDescriptor -DistinguishedName $target
        try {
            $security = $descriptor.Security
            $rules = Get-AuditRulesAsSid -Security $security
            $removed = 0
            foreach ($rule in $rules) {
                if ($rule.IdentityReference.Value -ne $principalSid) { continue }
                if ($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) {
                    [void]$security.RemoveAuditRule($rule)
                    $removed++
                }
            }
            if ($removed -gt 0) {
                $descriptor.Entry.ObjectSecurity = $security
                $descriptor.Entry.CommitChanges()
            }
            Write-Host ("Removed {0} audit rule(s) from: {1}" -f $removed, $target)
        }
        finally { $descriptor.Entry.Close() }
    }

    & auditpol.exe /set /subcategory:$dsChangeSubcategory /success:disable /failure:disable | Out-Null
    Write-Host 'Disabled audit subcategory: Directory Service Changes'
}

switch ($PSCmdlet.ParameterSetName) {
    'Apply' { Enable-Auditing }
    'Revert' { Disable-Auditing }
    default { Show-Status }
}
