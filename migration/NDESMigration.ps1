#Requires -Version 5.1
<#
.SYNOPSIS
    Backs up and restores a Network Device Enrollment Service (NDES) configuration
    between servers without requiring Enterprise Admin.

.DESCRIPTION
    The stock NDES setup wizard needs Enterprise Admin because it publishes RA
    certificates to the service account in Active Directory. This script avoids
    that entirely by reproducing the configuration directly:

        - roles/features installed with Install-WindowsFeature
        - SCEP IIS application pool and applications created with appcmd
        - registry written from the backup: MSCEP, ADCS\NDES and the http.sys
          MaxFieldLength/MaxRequestBytes limits
        - RA certificates re-enrolled locally into the machine MY store
        - server (SSL) certificate re-requested for the target host
        - IIS application pool identity set from PowerShell, which is the step
          IIS Manager cannot do for this configuration

    Requires the source to be configured with CertsInMYStore = 1, which is what
    makes this possible: RA certificates are located by template in the machine
    store rather than by thumbprint hash, so nothing machine-specific has to be
    copied.

    -Backup  reads a live server (or an existing NdesCapture folder) and writes a
             portable JSON bundle. It contains no secrets and no private keys.
    -Restore rebuilds the configuration on the target server from that bundle.

.PARAMETER Backup
    Capture the current configuration into a bundle.

.PARAMETER Restore
    Rebuild the configuration from a bundle.

.PARAMETER Path
    Bundle folder. With -Backup, the destination (default
    C:\NDESMigration\<host>-<timestamp>); existing folders are fine, but an
    existing ndes-config.json is only overwritten with -Force. Relative paths
    and UNC paths are accepted. With -Restore, the bundle to use - a folder or
    the ndes-config.json file itself; if omitted, the newest bundle under
    C:\NDESMigration is used.

.PARAMETER FromCapture
    With -Backup: read an existing NdesCapture-NDES folder instead of the live
    server. Useful for rebuilding on a machine that cannot reach the source.

.PARAMETER ServiceAccount
    With -Restore: the account the SCEP application pool runs as. Defaults to
    the value recorded at backup time; you are always prompted to confirm it.

.PARAMETER ServiceAccountCredential
    Credentials for the service account. If omitted you are prompted, so the
    password is never stored in the bundle or on disk. It is used to set the app
    pool identity and to request the RA certificates as that account. Not
    applicable to a gMSA - see -UseGmsa.

.PARAMETER UseGmsa
    With -Restore: the service account is a group Managed Service Account, so
    there is no password to type or store. The app pool identity is written with
    the account name only, and the checks that need a password are replaced by
    gMSA ones. If omitted you are asked, defaulting to yes when the name ends in
    '$'. The gMSA is registered on this host with Install-ADServiceAccount before
    the preflight runs, and therefore also with -SkipPreflight.

.PARAMETER Spn
    With -Restore and a gMSA: extra service principal names to register, beyond
    HTTP/<server FQDN>, which is always added. Use it when clients reach the
    server through another name - a CNAME, or a load balancer address - because
    Kerberos resolves on the name the client typed and silently falls back to
    NTLM when there is no SPN for it.

.PARAMETER CAConfig
    Override the CA configuration string (default: captured value).

.PARAMETER RASigningTemplate
    With -Restore: template for the RA signing certificate. Defaults to the
    recorded MSCEP SignatureTemplate. It selects what to enrol and is never
    written to MSCEP - the three MSCEP template values are all set to the
    bundle's GeneralPurposeTemplate, which is what NDES needs.

.PARAMETER RAEncryptionTemplate
    With -Restore: template for the RA encryption certificate. Defaults to the
    recorded MSCEP EncryptionTemplate. Enrolment only, like -RASigningTemplate.

.PARAMETER EnrollmentPolicyUrl
    With -Restore: force alternate-credential enrolment through a certificate
    enrollment policy (CEP) endpoint instead of impersonating the service account
    locally. Requires the Certificate Enrollment Policy role service on the CA,
    which a default CA does not publish.

.PARAMETER ServerCertificateTemplate
    Template used for the new server certificate (default: NDESServer, or the
    value recorded at backup time).

.PARAMETER SkipRACertificates
    Do not enrol RA certificates. Use when they already exist in the machine
    MY store.

.PARAMETER SkipServerCertificate
    Do not request or bind a server certificate. Use when IIS is already
    configured with a valid certificate.

.PARAMETER Preflight
    Run only the preflight checks and exit. The checks themselves change nothing -
    the one exception is a gMSA, which is registered on this host first
    (Install-ADServiceAccount), because every check about the account depends on
    it. -WhatIf still prevents that.

.PARAMETER SkipPreflight
    Skip the preflight checks. Use when a check is known to fail for a reason
    that does not affect this restore (for example an ACL the check cannot model).

.PARAMETER Force
    With -Restore: recreate IIS objects that already exist.

.EXAMPLE
    .\NDESMigration.ps1 -Backup

    Captures this server into C:\NDESMigration\NDES-20261123-140000.

.EXAMPLE
    .\NDESMigration.ps1 -Backup -FromCapture C:\Uploads\NdesCapture-NDES -Path C:\Staging\ndes

    Builds a bundle from an existing capture folder.

.EXAMPLE
    .\NDESMigration.ps1 -Restore -Path C:\Staging\ndes

    Rebuilds NDES on this server, prompting for the service account password.

.EXAMPLE
    .\NDESMigration.ps1 -Restore -Path C:\Staging\ndes -WhatIf

    Shows every change the restore would make without making any of them.
    Note that -WhatIf does NOT validate permissions - add -Preflight for that.

.EXAMPLE
    .\NDESMigration.ps1 -Restore -Path C:\Staging\ndes -Preflight

    Runs the read-only preflight checks against the target and exits.

.NOTES
    Both modes support -WhatIf. Run it once before a real restore to see exactly
    which app pool, applications, registry values, certificate requests and
    bindings the target would receive.

    Run elevated on both servers. The restore account needs:
      - local Administrator on the target
      - Enroll rights on the CEP Encryption and Exchange Enrollment Agent
        (Offline) templates
      - Request Certificates on the CA
    It does NOT need Enterprise Admin, Domain Admin, or any rights on the
    service account's AD object.
#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Backup')]
param(
    [Parameter(ParameterSetName = 'Backup', Mandatory = $true)]
    [switch]$Backup,

    [Parameter(ParameterSetName = 'Restore', Mandatory = $true)]
    [switch]$Restore,

    [Parameter(ParameterSetName = 'Backup')]
    [Parameter(ParameterSetName = 'Restore')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Backup')]
    [string]$FromCapture,

    [Parameter(ParameterSetName = 'Restore')]
    [string]$ServiceAccount,

    [Parameter(ParameterSetName = 'Restore')]
    [System.Management.Automation.PSCredential]$ServiceAccountCredential,

    [Parameter(ParameterSetName = 'Restore')]
    [switch]$UseGmsa,

    # Extra SPNs to register on the gMSA, beyond HTTP/<server FQDN>. Use when
    # clients reach the server through another name (a CNAME, a load balancer).
    [Parameter(ParameterSetName = 'Restore')]
    [string[]]$Spn,

    [Parameter(ParameterSetName = 'Restore')]
    [string]$CAConfig,

    [Parameter(ParameterSetName = 'Restore')]
    [string]$RASigningTemplate,

    [Parameter(ParameterSetName = 'Restore')]
    [string]$RAEncryptionTemplate,

    [Parameter(ParameterSetName = 'Restore')]
    [string]$EnrollmentPolicyUrl,

    [Parameter(ParameterSetName = 'Restore')]
    [string]$ServerCertificateTemplate,

    [Parameter(ParameterSetName = 'Restore')]
    [switch]$SkipRACertificates,

    # Alternate source for features whose payload this build does not carry
    # (Sources\SxS on the installation media). Used by both
    # Install-WindowsFeature and DISM when a required feature is missing.
    [Parameter(ParameterSetName = 'Restore')]
    [string]$FeatureSource,

    [Parameter(ParameterSetName = 'Restore')]
    [switch]$SkipServerCertificate,

    [Parameter(ParameterSetName = 'Restore')]
    [switch]$Preflight,

    [Parameter(ParameterSetName = 'Restore')]
    [switch]$SkipPreflight,

    # Read-only: compare this server with the bundle and report every difference.
    # Nothing is written, and it does not prompt - values come from the bundle and
    # from the -CAConfig/-RA*Template overrides.
    [Parameter(ParameterSetName = 'Restore')]
    [switch]$Verify,

    # Apply every difference the comparison finds without asking. Without it you
    # are asked once per repair.
    [Parameter(ParameterSetName = 'Restore')]
    [switch]$FixDrift,

    # Applies to both operations: overwrite the bundle (-Backup) or recreate
    # existing IIS objects (-Restore).
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ----------------------------------------------------------------- constants ---

$script:MSCEPKeyPath = 'HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP'
$script:MSCEPKeyNative = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MSCEP'
$script:MscepPhysicalPath = Join-Path $env:SystemRoot 'System32\CertSrv\mscep'
$script:AppPoolName = 'SCEP'
$script:SiteName = 'Default Web Site'
$script:AppPaths = @('/CertSrv/mscep', '/CertSrv/mscep_admin')
$script:MscepDll = Join-Path $script:MscepPhysicalPath 'mscep.dll'
$script:AppCmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
$script:BundleSchemaVersion = 3
$script:LogFile = $null

# Identity of the copy that is actually running. Bundles and restores are run from
# a share, and a stale copy silently produces the previous release's behaviour -
# which looks exactly like a configuration bug. Stamping the script's own hash
# makes "which version ran?" answerable from the log.
$script:ScriptPath = $MyInvocation.MyCommand.Path
if (-not $script:ScriptPath) { $script:ScriptPath = $PSCommandPath }
$script:ScriptHash = ''
$script:ScriptBuilt = 'unknown'
if ($script:ScriptPath -and (Test-Path -LiteralPath $script:ScriptPath)) {
    try { $script:ScriptHash = (Get-FileHash -LiteralPath $script:ScriptPath -Algorithm SHA256).Hash } catch { }
    try { $script:ScriptBuilt = (Get-Item -LiteralPath $script:ScriptPath).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { }
}

# Per-application IIS settings the NDES install writes. They are not cosmetic:
#
#   handlers accessPolicy = 'Read, Execute'
#       ISAPI-dll carries requireAccess="Execute", and IIS skips any handler whose
#       access type the current handlers section does not allow. The inherited
#       value is "Read, Script", so without the per-application override the
#       ISAPI never runs and StaticFile serves mscep.dll as a download - which
#       looks like "NDES is not working" and is what an empty browser download of
#       mscep.dll actually is.
#   anonymousAuthentication on /CertSrv/mscep
#       Devices performing SCEP have no domain account, so the device endpoint
#       must answer anonymously. mscep_admin is the opposite: an administrator
#       mints the one-time password with Windows credentials.
#   requestFiltering allowDoubleEscaping
#       SCEP query strings carry base64 payloads whose '+', '/' and '=' arrive
#       percent-encoded, which IIS rejects unless double escaping is allowed.
#
# Values recorded in a bundle win; these are the fallbacks for bundles that
# never recorded them (schema 2 and older).
$script:ApplicationIisDefaults = @{
    '/CertSrv/mscep'       = @{
        Anonymous           = $true
        Windows             = $true
        AccessPolicy        = 'Read, Execute'
        AllowDoubleEscaping = $true
        MaxQueryString      = 65536
        DefaultDocument     = 'mscep.dll'
    }
    '/CertSrv/mscep_admin' = @{
        Anonymous           = $false
        Windows             = $true
        AccessPolicy        = 'Read, Execute'
        AllowDoubleEscaping = $true
        MaxQueryString      = 65536
        DefaultDocument     = 'mscep.dll'
    }
}

# What a rebuilt NDES host needs *on top of a fresh server*, whatever the bundle
# says - the delta between softwareCheck/installed-base.txt (a fresh server) and
# softwareCheck/installed-manually.txt (the hand-built reference).
#
# Two rules keep the result identical to the reference instead of a superset:
#
#   1. Default features are never requested. A fresh server already has them
#      (installed-base.txt), so listing them only invites the installer to
#      resolve their children.
#   2. Leaf features are requested, never intermediate parents. Install-WindowsFeature
#      installs a feature's *default children* along with it, so asking for a
#      parent pulls in siblings the reference build never had: AD-Certificate
#      brings ADCS-Cert-Authority, RSAT brings every RSAT tool,
#      NET-WCF-Services45 brings MSMQ and the pipe/TCP activations,
#      Web-Mgmt-Tools brings the IIS 6 console. Parents still get installed -
#      they are dependencies of the leaves below - they are just never asked for.
#      See $script:NeverRequestFeatures.
#
# HTTP Activation (both the .NET Framework 3.5 feature and WCF Services 4.5) is
# here because the documented NDES installation selects it:
# https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/hello-hybrid-aadj-sso-cert
$script:BaselineFeatures = @(
    # AD CS - the role service only; AD-Certificate is its parent
    'ADCS-Device-Enrollment'
    # Windows Process Activation Service
    'WAS'
    'WAS-Process-Model'
    'WAS-NET-Environment'
    'WAS-Config-APIs'
    # .NET Framework 3.5 (with HTTP activation) and 4.x WCF HTTP activation.
    # NET-Framework-45-Features/-Core, NET-WCF-Services45 and
    # NET-WCF-TCP-PortSharing45 are fresh-server defaults and are not listed.
    'NET-Framework-Features'
    'NET-Framework-Core'
    'NET-HTTP-Activation'
    'NET-Framework-45-ASPNET'
    'NET-WCF-HTTP-Activation45'
    # IIS - the role and the role services the reference build selected
    'Web-Server'
    'Web-WebServer'
    'Web-Common-Http'
    'Web-Default-Doc'
    'Web-Dir-Browsing'
    'Web-Http-Errors'
    'Web-Static-Content'
    'Web-Http-Redirect'
    'Web-Health'
    'Web-Http-Logging'
    'Web-Log-Libraries'
    'Web-Request-Monitor'
    'Web-Http-Tracing'
    'Web-Performance'
    'Web-Stat-Compression'
    'Web-Security'
    'Web-Filtering'
    'Web-Windows-Auth'
    'Web-App-Dev'
    'Web-Net-Ext'
    'Web-Net-Ext45'
    'Web-Asp-Net45'
    'Web-ISAPI-Ext'
    'Web-ISAPI-Filter'
    # IIS Manager and the IIS 6 compatibility pieces (not the IIS 6 console)
    'Web-Mgmt-Console'
    'Web-Metabase'
    'Web-WMI'
    # The CA console MMC add-on; RSAT, RSAT-Role-Tools and RSAT-ADCS are parents
    'RSAT-ADCS-Mgmt'
    # Present in the reference build and not on a fresh server
    'PowerShell-V2'
)

# Features that come from the .NET 3.5 payload, which newer Server builds remove
# by default. If they cannot be installed the restore retries without them rather
# than failing a rebuild, and says so.
$script:PayloadDependentFeatures = @(
    'NET-Framework-Features'
    'NET-Framework-Core'
    'NET-HTTP-Activation'
    'Web-Net-Ext'
    'WAS-NET-Environment'
)

# Without these there is no NDES, so a missing one is a hard failure rather than a
# skip. That distinction matters: a server whose AD CS role is installed but whose
# NDES role service is not still has mscep.dll on disk and the SCEP IIS
# applications in applicationHost.config from an earlier install, and every check
# that looks at those alone reports success while the ISAPI cannot execute.
$script:RequiredFeatures = @(
    'ADCS-Device-Enrollment'
    'Web-Server'
    'Web-ISAPI-Ext'
    'Web-Windows-Auth'
)

# Features that are never *requested*, even when a bundle recorded them or a
# default sneaks into the list above. Two reasons:
#
#   - parent features, whose default children are not in the reference build. The
#     parent itself still gets installed as a dependency of the leaves we do ask
#     for, so excluding it costs nothing and prevents the whole subtree.
#   - fresh-server defaults, which are already installed before the restore runs.
#
# Measured against softwareCheck/installed-automated-2.txt, which overshot the
# reference build by 24 features: every one of them came from this list.
$script:NeverRequestFeatures = @(
    # parent of ADCS-Device-Enrollment; requesting it installs the CA role service
    'AD-Certificate'
    # the CA role service; the documented procedure clears its check box
    'ADCS-Cert-Authority'
    # RSAT tree: requesting any of these installs every tool underneath it
    'RSAT'
    'RSAT-Role-Tools'
    'RSAT-ADCS'                 # also installs RSAT-Online-Responder
    # requesting this installs MSMQ, the pipe/TCP activations and the MSMQ role
    'NET-WCF-Services45'
    # requesting either installs the IIS 6 management console
    'Web-Mgmt-Tools'
    'Web-Mgmt-Compat'
    # fresh-server defaults (installed-base.txt)
    'FileAndStorage-Services'
    'Storage-Services'
    'Windows-Defender'
    'WoW64-Support'
    'XPS-Viewer'
    'PowerShellRoot'
    'PowerShell'
    'PowerShell-ISE'
    'NET-Framework-45-Features'
    'NET-Framework-45-Core'
    'NET-WCF-TCP-PortSharing45'
)

# Features whose presence means a parent feature was requested (or the box was
# built by hand) rather than the leaves. The whole list came from
# softwareCheck/installed-automated-2.txt the one time parents were requested;
# with $script:BaselineFeatures and $script:NeverRequestFeatures a clean rebuild
# produces none of them.
$script:OverInstallIndicators = @(
    # AD-Certificate -> Certification Authority
    'ADCS-Cert-Authority'
    # Web-Mgmt-Tools / Web-Mgmt-Compat -> IIS 6 console
    'Web-Lgcy-Mgmt-Console'
    'Web-Lgcy-Scripting'
    # RSAT -> every tool in the tree
    'RSAT-Feature-Tools'
    'RSAT-SMTP'
    'RSAT-AD-Tools'
    'RSAT-AD-PowerShell'
    'RSAT-ADDS'
    'RSAT-AD-AdminCenter'
    'RSAT-ADDS-Tools'
    'RSAT-ADLDS'
    'RSAT-Hyper-V-Tools'
    'Hyper-V-Tools'
    'Hyper-V-PowerShell'
    'RSAT-RDS-Tools'
    'RSAT-WDS'
    'UpdateServices-RSAT'
    'UpdateServices-API'
    'UpdateServices-UI'
    # RSAT-ADCS -> Online Responder
    'RSAT-Online-Responder'
    # NET-WCF-Services45 -> every activation and the MSMQ role
    'NET-WCF-MSMQ-Activation45'
    'NET-WCF-Pipe-Activation45'
    'NET-WCF-TCP-Activation45'
    'MSMQ'
    'MSMQ-Services'
    'MSMQ-Server'
)

# Registry locations NDES depends on, beyond its own MSCEP settings.
#
#   MSCEP            - the service configuration (nested: subkeys hold values)
#   ADCS\NDES        - ConfigurationStatus, written when setup completes
#   HTTP\Parameters  - large-URL limits; SCEP requests exceed the defaults
#
# HTTP\Parameters is captured by value name, not as a tree: the key also holds
# SslBindingInfo (with the OLD certificate's hash) and UrlAclInfo, which are
# machine-specific and must never be copied to another server.
$script:RegistryTargets = @(
    [pscustomobject]@{ Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MSCEP'; Mode = 'Tree' },
    [pscustomobject]@{ Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ADCS\NDES'; Mode = 'Tree' },
    [pscustomobject]@{ Key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'; Mode = 'Selected'; Values = @('MaxFieldLength', 'MaxRequestBytes') }
)

# The templates -Restore enrols the RA certificates from. These are never written
# to the MSCEP template values: the wizard puts the same name in all three there
# (NDESUser), and NDES refuses every request if they name the templates the
# certificates were enrolled from. Note the direction - CEP Encryption is the
# ENCRYPTION template and Exchange Enrollment Agent (Offline request) is the
# SIGNING template.
$script:DefaultEncryptionTemplate = 'CEPEncryption'
# Machine-capable enrollment agent template. Verified against this lab: templates
# whose 'flags' attribute carries 0x40 (machine type) accept NDES$ requests;
# EnrollmentAgent and EnrollmentAgentOffline do not, and refuse with
# CONTEXT_E_ROLENOTFOUND regardless of their ACL.
$script:DefaultSigningTemplate = 'MachineEnrollmentAgent'
$script:DefaultServerTemplate = 'NDESServer'

# --------------------------------------------------------------------- output ---

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host "== $Message" -ForegroundColor Cyan
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value ("`n== {0}" -f $Message) }
}

function Write-Info {
    param([Parameter(Mandatory)][string]$Message, [ValidateSet('Ok', 'Warn', 'Info')][string]$Level = 'Info')
    $prefix = switch ($Level) { 'Ok' { '  [ok]  ' } 'Warn' { '  [warn]' } default { '  ' } }
    $colour = switch ($Level) { 'Ok' { 'Green' } 'Warn' { 'Yellow' } default { 'Gray' } }
    Write-Host ($prefix + ' ' + $Message) -ForegroundColor $colour
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value ($prefix + ' ' + $Message) }
}

function Initialize-Log {
    param([Parameter(Mandatory)][string]$Directory)
    if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }
    $script:LogFile = Join-Path $Directory ('ndesmigration-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Add-Content -LiteralPath $script:LogFile -Value ("NDESMigration on {0} at {1:o}" -f $env:COMPUTERNAME, (Get-Date))
    Add-Content -LiteralPath $script:LogFile -Value ("Script: {0} ({1:o}) sha256 {2}" -f $script:ScriptPath, $script:ScriptBuilt, $script:ScriptHash)
}

function Write-ScriptIdentity {
    # Printed before the first change, so the log always names the copy that ran.
    $name = if ($script:ScriptPath) { Split-Path -Leaf $script:ScriptPath } else { 'NDESMigration.ps1' }
    $size = ''
    if ($script:ScriptPath -and (Test-Path -LiteralPath $script:ScriptPath)) {
        $bytes = (Get-Item -LiteralPath $script:ScriptPath).Length
        $size = ' ({0:N0} bytes)' -f $bytes
    }
    Write-Info ('Script      : {0}{1}' -f $name, $size) 'Info'
    Write-Info ('Last write  : {0}' -f $script:ScriptBuilt) 'Info'
    if ($script:ScriptHash) { Write-Info ('SHA256      : {0}' -f $script:ScriptHash.Substring(0, 16)) 'Info' }
    Write-Info ('Bundle schema this script writes: {0}' -f $script:BundleSchemaVersion) 'Info'
}

# ------------------------------------------------------------------- helpers ---

function Test-Elevated {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Elevated {
    if (-not (Test-Elevated)) { throw 'Run this script from an elevated PowerShell session (Run as administrator).' }
}

function Assert-IisPresent {
    if (-not (Test-Path -LiteralPath $script:AppCmd)) {
        throw ("IIS is not installed (appcmd.exe not found at {0}). Install the web server first." -f $script:AppCmd)
    }
}

function Invoke-AppCmd {
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$IgnoreExitCode)

    $output = & $script:AppCmd @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0 -and -not $IgnoreExitCode) {
        throw ("appcmd {0} failed (exit {1}): {2}" -f ($Arguments -join ' '), $code, (($output | Out-String).Trim()))
    }
    return ($output | Out-String)
}

function Get-AppCmdXml {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $text = Invoke-AppCmd -Arguments ($Arguments + '/xml') -IgnoreExitCode
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $start = $text.IndexOf('<')
    if ($start -lt 0) { return $null }
    try { return [xml]$text.Substring($start) } catch { return $null }
}

function ConvertFrom-RegExportData {
    <#
        Converts a value as written by `reg export` into a typed representation.
        Handles String, ExpandString, MultiString, DWord, QWord and Binary.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Data)

    $d = $Data
    if ($d -match '^"(.*)"$') {
        $text = $Matches[1] -replace '\\\\', '\' -replace '\\"', '"'
        return [pscustomobject]@{ Kind = 'String'; Value = $text }
    }
    if ($d -match '^dword:([0-9a-fA-F]{1,8})$') {
        return [pscustomobject]@{ Kind = 'DWord'; Value = [int64][Convert]::ToInt64($Matches[1], 16) }
    }
    if ($d -match '^hex\(b\):(.*)$') {
        $bytes = @($Matches[1] -split ',' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_.Trim(), 16) })
        return [pscustomobject]@{ Kind = 'QWord'; Value = [int64]([BitConverter]::ToInt64([byte[]]$bytes, 0)) }
    }
    if ($d -match '^hex\(([0-9a-fA-F]+)\):(.*)$') {
        $type = [int]$Matches[1]
        $bytes = @($Matches[2] -split ',' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_.Trim(), 16) })
        $byteArray = [byte[]]$bytes
        switch ($type) {
            1 { return [pscustomobject]@{ Kind = 'String'; Value = [Text.Encoding]::Unicode.GetString($byteArray).TrimEnd([char]0) } }
            2 { return [pscustomobject]@{ Kind = 'ExpandString'; Value = [Text.Encoding]::Unicode.GetString($byteArray).TrimEnd([char]0) } }
            7 {
                $text = [Text.Encoding]::Unicode.GetString($byteArray).TrimEnd([char]0)
                return [pscustomobject]@{ Kind = 'MultiString'; Value = @($text -split [char]0 | Where-Object { $_ }) }
            }
            3 { return [pscustomobject]@{ Kind = 'Binary'; Value = [Convert]::ToBase64String($byteArray) } }
            4 { return [pscustomobject]@{ Kind = 'DWord'; Value = [int64][BitConverter]::ToInt32($byteArray, 0) } }
            default { return [pscustomobject]@{ Kind = 'Binary'; Value = [Convert]::ToBase64String($byteArray) } }
        }
    }
    return [pscustomobject]@{ Kind = 'String'; Value = $d }
}

function Export-RegistryTree {
    <#
        Reads a registry key AND its subkeys into a serialisable list.

        NDES does not store its configuration as flat values under MSCEP. The
        real layout is nested, e.g.:
            MSCEP\SignatureTemplate            value SignatureTemplate
            MSCEP\CAInfo\Configuration         value Configuration
            MSCEP\CAType\CAType                value CAType
            MSCEP\CertsInMYStore\CertsInMYStore value CertsInMYStore
        so Path is recorded relative to the root and reproduced on restore.
    #>
    param([Parameter(Mandatory)][string]$KeyPath)

    if (-not (Test-Path -LiteralPath $KeyPath)) { return @() }

    $root = Get-Item -LiteralPath $KeyPath
    $rootName = $root.Name
    $entries = @()

    $keys = @($root) + @(Get-ChildItem -LiteralPath $KeyPath -Recurse -ErrorAction SilentlyContinue)
    foreach ($key in $keys) {
        $relative = ''
        if ($key.Name -ne $rootName) { $relative = $key.Name.Substring($rootName.Length).TrimStart('\') }

        foreach ($name in $key.GetValueNames()) {
            # MSCEP contains no credentials - the app pool password lives in
            # IIS, not here. Only guard against a literal credential value, so
            # that legitimate settings like UseSinglePassword, EnforcePassword
            # and PasswordVDir are preserved.
            if ($name -match '^(?i)(password|pwd|secret)$') { continue }
            $kind = [string]$key.GetValueKind($name)
            $raw = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)

            $value = switch ($kind) {
                'DWord' { [int64]$raw }
                'QWord' { [int64]$raw }
                'Binary' { [Convert]::ToBase64String([byte[]]$raw) }
                'MultiString' { @($raw) }
                default { [string]$raw }
            }
            $entries += [pscustomobject]@{ Path = $relative; Name = $name; Kind = $kind; Value = $value }
        }
    }
    return $entries
}

function Import-RegistryTree {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][AllowEmptyCollection()]$Values
    )

    if (-not (Test-Path -LiteralPath $KeyPath)) {
        if ($PSCmdlet.ShouldProcess($KeyPath, 'Create registry key')) {
            New-Item -Path $KeyPath -Force | Out-Null
        }
    }

    $written = 0
    foreach ($entry in @($Values)) {
        if ($null -eq $entry) { continue }
        $name = [string]$entry.Name
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $target = $KeyPath
        $relative = [string]$entry.Path
        if (-not [string]::IsNullOrWhiteSpace($relative)) {
            $target = Join-Path $KeyPath $relative
            if (-not (Test-Path -LiteralPath $target) -and $PSCmdlet.ShouldProcess($target, 'Create registry subkey')) {
                New-Item -Path $target -Force | Out-Null
            }
        }

        $kind = if ($entry.Kind) { [string]$entry.Kind } else { 'String' }
        $value = switch ($kind) {
            'DWord' { [int]$entry.Value }
            'QWord' { [int64]$entry.Value }
            'Binary' { [Convert]::FromBase64String([string]$entry.Value) }
            'MultiString' { [string[]]@($entry.Value) }
            default { [string]$entry.Value }
        }
        $propertyType = switch ($kind) {
            'DWord' { 'DWord' }
            'QWord' { 'QWord' }
            'Binary' { 'Binary' }
            'MultiString' { 'MultiString' }
            'ExpandString' { 'ExpandString' }
            default { 'String' }
        }

        if ($PSCmdlet.ShouldProcess(("{0}\{1}" -f $target, $name), "Set $kind value")) {
            New-ItemProperty -LiteralPath $target -Name $name -PropertyType $propertyType -Value $value -Force | Out-Null
            $written++
        }
    }
    return $written
}

function Get-OptionalProperty {
    <#
        Reads a property that may not exist. Under Set-StrictMode 2.0 a direct
        access on a missing property throws, and bundles written by an older
        version may legitimately lack newer fields.
    #>
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    # A live capture is an [ordered] dictionary; PSObject.Properties only
    # exposes the dictionary's own members, never its keys.
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Test-AppPool {
    param([Parameter(Mandatory)][string]$Name)
    $xml = Get-AppCmdXml -Arguments @('list', 'apppool', $Name)
    return ($null -ne $xml -and $null -ne $xml.SelectSingleNode('/appcmd/APPPOOL'))
}

function Test-IisApplication {
    param([Parameter(Mandatory)][string]$Path)

    $listing = Invoke-AppCmd -Arguments @('list', 'app') -IgnoreExitCode
    if (-not [string]::IsNullOrWhiteSpace($listing)) {
        foreach ($line in ($listing -split "`r?`n")) {
            if ($line -match ('APP\s+"[^"]*{0}"' -f [regex]::Escape($Path))) { return $true }
        }
    }

    # appcmd's listing can come back unparseable; the config file is
    # authoritative. Getting this wrong makes a re-run try to re-create an
    # application that already exists, which appcmd rejects outright.
    try {
        $appHost = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
        if (Test-Path -LiteralPath $appHost) {
            [xml]$hostConfig = Get-Content -LiteralPath $appHost -Raw
            $node = $hostConfig.SelectSingleNode(
                "/configuration/system.applicationHost/sites/site[@name='$($script:SiteName)']/application[@path='$Path']")
            return ($null -ne $node)
        }
    }
    catch { }
    return $false
}

function ConvertTo-PSPath {
    param([Parameter(Mandatory)][string]$Key)
    if ($Key -match '^HKLM:') { return $Key }
    if ($Key -match '^HKCU:') { return $Key }
    if ($Key -match '^HKEY_LOCAL_MACHINE\\(.*)$') { return ('HKLM:\' + $Matches[1]) }
    if ($Key -match '^HKEY_CURRENT_USER\\(.*)$') { return ('HKCU:\' + $Matches[1]) }
    throw "Unsupported registry root in: $Key"
}

function Get-IisApplicationIisSettings {
    <#
        Effective system.webServer settings for one IIS application, read from
        applicationHost.config.

        Not from appcmd: "appcmd list config <location>" prints section names
        mangled to dashes
        (system.webServer-security-authentication-anonymousAuthentication), so an
        XPath such as //anonymousAuthentication never matches and a capture that
        relies on it silently records its own fallback instead of the server's
        value. Reading the file is exact, and it can be tested offline against a
        captured applicationHost.config.

        Resolution order is server -> site -> application, which is how IIS
        applies location paths: the most specific element that sets a value wins.
    #>
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$SiteName,
        [Parameter(Mandatory)][string]$AppPath
    )

    $result = [ordered]@{
        Path                = $AppPath
        Anonymous           = $null
        Windows             = $null
        AccessPolicy        = $null
        AllowDoubleEscaping = $null
        MaxQueryString      = $null
        DefaultDocuments    = @()
        DirectoryBrowse     = $null
    }

    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $result }
    try { [xml]$doc = Get-Content -LiteralPath $ConfigPath -Raw }
    catch {
        Write-Info ("Could not parse {0}: {1}" -f $ConfigPath, $_.Exception.Message) 'Warn'
        return $result
    }

    $target = ('{0}{1}' -f $SiteName, $AppPath).TrimEnd('/')

    # Paths that apply here, least specific first: '', site, site/app, ...
    $levels = @('')
    $parts = @($target -split '/')
    for ($i = 1; $i -le $parts.Count; $i++) { $levels += (($parts[0..($i - 1)]) -join '/') }

    $nodes = @()
    $rootWeb = $doc.SelectSingleNode('/configuration/system.webServer')
    if ($rootWeb) { $nodes += $rootWeb }

    $byPath = @{}
    foreach ($location in $doc.SelectNodes('/configuration/location')) {
        $path = [string](Get-XmlAttr -Node $location -Name 'path')
        $web = $location.SelectSingleNode('system.webServer')
        if ($web) { $byPath[([string]$path).TrimEnd('/')] = $web }
    }
    foreach ($level in $levels) {
        if ($byPath.ContainsKey($level)) { $nodes += $byPath[$level] }
    }

    $documents = New-Object System.Collections.Generic.List[string]
    foreach ($web in $nodes) {
        $anon = $web.SelectSingleNode('security/authentication/anonymousAuthentication')
        if ($anon) {
            $value = Get-XmlAttr -Node $anon -Name 'enabled'
            if ($value) { $result.Anonymous = ($value -eq 'true') }
        }

        $win = $web.SelectSingleNode('security/authentication/windowsAuthentication')
        if ($win) {
            $value = Get-XmlAttr -Node $win -Name 'enabled'
            if ($value) { $result.Windows = ($value -eq 'true') }
        }

        $handlers = $web.SelectSingleNode('handlers')
        if ($handlers) {
            $value = Get-XmlAttr -Node $handlers -Name 'accessPolicy'
            if ($value) { $result.AccessPolicy = $value }
        }

        $filtering = $web.SelectSingleNode('security/requestFiltering')
        if ($filtering) {
            $value = Get-XmlAttr -Node $filtering -Name 'allowDoubleEscaping'
            if ($value) { $result.AllowDoubleEscaping = ($value -eq 'true') }
            $limits = $filtering.SelectSingleNode('requestLimits')
            if ($limits) {
                $value = Get-XmlAttr -Node $limits -Name 'maxQueryString'
                if ($value) { $result.MaxQueryString = [int]$value }
            }
        }

        $browse = $web.SelectSingleNode('directoryBrowse')
        if ($browse) {
            $value = Get-XmlAttr -Node $browse -Name 'enabled'
            if ($value) { $result.DirectoryBrowse = ($value -eq 'true') }
        }

        $defaults = $web.SelectSingleNode('defaultDocument')
        if ($defaults) {
            $files = $defaults.SelectSingleNode('files')
            if ($files) {
                # A <clear /> in the location replaces the inherited list instead
                # of adding to it.
                if ($files.SelectSingleNode('clear')) { $documents.Clear() }
                foreach ($add in $files.SelectNodes('add')) {
                    $value = Get-XmlAttr -Node $add -Name 'value'
                    if ($value -and -not $documents.Contains($value)) { $documents.Add($value) }
                }
            }
        }
    }

    $result.DefaultDocuments = @($documents)
    return $result
}

function Export-RegistrySelectedValues {
    <#
        Reads only the named values directly under a key. Used for keys that
        hold machine-specific data alongside the settings we want.
    #>
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string[]]$Names
    )

    if (-not (Test-Path -LiteralPath $KeyPath)) { return @() }
    $key = Get-Item -LiteralPath $KeyPath
    $entries = @()

    foreach ($name in $Names) {
        $value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $value) { continue }
        $kind = [string]$key.GetValueKind($name)
        $stored = switch ($kind) {
            'DWord' { [int64]$value }
            'QWord' { [int64]$value }
            'Binary' { [Convert]::ToBase64String([byte[]]$value) }
            'MultiString' { @($value) }
            default { [string]$value }
        }
        $entries += [pscustomobject]@{ Path = ''; Name = $name; Kind = $kind; Value = $stored }
    }
    return $entries
}

function Get-RegistryTargetsFromLive {
    $captured = @()
    foreach ($target in $script:RegistryTargets) {
        $psPath = ConvertTo-PSPath -Key $target.Key
        if (-not (Test-Path -LiteralPath $psPath)) {
            Write-Info ("Not present, skipped: {0}" -f $target.Key) 'Warn'
            continue
        }
        # Assigned inside the branches, never as `= if (...) { @(...) }`:
        # that form unwraps a single-item result to a scalar, and .Count then
        # throws under Set-StrictMode. ADCS\NDES holds exactly one value.
        $values = @()
        if ($target.Mode -eq 'Selected') {
            $values = @(Export-RegistrySelectedValues -KeyPath $psPath -Names @($target.Values))
        }
        else {
            $values = @(Export-RegistryTree -KeyPath $psPath)
        }
        if ($values.Count -eq 0) {
            Write-Info ("{0}: no values to capture, skipped" -f $target.Key) 'Warn'
            continue
        }
        $captured += [pscustomobject]@{ Key = $target.Key; Mode = $target.Mode; Values = $values }
    }
    return $captured
}

function Import-RegistryTargets {
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Targets)

    foreach ($target in @($Targets)) {
        if ($null -eq $target) { continue }
        $keyName = [string]$target.Key
        if ([string]::IsNullOrWhiteSpace($keyName)) { continue }

        $values = @($target.Values)
        if ($values.Count -eq 0) {
            Write-Info ("No values captured for {0}; skipped" -f $keyName) 'Warn'
            continue
        }

        $psPath = ConvertTo-PSPath -Key $keyName
        $written = Import-RegistryTree -KeyPath $psPath -Values $values
        if ($WhatIfPreference) {
            Write-Info ("{0}: would write {1} value(s)" -f $keyName, $values.Count) 'Warn'
        }
        else {
            Write-Info ("{0}: {1} value(s)" -f $keyName, [int]$written) 'Ok'
        }
    }
}

function Get-XmlAttr {
    param($Node, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Node) { return $null }
    if ($Node.Attributes -and $Node.Attributes[$Name]) { return $Node.Attributes[$Name].Value }
    return $null
}

# ------------------------------------------------------------------- capture ---

function Get-NdesConfigFromLive {
    $config = [ordered]@{
        SchemaVersion = $script:BundleSchemaVersion
        SourceHost    = $env:COMPUTERNAME
        CapturedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        CapturedFrom  = 'live'
    }

    # --- registry (MSCEP, ADCS\NDES, HTTP\Parameters) -----------------------
    $config.Registry = @(Get-RegistryTargetsFromLive)
    # Kept for older bundles / convenience: the MSCEP tree on its own.
    $mscepTarget = @($config.Registry) | Where-Object { $_.Key -match '\\Cryptography\\MSCEP$' } | Select-Object -First 1
    $config.Mscep = @()
    if ($mscepTarget) { $config.Mscep = @($mscepTarget.Values) }

    # --- IIS ----------------------------------------------------------------
    Assert-IisPresent

    $pool = [ordered]@{ Name = $script:AppPoolName; ManagedRuntimeVersion = 'v4.0'; ManagedPipelineMode = 'Integrated'; IdentityType = 'SpecificUser'; UserName = '' }
    $poolXml = Get-AppCmdXml -Arguments @('list', 'apppool', $script:AppPoolName)
    if ($poolXml) {
        $node = $poolXml.SelectSingleNode('/appcmd/APPPOOL')
        if ($node) {
            $runtime = Get-XmlAttr -Node $node -Name 'RuntimeVersion'
            $mode = Get-XmlAttr -Node $node -Name 'PipelineMode'
            if ($runtime) { $pool.ManagedRuntimeVersion = $runtime }
            if ($mode) { $pool.ManagedPipelineMode = $mode }
        }
    }

    # The identity lives in applicationHost.config, not in the appcmd list output.
    $appHost = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
    if (Test-Path -LiteralPath $appHost) {
        try {
            [xml]$ah = Get-Content -LiteralPath $appHost -Raw
            $poolNode = $ah.SelectSingleNode("/configuration/system.applicationHost/applicationPools/add[@name='$($script:AppPoolName)']")
            if ($poolNode) {
                $rt = Get-XmlAttr -Node $poolNode -Name 'managedRuntimeVersion'
                $pm = Get-XmlAttr -Node $poolNode -Name 'managedPipelineMode'
                if ($rt) { $pool.ManagedRuntimeVersion = $rt }
                if ($pm) { $pool.ManagedPipelineMode = $pm }

                $processModel = $poolNode.SelectSingleNode('processModel')
                if ($processModel) {
                    $it = Get-XmlAttr -Node $processModel -Name 'identityType'
                    $un = Get-XmlAttr -Node $processModel -Name 'userName'
                    if ($it) { $pool.IdentityType = $it }
                    if ($un) { $pool.UserName = $un }
                }
            }
        }
        catch { Write-Info "Could not parse applicationHost.config: $($_.Exception.Message)" 'Warn' }
    }
    if (-not $pool.UserName) { Write-Info 'App pool identity not found; will prompt at restore.' 'Warn' }
    $config.AppPool = $pool

    # --- applications -------------------------------------------------------
    $apps = @()
    foreach ($appPath in $script:AppPaths) {
        $apps += [ordered]@{
            Path         = $appPath
            PhysicalPath = $script:MscepPhysicalPath
            AppPool      = $script:AppPoolName
        }
    }
    $config.Applications = $apps

    # --- site bindings ------------------------------------------------------
    $bindings = @()
    $siteXml = Get-AppCmdXml -Arguments @('list', 'site', $script:SiteName)
    if ($siteXml) {
        foreach ($b in $siteXml.SelectNodes('/appcmd/SITE/bindings/binding')) {
            $bindings += [ordered]@{
                Protocol    = [string](Get-XmlAttr -Node $b -Name 'protocol')
                Information = [string](Get-XmlAttr -Node $b -Name 'bindingInformation')
            }
        }
    }
    if ($bindings.Count -eq 0) {
        # appcmd's listing is per-site XML and can come back unparseable; the
        # config file is authoritative and already open in this function.
        try {
            [xml]$ahBind = Get-Content -LiteralPath $appHost -Raw
            foreach ($b in $ahBind.SelectNodes("/configuration/system.applicationHost/sites/site[@name='$($script:SiteName)']/bindings/binding")) {
                $bindings += [ordered]@{
                    Protocol    = [string](Get-XmlAttr -Node $b -Name 'protocol')
                    Information = [string](Get-XmlAttr -Node $b -Name 'bindingInformation')
                }
            }
        }
        catch { }
    }
    if ($bindings.Count -eq 0) { Write-Info 'No site bindings found; the restore adds the https binding itself.' 'Warn' }
    $config.Bindings = $bindings

    # --- per-application IIS settings (effective) ---------------------------
    # Read from applicationHost.config rather than appcmd: see
    # Get-IisApplicationIisSettings. These are the settings that decide whether
    # the SCEP ISAPI runs at all, so they belong in the bundle.
    $auth = @()
    foreach ($app in @($config.Applications)) {
        $effective = Get-IisApplicationIisSettings -ConfigPath $appHost -SiteName $script:SiteName -AppPath $app.Path
        foreach ($name in 'Anonymous', 'Windows', 'AccessPolicy', 'AllowDoubleEscaping', 'MaxQueryString', 'DirectoryBrowse') {
            $value = $effective[$name]
            if ($null -ne $value) { $app[$name] = $value }
        }
        if ($effective.DefaultDocuments.Count -gt 0) {
            $app['DefaultDocuments'] = @($effective.DefaultDocuments)
        }

        $auth += [ordered]@{
            Path      = $app.Path
            Anonymous = if ($null -ne $effective.Anonymous) { [bool]$effective.Anonymous }
                        elseif ($script:ApplicationIisDefaults.ContainsKey($app.Path)) { [bool]$script:ApplicationIisDefaults[$app.Path].Anonymous }
                        else { $false }
            Windows   = if ($null -ne $effective.Windows) { [bool]$effective.Windows } else { $true }
        }

        if ($effective.AccessPolicy -and $effective.AccessPolicy -notmatch '(?i)\bExecute\b') {
            Write-Info ("{0}: handlers accessPolicy is '{1}', which does not allow Execute - mscep.dll is being served as a file on this server. The restore writes 'Read, Execute'." -f $app.Path, $effective.AccessPolicy) 'Warn'
        }
    }
    $config.Authentication = $auth

    # --- roles and features -------------------------------------------------
    # NET- and WAS are captured as well as the IIS and AD CS families: the
    # gold-standard build has the HTTP activation features, and they are not
    # dependencies of anything else in the list, so a filter that stopped at
    # Web- would silently drop them from every bundle.
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $config.Features = @(Get-WindowsFeature |
            Where-Object { $_.InstallState -eq 'Installed' -and $_.Name -match '^(ADCS|AD-Certificate|Web-|WAS|NET-)' } |
            ForEach-Object { $_.Name })
    }
    else { $config.Features = @() }

    # --- certificates (no private keys, no export) --------------------------
    $config.Certificates = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match 'NDES|MSCEP' -or $_.FriendlyName -match 'NDES' } |
        ForEach-Object {
            [ordered]@{
                Subject       = $_.Subject
                Thumbprint    = $_.Thumbprint
                Issuer        = $_.Issuer
                NotAfter      = $_.NotAfter.ToUniversalTime().ToString('o')
                FriendlyName  = $_.FriendlyName
                HasPrivateKey = $_.HasPrivateKey
            }
        })

    # --- local group membership (needed, and not part of a capture) ---------
    $groups = @()
    foreach ($g in 'IIS_IUSRS', 'Administrators') {
        try {
            $members = @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { $_.Name })
            $groups += [ordered]@{ Name = $g; Members = $members }
        }
        catch { }
    }
    $config.LocalGroups = $groups

    # --- derived settings ---------------------------------------------------
    # The RA template names are the ones NDES itself will look for (CertsInMYStore
    # = 1 searches by template), so they are read from the captured MSCEP values
    # rather than assumed.
    $config.RAEncryptionTemplate = Get-MscepValue -Config $config -Name 'EncryptionTemplate'
    if (-not $config.RAEncryptionTemplate) { $config.RAEncryptionTemplate = $script:DefaultEncryptionTemplate }
    $config.RASigningTemplate = Get-MscepValue -Config $config -Name 'SignatureTemplate'
    if (-not $config.RASigningTemplate) { $config.RASigningTemplate = $script:DefaultSigningTemplate }
    $config.ServerCertificateTemplate = $script:DefaultServerTemplate

    $signing = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match 'MSCEP-RA' } | Select-Object -First 1
    if ($signing) {
        # Certificate template name is not exposed by the .NET API; record the
        # subject so the restore enrols an equivalent certificate.
        $config.RACertificateSubject = $signing.Subject
    }

    $server = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -match 'NDES' -and $_.Subject -notmatch 'MSCEP-RA' } | Select-Object -First 1
    if ($server) { $config.ServerCertificateSubject = $server.Subject }

    return $config
}

function Get-NdesConfigFromCapture {
    param([Parameter(Mandatory)][string]$CapturePath)

    if (-not (Test-Path -LiteralPath $CapturePath)) { throw "Capture path not found: $CapturePath" }

    # Accept either NdesCapture-NDES\NDES\T1-<label> or that folder directly.
    $t1 = Get-ChildItem -LiteralPath $CapturePath -Directory -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'T1-*' } | Sort-Object FullName | Select-Object -Last 1
    if (-not $t1) { throw "No T1-* folder found under $CapturePath" }
    Write-Info ("Using capture: {0}" -f $t1.FullName)

    $config = [ordered]@{
        SchemaVersion = $script:BundleSchemaVersion
        SourceHost    = 'unknown'
        CapturedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        CapturedFrom  = ('capture:' + $t1.FullName)
    }

    # --- registry: MSCEP, ADCS\NDES and HTTP\Parameters ---------------------
    $registryDir = Join-Path $t1.FullName 'registry'
    if (-not (Test-Path -LiteralPath $registryDir)) { throw "Registry values not found: $registryDir" }
    Write-Info 'Reading registry values from capture (streamed - the SOFTWARE export is >100 MB)'

    # Streamed, because Import-Csv on the whole SOFTWARE export needs gigabytes.
    # Key is the first CSV column, so a prefix test on the raw line is enough.
    $prefixes = @($script:RegistryTargets | ForEach-Object { '"' + $_.Key })
    $registryRows = New-Object System.Collections.Generic.List[object]
    foreach ($csv in (Get-ChildItem -LiteralPath $registryDir -Filter '*.values.csv' -ErrorAction SilentlyContinue)) {
        $reader = New-Object System.IO.StreamReader($csv.FullName)
        try {
            $header = $reader.ReadLine()
            if (-not $header) { continue }
            while ($null -ne ($line = $reader.ReadLine())) {
                $hit = $false
                foreach ($prefix in $prefixes) {
                    if ($line.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { $hit = $true; break }
                }
                if ($hit) { $registryRows.Add(($header + "`n" + $line | ConvertFrom-Csv)) }
            }
        }
        finally { $reader.Dispose() }
    }
    if ($registryRows.Count -eq 0) { throw "No NDES registry values found in $registryDir" }

    $capturedTargets = @()
    foreach ($target in $script:RegistryTargets) {
        $targetKey = $target.Key
        # StartsWith + explicit separator check, rather than a regex per row:
        # the SOFTWARE hive export is ~140 MB and this is scanned per target.
        $matching = @($registryRows | Where-Object {
                $k = $_.Key
                if ($k.Length -lt $targetKey.Length) { return $false }
                if (-not $k.StartsWith($targetKey, [StringComparison]::OrdinalIgnoreCase)) { return $false }
                return ($k.Length -eq $targetKey.Length -or $k[$targetKey.Length] -eq '\')
            })
        if ($matching.Count -eq 0) {
            Write-Info ("Not present in capture, skipped: {0}" -f $target.Key) 'Warn'
            continue
        }

        $entries = @()
        foreach ($row in $matching) {
            $relative = ''
            if ($row.Key.Length -gt $targetKey.Length) { $relative = $row.Key.Substring($targetKey.Length).TrimStart('\') }

            if ($target.Mode -eq 'Selected') {
                if ($relative) { continue }                                # ignore subkeys
                if (@($target.Values) -notcontains $row.Name) { continue }  # only named values
            }

            $converted = ConvertFrom-RegExportData -Data $row.Data
            $entries += [pscustomobject]@{ Path = $relative; Name = $row.Name; Kind = $converted.Kind; Value = $converted.Value }
        }

        if ($entries.Count -eq 0) {
            Write-Info ("{0}: no matching values in capture" -f $target.Key) 'Warn'
            continue
        }
        $capturedTargets += [pscustomobject]@{ Key = $target.Key; Mode = $target.Mode; Values = $entries }
    }

    if ($capturedTargets.Count -eq 0) { throw "No NDES registry values found in $registryDir" }
    $config.Registry = $capturedTargets

    $mscepTarget = @($capturedTargets) | Where-Object { $_.Key -match '\\Cryptography\\MSCEP$' } | Select-Object -First 1
    $config.Mscep = @()
    if ($mscepTarget) { $config.Mscep = @($mscepTarget.Values) }
    if (@($config.Mscep).Count -eq 0) { throw 'The capture contains no MSCEP values; it may not be an NDES capture.' }

    # --- IIS from the appcmd dumps -----------------------------------------
    $pool = [ordered]@{ Name = $script:AppPoolName; ManagedRuntimeVersion = 'v4.0'; ManagedPipelineMode = 'Integrated'; IdentityType = 'SpecificUser'; UserName = '' }
    $poolsXml = Join-Path $t1.FullName 'iis\apppools.xml'
    if (Test-Path -LiteralPath $poolsXml) {
        try {
            [xml]$px = Get-Content -LiteralPath $poolsXml -Raw
            $node = $px.SelectNodes('/appcmd/APPPOOL') |
                Where-Object { (Get-XmlAttr -Node $_ -Name 'APPPOOL.NAME') -eq $script:AppPoolName } |
                Select-Object -First 1
            if ($node) {
                $mode = Get-XmlAttr -Node $node -Name 'PipelineMode'
                $runtime = Get-XmlAttr -Node $node -Name 'RuntimeVersion'
                if ($mode) { $pool.ManagedPipelineMode = $mode }
                if ($runtime) { $pool.ManagedRuntimeVersion = $runtime }
            }
        }
        catch { Write-Info "Could not parse apppools.xml: $($_.Exception.Message)" 'Warn' }
    }

    $appsXml = Join-Path $t1.FullName 'iis\apps.xml'
    $physical = $script:MscepPhysicalPath
    if (Test-Path -LiteralPath $appsXml) {
        try {
            [xml]$ax = Get-Content -LiteralPath $appsXml -Raw
            $app = $ax.SelectNodes('/appcmd/APP') |
                Where-Object { (Get-XmlAttr -Node $_ -Name 'APP.NAME') -match 'mscep$' } |
                Select-Object -First 1
            if ($app) {
                $path = Get-XmlAttr -Node $app -Name 'PHYSICAL_PATH'
                if ($path) { $physical = $path }
            }
        }
        catch { }
    }

    # Identity: read it out of the captured applicationHost.config if present.
    $appHost = Join-Path $t1.FullName 'iis\applicationHost.config'
    if (Test-Path -LiteralPath $appHost) {
        try {
            [xml]$ah = Get-Content -LiteralPath $appHost -Raw
            $poolNode = $ah.SelectSingleNode("/configuration/system.applicationHost/applicationPools/add[@name='$($script:AppPoolName)']")
            if ($poolNode) {
                $rt = Get-XmlAttr -Node $poolNode -Name 'managedRuntimeVersion'
                $pm = Get-XmlAttr -Node $poolNode -Name 'managedPipelineMode'
                if ($rt) { $pool.ManagedRuntimeVersion = $rt }
                if ($pm) { $pool.ManagedPipelineMode = $pm }

                $processModel = $poolNode.SelectSingleNode('processModel')
                if ($processModel) {
                    $it = Get-XmlAttr -Node $processModel -Name 'identityType'
                    $un = Get-XmlAttr -Node $processModel -Name 'userName'
                    if ($it) { $pool.IdentityType = $it }
                    if ($un) { $pool.UserName = $un }
                }
            }
        }
        catch { Write-Info "Could not parse captured applicationHost.config: $($_.Exception.Message)" 'Warn' }
    }
    $config.AppPool = $pool

    $config.Applications = @($script:AppPaths | ForEach-Object {
            [ordered]@{ Path = $_; PhysicalPath = $physical; AppPool = $script:AppPoolName }
        })

    # Per-application IIS settings from the captured applicationHost.config: the
    # same reader the live capture uses, so both paths record identical data.
    $capturedAuth = @()
    foreach ($app in @($config.Applications)) {
        $effective = Get-IisApplicationIisSettings -ConfigPath $appHost -SiteName $script:SiteName -AppPath $app.Path
        foreach ($name in 'Anonymous', 'Windows', 'AccessPolicy', 'AllowDoubleEscaping', 'MaxQueryString', 'DirectoryBrowse') {
            $value = $effective[$name]
            if ($null -ne $value) { $app[$name] = $value }
        }
        if ($effective.DefaultDocuments.Count -gt 0) {
            $app['DefaultDocuments'] = @($effective.DefaultDocuments)
        }
        $capturedAuth += [ordered]@{
            Path      = $app.Path
            Anonymous = if ($null -ne $effective.Anonymous) { [bool]$effective.Anonymous }
                        elseif ($script:ApplicationIisDefaults.ContainsKey($app.Path)) { [bool]$script:ApplicationIisDefaults[$app.Path].Anonymous }
                        else { $false }
            Windows   = if ($null -ne $effective.Windows) { [bool]$effective.Windows } else { $true }
        }
    }

    # Bindings
    $bindings = @()
    if (Test-Path -LiteralPath $appHost) {
        try {
            [xml]$ah2 = Get-Content -LiteralPath $appHost -Raw
            foreach ($b in $ah2.SelectNodes('/configuration/system.applicationHost/sites/site/bindings/binding')) {
                $bindings += [ordered]@{
                    Protocol    = [string](Get-XmlAttr -Node $b -Name 'protocol')
                    Information = [string](Get-XmlAttr -Node $b -Name 'bindingInformation')
                }
            }
        }
        catch { }
    }
    if ($bindings.Count -eq 0) {
        $bindings = @(
            [ordered]@{ Protocol = 'http'; Information = '*:80:' },
            [ordered]@{ Protocol = 'https'; Information = '*:443:' }
        )
    }
    $config.Bindings = $bindings

    $config.Authentication = $capturedAuth

    # Features
    $rolesFile = Join-Path $t1.FullName 'features\installed-roles.txt'
    $features = @()
    if (Test-Path -LiteralPath $rolesFile) {
        foreach ($line in Get-Content -LiteralPath $rolesFile) {
            if ($line -match 'Install-WindowsFeature -Name (.+)$') {
                $features = @($Matches[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }
        }
    }
    if ($features.Count -eq 0) {
        Write-Info 'No feature list in the capture; the restore will install the minimum set.' 'Warn'
        $features = @('ADCS-Device-Enrollment', 'Web-Server', 'Web-Windows-Auth', 'Web-ISAPI-Ext', 'Web-ISAPI-Filter', 'Web-Mgmt-Console')
    }
    $config.Features = $features

    # Certificates (metadata only)
    $certCsv = Join-Path $t1.FullName 'certs\certificates.csv'
    $certs = @()
    if (Test-Path -LiteralPath $certCsv) {
        foreach ($row in Import-Csv -LiteralPath $certCsv) {
            if ($row.Store -notmatch 'LocalMachine\\My') { continue }
            if ($row.Subject -notmatch 'NDES|MSCEP') { continue }
            $certs += [ordered]@{
                Subject       = $row.Subject
                Thumbprint    = $row.Thumbprint
                Issuer        = $row.Issuer
                NotAfter      = $row.NotAfter
                FriendlyName  = $row.FriendlyName
                HasPrivateKey = ($row.HasPrivateKey -eq 'True')
            }
        }
    }
    $config.Certificates = $certs

    $config.LocalGroups = @()

    # NDES finds its RA certificates by template name, so these must be the
    # captured MSCEP values - not assumed defaults.
    $config.RAEncryptionTemplate = Get-MscepValue -Config $config -Name 'EncryptionTemplate'
    if (-not $config.RAEncryptionTemplate) { $config.RAEncryptionTemplate = $script:DefaultEncryptionTemplate }
    $config.RASigningTemplate = Get-MscepValue -Config $config -Name 'SignatureTemplate'
    if (-not $config.RASigningTemplate) { $config.RASigningTemplate = $script:DefaultSigningTemplate }
    $config.ServerCertificateTemplate = $script:DefaultServerTemplate
    $ra = $certs | Where-Object { $_.Subject -match 'MSCEP-RA' } | Select-Object -First 1
    if ($ra) { $config.RACertificateSubject = $ra.Subject }

    $srv = $certs | Where-Object { $_.FriendlyName -match 'NDES' -and $_.Subject -notmatch 'MSCEP-RA' } | Select-Object -First 1
    if ($srv) { $config.ServerCertificateSubject = $srv.Subject }

    return $config
}

function Get-BundleRegistryTargets {
    <#
        Returns the bundle's registry targets, upgrading a schema-1 bundle
        (which only had a flat Mscep list) on the fly.
    #>
    param($Config)

    $registry = Get-OptionalProperty -Object $Config -Name 'Registry'
    if ($registry) { return @($registry) }

    $mscep = Get-OptionalProperty -Object $Config -Name 'Mscep'
    if ($mscep) {
        return @([pscustomobject]@{ Key = $script:MSCEPKeyNative; Mode = 'Tree'; Values = @($mscep) })
    }
    return @()
}

function Get-MscepValue {
    param($Config, [Parameter(Mandatory)][string]$Name)
    foreach ($target in (Get-BundleRegistryTargets -Config $Config)) {
        $entry = @($target.Values) | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if ($entry) { return $entry.Value }
    }
    return $null
}

function Set-MscepTargetValue {
    <#
        Sets one value on the MSCEP registry targets that will be written. Only for
        values the target environment decides rather than the source - the template
        names, which have to agree with each other.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Targets,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    foreach ($target in @($Targets)) {
        if ($target.Key -notmatch '\\Cryptography\\MSCEP$') { continue }
        $entry = @($target.Values) | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if ($entry) { $entry.Value = $Value }
        else { $target.Values += [pscustomobject]@{ Path = ''; Name = $Name; Kind = 'String'; Value = $Value } }
    }
}

# ------------------------------------------------------------------- backup ---

function Resolve-BackupPath {
    <#
        Works out where the bundle goes.

        -Path is the bundle FOLDER. When omitted, a timestamped folder under
        C:\NDESMigration is used so repeated backups never collide. Relative
        paths are resolved once, up front, so the log, the summary and the
        restore hint all name the same absolute place.
    #>
    param([string]$Requested)

    if ([string]::IsNullOrWhiteSpace($Requested)) {
        $Requested = Join-Path 'C:\NDESMigration' ('{0}-{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }

    if (-not [System.IO.Path]::IsPathRooted($Requested)) {
        $Requested = Join-Path (Get-Location).ProviderPath $Requested
    }
    $full = [System.IO.Path]::GetFullPath($Requested)

    # Keep the root separator: 'C:\Backups\' otherwise collapses to 'C:\Backups'
    # (fine) but 'C:\' would collapse to 'C:' and stop meaning the drive root.
    if ($full -match '^[A-Za-z]:$') { $full += '\' }
    if ($full.Length -gt 3) { $full = $full.TrimEnd('\', '/') }

    if (Test-Path -LiteralPath $full -PathType Leaf) {
        throw "Bundle destination is a file, not a folder: $full"
    }

    # Only an existing bundle is a conflict. An existing but empty folder (or one
    # holding something else) is a perfectly good destination.
    if ((Test-Path -LiteralPath (Join-Path $full 'ndes-config.json')) -and -not $Force) {
        throw "A bundle already exists in $full. Choose another -Path, or add -Force to overwrite it."
    }

    if (-not (Test-Path -LiteralPath $full)) {
        New-Item -ItemType Directory -Path $full -Force | Out-Null
    }
    return $full
}

function Get-TemplateMachineCapable {
    <#
        Whether a certificate template can be enrolled by a COMPUTER. The AD
        'flags' attribute carries 0x40 for machine-type templates; user-only
        templates refuse a LocalMachine\My request with CONTEXT_E_ROLENOTFOUND
        before their ACL is ever consulted.

        Returns $true/$false, or $null when it cannot be determined.
    #>
    param([Parameter(Mandatory)][string]$Template)

    try {
        $naming = Get-DirectoryNamingContexts
        $base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($naming.Configuration)"
        $result = Find-DirectoryObject -Base $base `
            -Filter ("(&(objectClass=pKICertificateTemplate)(cn={0}))" -f (ConvertTo-LdapFilterValue $Template)) `
            -Properties @('flags')
        $flags = Get-ResultFirstProperty -SearchResult $result -Name 'flags'
        if ($null -eq $flags) { return $null }
        return [bool](([int64]$flags) -band 0x40)
    }
    catch { return $null }
}

function Invoke-Backup {
    $Path = Resolve-BackupPath -Requested $Path

    Initialize-Log -Directory $Path
    Write-Step 'Capturing NDES configuration'

    if ($FromCapture) {
        Write-Info "Source: existing capture ($FromCapture)"
        $config = Get-NdesConfigFromCapture -CapturePath $FromCapture
    }
    else {
        Write-Info "Source: live server ($env:COMPUTERNAME)"
        $config = Get-NdesConfigFromLive
    }

    $bundleFile = Join-Path $Path 'ndes-config.json'
    $config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $bundleFile -Encoding UTF8

    $targetSummary = (@((Get-BundleRegistryTargets -Config $config) | ForEach-Object {
                '{0} ({1} value(s))' -f $_.Key, @($_.Values).Count
            })) -join '; '
    Write-Info ("Registry targets      : {0}" -f $targetSummary) 'Ok'
    Write-Info ("Applications          : {0}" -f ((@($config.Applications) | ForEach-Object { $_.Path }) -join ', ')) 'Ok'
    Write-Info ("Features to install   : {0}" -f @($config.Features).Count) 'Ok'
    Write-Info ("CA configuration      : {0}" -f (Get-MscepValue -Config $config -Name 'Configuration')) 'Ok'
    Write-Info ("CertsInMYStore        : {0}" -f (Get-MscepValue -Config $config -Name 'CertsInMYStore')) 'Ok'
    Write-Info ("MaxFieldLength        : {0}" -f (Get-MscepValue -Config $config -Name 'MaxFieldLength')) 'Ok'
    Write-Info ("MaxRequestBytes       : {0}" -f (Get-MscepValue -Config $config -Name 'MaxRequestBytes')) 'Ok'
    Write-Info ("ConfigurationStatus   : {0}" -f (Get-MscepValue -Config $config -Name 'ConfigurationStatus')) 'Ok'
    Write-Info ("RA templates          : encryption={0}, signing={1}" -f $config.RAEncryptionTemplate, $config.RASigningTemplate) 'Ok'
    Write-Info ("Service account       : {0}" -f $config.AppPool.UserName) 'Ok'
    Write-Info ("Bindings              : {0}" -f ((@($config.Bindings) | ForEach-Object { "$($_.Protocol) $($_.Information)" }) -join ', ')) 'Ok'
    Write-Info ("Bundle                : {0}" -f $bundleFile) 'Ok'

    if ((Get-MscepValue -Config $config -Name 'CertsInMYStore') -ne 1) {
        Write-Info 'CertsInMYStore is not 1: the source locates RA certificates by thumbprint, which does not migrate. Restore will still enrol fresh RA certificates.' 'Warn'
    }

    # Flag unusable templates now, not halfway through a restore. A restore
    # re-enrols into LocalMachine\My, which only machine-type templates permit.
    foreach ($pair in @(
            [pscustomobject]@{ Setting = 'EncryptionTemplate'; Template = $config.RAEncryptionTemplate },
            [pscustomobject]@{ Setting = 'SignatureTemplate'; Template = $config.RASigningTemplate }
        )) {
        if ([string]::IsNullOrWhiteSpace($pair.Template)) { continue }
        $capable = Get-TemplateMachineCapable -Template $pair.Template
        if ($capable -eq $false) {
            $message = "MSCEP {0} = '{1}' is NOT machine-capable, so a restore cannot re-enrol it into the machine store."
            Write-Info ($message -f $pair.Setting, $pair.Template) 'Warn'
            Write-Info 'Use a template whose AD flags carry 0x40 (CEPEncryption, MachineEnrollmentAgent) and pass it with -RAEncryptionTemplate / -RASigningTemplate at restore time.' 'Warn'
        }
        elseif ($capable -eq $true) {
            Write-Info ("MSCEP {0} = '{1}' is machine-capable" -f $pair.Setting, $pair.Template) 'Ok'
        }
    }
    if (-not $config.AppPool.UserName) {
        Write-Info 'No app pool identity recorded; the restore will prompt for the account name.' 'Warn'
    }

    Write-Step 'Backup complete'
    Write-Info ("Restore on the target with:  .\NDESMigration.ps1 -Restore -Path '{0}'" -f $Path)
}

# ----------------------------------------------------------------- preflight ---
#
# Everything here is READ-ONLY. It exists because -WhatIf can tell you what the
# restore would write, but says nothing about whether it would succeed: the CA
# refuses requests for reasons a dry run cannot discover. So the checks that can
# be answered without touching anything are answered up front, and the ones that
# genuinely cannot be are listed as "not checked" rather than quietly assumed.

function New-PreflightResult {
    param(
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Warn', 'Fail', 'NotChecked')][string]$Result,
        [AllowEmptyString()][string]$Detail = ''
    )
    [pscustomobject]@{ Phase = $Phase; Check = $Check; Result = $Result; Detail = $Detail }
}

function ConvertTo-LdapFilterValue {
    param([AllowEmptyString()][string]$Value)
    return ($Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29')
}

function Get-DirectoryNamingContexts {
    $rootDse = [ADSI]'LDAP://RootDSE'
    return [pscustomobject]@{
        Default       = [string]$rootDse.defaultNamingContext
        Configuration = [string]$rootDse.configurationNamingContext
    }
}

function Find-DirectoryObject {
    param(
        [Parameter(Mandatory)][string]$Base,
        [Parameter(Mandatory)][string]$Filter,
        [string[]]$Properties = @(),
        [ValidateSet('Base', 'OneLevel', 'Subtree')][string]$Scope = 'Subtree'
    )

    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Base")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = $Filter
    $searcher.SearchScope = $Scope
    $searcher.PageSize = 1
    foreach ($name in @($Properties + 'distinguishedName' | Select-Object -Unique)) {
        [void]$searcher.PropertiesToLoad.Add($name)
    }
    return $searcher.FindOne()
}

function Get-ResultFirstProperty {
    param($SearchResult, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $SearchResult) { return $null }
    $property = $SearchResult.Properties[$Name]
    if ($null -eq $property -or $property.Count -eq 0) { return $null }
    return $property[0]
}

function ConvertTo-SidValue {
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    return (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$Bytes, 0)).Value
}

function Get-DirectorySidSet {
    <#
        The object's own SID plus every group it belongs to, flattened by AD
        (tokenGroups). This is what an ACL evaluation needs, and it needs no
        directory rights beyond normal read.
    #>
    param([Parameter(Mandatory)][string]$DistinguishedName)

    $result = Find-DirectoryObject -Base $DistinguishedName -Filter '(objectClass=*)' `
        -Properties @('objectSid', 'tokenGroups') -Scope Base
    if ($null -eq $result) { throw "Object not found: $DistinguishedName" }

    $sids = New-Object System.Collections.Generic.List[string]
    $ownSid = ConvertTo-SidValue -Bytes (Get-ResultFirstProperty -SearchResult $result -Name 'objectSid')
    if ($ownSid) { $sids.Add($ownSid) }
    foreach ($bytes in @($result.Properties['tokenGroups'])) {
        $sid = ConvertTo-SidValue -Bytes $bytes
        if ($sid) { $sids.Add($sid) }
    }
    return $sids
}

function Get-ExtendedRightNames {
    <#
        Maps the extended-right GUIDs used in ACEs to their names. Read from AD
        rather than hardcoded, so the check does not depend on guessing GUIDs.
    #>
    param([Parameter(Mandatory)][string]$ConfigurationNamingContext)

    $map = @{}
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Extended-Rights,$ConfigurationNamingContext")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = '(objectClass=controlAccessRight)'
    $searcher.PageSize = 200
    foreach ($name in 'rightsGuid', 'displayName', 'cn') { [void]$searcher.PropertiesToLoad.Add($name) }
    foreach ($item in $searcher.FindAll()) {
        $guid = [string](Get-ResultFirstProperty -SearchResult $item -Name 'rightsGuid')
        if (-not $guid) { continue }
        $display = [string](Get-ResultFirstProperty -SearchResult $item -Name 'displayName')
        if (-not $display) { $display = [string](Get-ResultFirstProperty -SearchResult $item -Name 'cn') }
        $map[$guid.ToLower()] = $display
    }
    return $map
}

function Read-DirectoryAcl {
    param([Parameter(Mandatory)][string]$DistinguishedName)

    $result = Find-DirectoryObject -Base $DistinguishedName -Filter '(objectClass=*)' `
        -Properties @('nTSecurityDescriptor') -Scope Base
    if ($null -eq $result) { throw "Object not found: $DistinguishedName" }

    $bytes = Get-ResultFirstProperty -SearchResult $result -Name 'nTSecurityDescriptor'
    if ($null -eq $bytes) {
        # Without an explicit DACL request the attribute comes back empty.
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DistinguishedName")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter = '(objectClass=*)'
        $searcher.SearchScope = 'Base'
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        [void]$searcher.PropertiesToLoad.Add('nTSecurityDescriptor')
        $daclResult = $searcher.FindOne()
        if ($daclResult) { $bytes = Get-ResultFirstProperty -SearchResult $daclResult -Name 'nTSecurityDescriptor' }
    }
    if ($null -eq $bytes) { throw "No security descriptor readable on $DistinguishedName" }

    $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $security.SetSecurityDescriptorBinaryForm([byte[]]$bytes)
    return @($security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
}

function Test-AclGrantsEnrol {
    <#
        Advisory: does the DACL grant an "enrol"-style extended right to any of
        these SIDs? Deny ACEs win here, which matches AD's own evaluation.

        This is deliberately advisory. It cannot account for S4U, logon rights,
        CA policy module rules or template supersedence, so a Pass is never proof
        and a Warn is never a certainty.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Rules,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$SidSet,
        [Parameter(Mandatory)][hashtable]$ExtendedRights
    )

    $grants = @()
    $denies = @()
    foreach ($rule in @($Rules)) {
        $sid = [string]$rule.IdentityReference
        if ($SidSet -notcontains $sid -and $sid -ne 'S-1-1-0' -and $sid -ne 'S-1-5-11') { continue }

        $rights = [int]$rule.ActiveDirectoryRights
        $isEnrol = $false
        $name = ''

        # GenericAll (0x000F01FF) CONTAINS the ExtendedRight bit, so testing it
        # with -band would classify every extended right as full control. Test
        # for every full-control bit being present instead.
        $fullControl = 0x000F01FF
        if (($rights -band $fullControl) -eq $fullControl) {
            $isEnrol = $true
            $name = 'GenericAll'
        }
        elseif (($rights -band [int][System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0) {
            $objectType = [string]$rule.ObjectType
            if ($ExtendedRights.ContainsKey($objectType.ToLower())) { $name = $ExtendedRights[$objectType.ToLower()] }
            if ($name -match '(?i)enrol') { $isEnrol = $true }
        }

        if (-not $isEnrol) { continue }
        if ($rule.AccessControlType -eq 'Deny') { $denies += ("{0} denied {1}" -f $sid, $name) }
        else { $grants += ("{0} allowed {1}" -f $sid, $name) }
    }

    if ($denies.Count -gt 0) {
        return [pscustomobject]@{ Outcome = 'Warn'; Detail = ('explicit deny: ' + ($denies -join '; ')) }
    }
    if ($grants.Count -gt 0) {
        return [pscustomobject]@{ Outcome = 'Pass'; Detail = ('allow: ' + ($grants -join '; ')) }
    }
    return [pscustomobject]@{ Outcome = 'Warn'; Detail = 'no allowing ACE found for this identity' }
}

function Get-PreflightTemplateCheck {
    param(
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][string]$SidName,
        [Parameter(Mandatory)][string[]]$SidSet,
        [Parameter(Mandatory)][hashtable]$ExtendedRights,
        [Parameter(Mandatory)][string]$ConfigurationNamingContext
    )

    $base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigurationNamingContext"
    $result = Find-DirectoryObject -Base $base -Filter ("(&(objectClass=pKICertificateTemplate)(cn={0}))" -f (ConvertTo-LdapFilterValue $Template)) `
        -Properties @('cn') -Scope Subtree
    if ($null -eq $result) {
        return New-PreflightResult -Phase 'CA' -Check ("Template '{0}' exists in AD" -f $Template) -Result 'Fail' `
            -Detail 'not found under CN=Certificate Templates - it is not published to this forest'
    }

    $dn = [string]$result.Properties['distinguishedName'][0]
    $rules = Read-DirectoryAcl -DistinguishedName $dn
    $verdict = Test-AclGrantsEnrol -Rules $rules -SidSet $SidSet -ExtendedRights $ExtendedRights
    $detail = ('{0}; evaluated {1} ACE(s) against {2} ({3} sid(s))' -f $verdict.Detail, @($rules).Count, $SidName, @($SidSet).Count)
    return New-PreflightResult -Phase 'CA' -Check ("Template '{0}' enrol ACL (advisory)" -f $Template) -Result $verdict.Outcome -Detail $detail
}

function Invoke-Preflight {
    param(
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][string]$CAConfig,
        [Parameter(Mandatory)][string]$ServerTemplate,
        [Parameter(Mandatory)][string]$EncryptionTemplate,
        [Parameter(Mandatory)][string]$SigningTemplate,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$EnrollmentPolicyUrl,
        [switch]$UseGmsa
    )

    $results = New-Object System.Collections.Generic.List[object]
    $serviceAccountDn = $null
    $computerDn = $null
    $computerSam = $env:COMPUTERNAME + '$'
    $add = {
        param($phase, $check, $outcome, $detail)
        [void]$results.Add((New-PreflightResult -Phase $phase -Check $check -Result $outcome -Detail $detail))
    }

    # --- host ---------------------------------------------------------------
    if (Test-Elevated) { & $add 'Host' 'Running elevated' 'Pass' '' }
    else { & $add 'Host' 'Running elevated' 'Fail' 'start an elevated PowerShell session' }

    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    if ($os) { & $add 'Host' 'Operating system' 'Pass' ("{0} build {1}" -f $os.Caption, $os.BuildNumber) }
    else { & $add 'Host' 'Operating system' 'NotChecked' 'Win32_OperatingSystem not readable' }

    $computerSystem = $null
    try { $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }
    if ($computerSystem) {
        if ($computerSystem.PartOfDomain) { & $add 'Host' 'Domain-joined' 'Pass' ([string]$computerSystem.Domain) }
        else { & $add 'Host' 'Domain-joined' 'Fail' 'this server is in a workgroup; NDES needs a domain' }
    }
    else { & $add 'Host' 'Domain-joined' 'NotChecked' 'Win32_ComputerSystem not readable' }

    if (Get-Command Get-Certificate -ErrorAction SilentlyContinue) { & $add 'Host' 'Certificate enrolment module' 'Pass' 'Get-Certificate available' }
    else { & $add 'Host' 'Certificate enrolment module' 'Fail' 'Get-Certificate not available (PKI module)' }

    if (Test-Path -LiteralPath $script:AppCmd) { & $add 'Host' 'IIS present' 'Pass' 'appcmd.exe found' }
    else { & $add 'Host' 'IIS present' 'Warn' 'not installed yet; -Restore installs it' }

    # --- directory ----------------------------------------------------------
    $naming = $null
    try { $naming = Get-DirectoryNamingContexts } catch { & $add 'Directory' 'LDAP reachable' 'Fail' $_.Exception.Message }
    if ($naming) {
        & $add 'Directory' 'LDAP reachable' 'Pass' $naming.Default

        # the machine account is what actually requests the RA certificates
        try {
            $computer = Find-DirectoryObject -Base $naming.Default `
                -Filter ("(&(objectClass=computer)(sAMAccountName={0}))" -f (ConvertTo-LdapFilterValue $computerSam)) `
                -Properties @('distinguishedName', 'userAccountControl')
            if ($computer) {
                $computerDn = [string]$computer.Properties['distinguishedName'][0]
                $uac = [int](Get-ResultFirstProperty -SearchResult $computer -Name 'userAccountControl')
                if (($uac -band 0x2) -ne 0) { & $add 'Directory' 'Computer account enabled' 'Fail' ("{0} is disabled" -f $computerSam) }
                else { & $add 'Directory' 'Computer account enabled' 'Pass' ([string]$computer.Properties['distinguishedName'][0]) }
            }
            else { & $add 'Directory' 'Computer account enabled' 'Fail' ("{0} not found in the directory" -f $computerSam) }
        }
        catch { & $add 'Directory' 'Computer account enabled' 'NotChecked' $_.Exception.Message }

        $accountName = ($Account -split '\\')[-1]
        try {
            $serviceAccount = Find-DirectoryObject -Base $naming.Default `
                -Filter ("(&(|(objectClass=user)(objectClass=inetOrgPerson))(sAMAccountName={0}))" -f (ConvertTo-LdapFilterValue $accountName)) `
                -Properties @('distinguishedName', 'userAccountControl')
            if ($serviceAccount) {
                $serviceAccountDn = [string]$serviceAccount.Properties['distinguishedName'][0]
                $uac = [int](Get-ResultFirstProperty -SearchResult $serviceAccount -Name 'userAccountControl')
                if (($uac -band 0x2) -ne 0) { & $add 'Directory' 'Service account enabled' 'Fail' ("{0} is disabled" -f $Account) }
                else { & $add 'Directory' 'Service account enabled' 'Pass' $Account }
            }
            else { & $add 'Directory' 'Service account enabled' 'Warn' ("{0} not found - typo, or a different domain" -f $Account) }
        }
        catch { & $add 'Directory' 'Service account enabled' 'NotChecked' $_.Exception.Message }
    }

    # The password can be proven without changing anything - but a gMSA has none,
    # so what matters there is whether this host has installed the account.
    if ($UseGmsa) {
        & $add 'Directory' 'Service account is a gMSA' 'Pass' $Account
        $gmsaReady = Test-GmsaReady -Account $Account
        switch ($gmsaReady.State) {
            'Ready' { & $add 'Host' 'gMSA installed on this host' 'Pass' $gmsaReady.Detail }
            'Missing' { & $add 'Host' 'gMSA installed on this host' 'Fail' $gmsaReady.Detail }
            default { & $add 'Host' 'gMSA installed on this host' 'NotChecked' $gmsaReady.Detail }
        }
        & $add 'Directory' 'Service account password' 'NotChecked' 'a gMSA password is managed by the domain; there is nothing to type or store'
    }
    elseif ($Credential) {
        $check = Test-AccountCredential -UserName $Credential.UserName -Credential $Credential
        if ($check.Valid -eq $true) { & $add 'Directory' 'Service account password' 'Pass' 'validated against the domain' }
        elseif ($check.Valid -eq $false) { & $add 'Directory' 'Service account password' 'Fail' 'the domain rejected it - the app pool would not start with it' }
        else { & $add 'Directory' 'Service account password' 'NotChecked' $check.Reason }
    }
    else { & $add 'Directory' 'Service account password' 'NotChecked' 'no credential supplied' }

    try {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { $_.Name })
        $isAdmin = $admins -contains $Account
        if ($UseGmsa) {
            if ($isAdmin) { & $add 'Host' 'gMSA in local Administrators' 'Pass' 'present - this script does not need it (the restore runs as you); the accounts allowed to run it are the gMSA''s own concern' }
            else { & $add 'Host' 'gMSA in local Administrators' 'Pass' 'not a member' }
        }
        elseif ($isAdmin) { & $add 'Host' 'Service account is not a local admin' 'Warn' 'it is - not required by this design' }
        else { & $add 'Host' 'Service account is not a local admin' 'Pass' '' }
    }
    catch { & $add 'Host' 'Service account is not a local admin' 'NotChecked' $_.Exception.Message }

    # --- CA -----------------------------------------------------------------
    $caHost = ($CAConfig -split '\\')[0]
    try {
        $dns = @(Resolve-DnsName -Name $caHost -Type A -ErrorAction Stop | Where-Object { $_.IPAddress })
        if ($dns.Count -gt 0) { & $add 'CA' 'CA host resolves' 'Pass' ("{0} -> {1}" -f $caHost, (($dns | ForEach-Object { $_.IPAddress }) -join ', ')) }
        else { & $add 'CA' 'CA host resolves' 'Warn' ("no A record for {0}" -f $caHost) }
    }
    catch { & $add 'CA' 'CA host resolves' 'Fail' ("cannot resolve {0}: {1}" -f $caHost, $_.Exception.Message) }

    try {
        if (Test-NetConnection -ComputerName $caHost -Port 135 -InformationLevel Quiet -WarningAction SilentlyContinue) {
            & $add 'CA' 'CA RPC reachable (135)' 'Pass' $caHost
        }
        else { & $add 'CA' 'CA RPC reachable (135)' 'Fail' ("no TCP 135 to {0}" -f $caHost) }
    }
    catch { & $add 'CA' 'CA RPC reachable (135)' 'NotChecked' $_.Exception.Message }

    # certutil -ping proves the CA name is right without submitting anything.
    try {
        $null = (& certutil.exe -config $CAConfig -ping 2>&1 | Out-String)
        if ($LASTEXITCODE -eq 0) { & $add 'CA' 'CA responds to its config string' 'Pass' $CAConfig }
        else { & $add 'CA' 'CA responds to its config string' 'Fail' ("certutil -ping failed for {0}" -f $CAConfig) }
    }
    catch { & $add 'CA' 'CA responds to its config string' 'NotChecked' $_.Exception.Message }

    # The RA certificates are requested as the service account, which needs an
    # explicit policy (CEP) endpoint - so it has to be answering.
    if ($EnrollmentPolicyUrl) {
        try {
            $response = $null
            $status = $null
            try {
                $response = Invoke-WebRequest -Uri $EnrollmentPolicyUrl -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
                $status = [int]$response.StatusCode
            }
            catch {
                if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
                else { throw }
            }
            if ($status -in 200, 401, 403) {
                # 401/403 is the healthy answer: the endpoint exists and wants
                # authentication. 404 means the virtual directory is not there.
                & $add 'CA' 'Enrolment policy endpoint answers' 'Pass' ("{0} -> HTTP {1}" -f $EnrollmentPolicyUrl, $status)
            }
            elseif ($status) {
                & $add 'CA' 'Enrolment policy endpoint answers' 'Fail' ("{0} -> HTTP {1} (endpoint not present - is Web Enrollment installed on the CA?)" -f $EnrollmentPolicyUrl, $status)
            }
            else { & $add 'CA' 'Enrolment policy endpoint answers' 'NotChecked' $EnrollmentPolicyUrl }
        }
        catch {
            & $add 'CA' 'Enrolment policy endpoint answers' 'Fail' ("{0}: {1}. Override with -EnrollmentPolicyUrl." -f $EnrollmentPolicyUrl, $_.Exception.Message)
        }
    }
    else { & $add 'CA' 'Enrolment policy endpoint answers' 'NotChecked' 'no URL derived' }

    # Enrolling as the service account needs a CEP endpoint, which requires the
    # Certificate Enrollment Policy role service with HTTPS. Record which (if
    # any) policy endpoints exist, so the choice of approach is based on fact.
    try {
        $cepEndpoints = @(
            'ADPolicyProvider_CEP_UsernamePassword/service.svc',
            'ADPolicyProvider_CEP_Kerberos/service.svc'
        )
        $found = @()
        foreach ($path in $cepEndpoints) {
            $candidate = 'https://{0}/{1}' -f $caHost, $path
            try {
                $null = Invoke-WebRequest -Uri $candidate -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
                $found += [pscustomobject]@{ Url = $candidate; Status = 200 }
            }
            catch {
                $code = $null
                if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                if ($code) { $found += [pscustomobject]@{ Url = $candidate; Status = $code } }
            }
        }

        if (@($found).Count -gt 0) {
            & $add 'CA' 'CEP policy endpoints published' 'Pass' ((@($found) | ForEach-Object { '{0} (HTTP {1})' -f $_.Url, $_.Status }) -join '; ')
        }
        else {
            & $add 'CA' 'CEP policy endpoints published' 'Warn' ('none found - alternate-credential enrolment is unavailable; see README "RA templates"')
        }
    }
    catch { & $add 'CA' 'CEP policy endpoints published' 'NotChecked' $_.Exception.Message }

    # Templates must be published on the CA, not merely present in AD.
    try {
        $published = (& certutil.exe -config $CAConfig -CATemplates 2>&1 | Out-String)
        if ($LASTEXITCODE -eq 0) {
            foreach ($template in @($EncryptionTemplate, $SigningTemplate, $ServerTemplate) | Select-Object -Unique) {
                if ($published -match ('(?i)\b{0}\b' -f [regex]::Escape($template))) {
                    & $add 'CA' ("Template '{0}' published on CA" -f $template) 'Pass' ''
                }
                else { & $add 'CA' ("Template '{0}' published on CA" -f $template) 'Fail' 'certutil -CATemplates does not list it' }
            }
        }
        else { & $add 'CA' 'Published templates list' 'NotChecked' 'certutil -CATemplates failed' }
    }
    catch { & $add 'CA' 'Published templates list' 'NotChecked' $_.Exception.Message }

    # Advisory ACL evaluation. The identity that matters is the one the CA will see
    # on the request, which is decided by Install-NdesRaCertificates:
    #   machine context (the normal path) -> the COMPUTER account, NDES$
    #   CEP endpoint plus a credential    -> the service account
    # Checking only the service account hides the failure that actually happens -
    # a template that grants Enroll to the service account and not to the servers,
    # so the request is refused and the resulting mscep_admin page says
    # "You do not have sufficient permission to enroll with SCEP".
    if ($naming -and $computerSystem -and $computerSystem.PartOfDomain) {
        try {
            $extendedRights = Get-ExtendedRightNames -ConfigurationNamingContext $naming.Configuration

            $useCep = [bool]($EnrollmentPolicyUrl -and $Credential)
            if ($useCep) { $enrollingName = $Account; $enrollingDn = $serviceAccountDn }
            else { $enrollingName = ('{0} (computer account)' -f $computerSam); $enrollingDn = $computerDn }

            if ($enrollingDn) {
                & $add 'CA' 'Identity enrolling the RA certificates' 'Pass' $enrollingName
                $sidSet = @(Get-DirectorySidSet -DistinguishedName $enrollingDn)
                $deniedTemplates = @()
                foreach ($template in @($EncryptionTemplate, $SigningTemplate) | Select-Object -Unique) {
                    $check = Get-PreflightTemplateCheck -Template $template -SidName $enrollingName `
                        -SidSet $sidSet -ExtendedRights $extendedRights -ConfigurationNamingContext $naming.Configuration
                    $results.Add($check)
                    if ($check.Result -eq 'Warn') { $deniedTemplates += $template }
                }

                # A machine request against a user-only template falls back to
                # submitting the same request as the service account, so when the
                # computer account has no Enroll ACE it is worth knowing whether that
                # fallback can succeed instead of failing at the CA.
                if ($deniedTemplates.Count -gt 0 -and -not $useCep -and $serviceAccountDn) {
                    $serviceSids = @(Get-DirectorySidSet -DistinguishedName $serviceAccountDn)
                    foreach ($template in $deniedTemplates) {
                        $results.Add((Get-PreflightTemplateCheck -Template $template -SidName ('{0} (fallback identity)' -f $Account) `
                                    -SidSet $serviceSids -ExtendedRights $extendedRights -ConfigurationNamingContext $naming.Configuration))
                    }
                }
            }
            else {
                & $add 'CA' 'RA template enrol ACL (advisory)' 'NotChecked' ("{0} not found in the directory, so its ACEs cannot be evaluated" -f $enrollingName)
            }
        }
        catch { & $add 'CA' 'RA template enrol ACL (advisory)' 'NotChecked' $_.Exception.Message }
    }
    else { & $add 'CA' 'RA template enrol ACL (advisory)' 'NotChecked' 'no directory context' }

    # --- things a dry run genuinely cannot answer ---------------------------
    & $add 'Unverifiable' 'Whether the CA will issue the certificate' 'NotChecked' 'manager approval, policy module, template supersedence - only a real request proves it'
    & $add 'Unverifiable' 'Whether http.sys accepts the certificate binding' 'NotChecked' 'needs an actual netsh binding'
    & $add 'Unverifiable' 'Whether the NDES ISAPI serves requests' 'NotChecked' 'needs the configured service running'
    & $add 'Unverifiable' 'Whether the app pool identity can read the RA private keys' 'NotChecked' 'needs the enrolled keys to exist; the admin endpoint check after iisreset covers it'
    & $add 'Unverifiable' 'ACL evaluation completeness (advisory checks)' 'NotChecked' 'S4U and logon rights are not modelled'

    return $results
}

function Write-PreflightReport {
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Results)

    Write-Step 'Preflight checks (read-only)'
    $counts = @{ Pass = 0; Warn = 0; Fail = 0; NotChecked = 0 }
    $phase = ''
    foreach ($result in @($Results)) {
        if ($result.Phase -ne $phase) {
            $phase = $result.Phase
            Write-Host ("  -- {0}" -f $phase) -ForegroundColor DarkCyan
        }
        $level = switch ($result.Result) {
            'Pass' { 'Ok' }
            'Warn' { 'Warn' }
            'Fail' { 'Warn' }
            default { 'Info' }
        }
        $prefix = switch ($result.Result) {
            'Pass' { 'pass ' }
            'Warn' { 'warn ' }
            'Fail' { 'FAIL ' }
            default { 'n/a  ' }
        }
        $text = if ($result.Detail) { '{0}{1}: {2}' -f $prefix, $result.Check, $result.Detail } else { '{0}{1}' -f $prefix, $result.Check }
        Write-Info $text $level
        $counts[$result.Result]++
    }

    Write-Info ("{0} passed, {1} warning(s), {2} failed, {3} not checked" -f $counts['Pass'], $counts['Warn'], $counts['Fail'], $counts['NotChecked'])
    return $counts
}

# ------------------------------------------------------------------ restore ---

function Resolve-BundlePath {
    if ($Path) {
        $candidate = $Path
        # Tolerate being pointed straight at the file, since that is what people
        # copy between machines.
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            if ((Split-Path -Leaf $candidate) -eq 'ndes-config.json') { return (Split-Path -Parent $candidate) }
            throw "Not a bundle: $candidate (expected a folder, or an ndes-config.json file)"
        }
        if (Test-Path -LiteralPath (Join-Path $candidate 'ndes-config.json')) { return $candidate }
        throw "No ndes-config.json found in $candidate"
    }

    $root = 'C:\NDESMigration'
    if (-not (Test-Path -LiteralPath $root)) { throw "No -Path supplied and $root does not exist." }
    $latest = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'ndes-config.json') } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) { throw "No bundles found under $root. Use -Path to point at one." }
    return $latest.FullName
}

function Confirm-Value {
    <#
        Asks for confirmation of a value, offering the backed-up value as the
        default. Returns the confirmed string.

        -Verify must not stop for input, so it takes the default - and accepts an
        empty one, which the comparison treats as "not overridden".
    #>
    param(
        [Parameter(Mandatory)][string]$Label,
        [AllowEmptyString()][string]$Default
    )

    if ($Verify) { return ([string]$Default).Trim() }

    if ([string]::IsNullOrWhiteSpace($Default)) {
        $answer = Read-Host ("{0}" -f $Label)
        if ([string]::IsNullOrWhiteSpace($answer)) { throw ("{0} is required." -f $Label) }
        return $answer.Trim()
    }

    $answer = Read-Host ("{0} [{1}]" -f $Label, $Default)
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default.Trim() }
    return $answer.Trim()
}

function Get-AppPoolIdentity {
    <#
        Reads an application pool's identity straight from applicationHost.config,
        because appcmd can accept a set that IIS then ignores - notably an empty
        password for a gMSA, which is the value that matters most.
    #>
    param([Parameter(Mandatory)][string]$Name)

    $appHost = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
    if (-not (Test-Path -LiteralPath $appHost)) { return $null }
    try {
        [xml]$ah = Get-Content -LiteralPath $appHost -Raw
        $pool = $ah.SelectSingleNode("/configuration/system.applicationHost/applicationPools/add[@name='$Name']")
        if (-not $pool) { return $null }
        $processModel = $pool.SelectSingleNode('processModel')
        if (-not $processModel) {
            return [pscustomobject]@{ IdentityType = ''; UserName = ''; PasswordStored = $false }
        }
        return [pscustomobject]@{
            IdentityType   = [string](Get-XmlAttr -Node $processModel -Name 'identityType')
            UserName       = [string](Get-XmlAttr -Node $processModel -Name 'userName')
            PasswordStored = -not [string]::IsNullOrEmpty([string](Get-XmlAttr -Node $processModel -Name 'password'))
        }
    }
    catch { return $null }
}

function Confirm-YesNo {
    <#
        A yes/no prompt with a default, for questions whose answer is not a string.
        -Verify must not stop for input, so it returns the default.
    #>
    param(
        [Parameter(Mandatory)][string]$Label,
        [bool]$Default = $false
    )

    if ($Verify) { return $Default }

    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $answer = Read-Host ('{0} {1}' -f $Label, $suffix)
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    return ($answer -match '^(?i)\s*y')
}

function Get-DismFeatureList {
    <#
        Every feature DISM knows about, or the reason it could not say.

        The count matters: "no AD CS features" from a successful call means the
        payload is gone, while "no AD CS features" from a failed call (another
        servicing operation in progress, an inaccessible image) means something
        quite different. Reporting both without distinguishing them would be
        misleading, so the exit code and total are returned alongside the names.
    #>
    param([string]$Filter = '')

    $dism = Join-Path $env:SystemRoot 'System32\dism.exe'
    if (-not (Test-Path -LiteralPath $dism)) {
        return [pscustomobject]@{ ExitCode = -1; Count = 0; Names = @(); Message = 'dism.exe not found' }
    }

    $output = & $dism /online /get-features /format:table 2>&1 | Out-String
    $code = $LASTEXITCODE

    $rows = @($output -split "`r?`n" | Where-Object { $_ -match '\S' })
    $names = @($rows |
            Where-Object { $_ -notmatch '(?i)^\s*Feature Name' -and $_ -notmatch '^\s*-+' } |
            ForEach-Object { ($_ -split '\|')[0].Trim() } |
            Where-Object { $_ })

    if ($Filter) { $names = @($names | Where-Object { $_ -match $Filter }) }

    $message = ''
    if ($code -ne 0) {
        $message = (@($rows | Where-Object { $_ -match '(?i)error|not recognized|unknown' } | Select-Object -First 2) -join ' | ')
    }

    return [pscustomobject]@{ ExitCode = $code; Count = @($rows).Count; Names = $names; Message = $message }
}

function Test-PendingReboot {
    <#
        A servicing operation that has not been finalised hides its own result: a
        feature that was just uninstalled stays listed as absent, and a role
        service that is being removed disappears from the feature database until
        the machine restarts. On a build like that, no amount of installing will
        bring the feature back - the reboot has to happen first.
    #>
    $reasons = @()

    foreach ($probe in @(
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; Label = 'component servicing (CBS) reboot pending' },
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'; Label = 'Windows Update reboot required' },
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'; Label = 'packages pending' })) {
        if (Test-Path -LiteralPath $probe.Path) { $reasons += $probe.Label }
    }

    $sessionManager = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    try {
        $renames = @((Get-ItemProperty -LiteralPath $sessionManager -Name 'PendingFileRenameOperations' -ErrorAction Stop).PendingFileRenameOperations)
        if ($renames.Count -gt 0 -and $renames[0]) { $reasons += 'pending file rename operations' }
    }
    catch { }

    try {
        if ([bool](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations2' -ErrorAction SilentlyContinue)) {
            $reasons += 'pending file rename operations'
        }
    }
    catch { }

    return [pscustomobject]@{ Pending = ($reasons.Count -gt 0); Reasons = @($reasons | Sort-Object -Unique) }
}

function Get-DismFeatureState {
    <#
        The authoritative feature state, from DISM.

        Worth having because Install-WindowsFeature validates its -Name argument
        against the ServerManager module's *cached* feature list. That cache goes
        stale, and then a feature that DISM can install perfectly well is rejected
        with "The role, role service, or feature name is not valid ... The name was
        not found" - which reads like the feature does not exist.

        Known = $false means DISM itself would not answer: either it does not have
        the feature (payload gone from the image) or the call failed, and Message
        says which.
    #>
    param([Parameter(Mandatory)][string]$Name)

    $dism = Join-Path $env:SystemRoot 'System32\dism.exe'
    if (-not (Test-Path -LiteralPath $dism)) {
        return [pscustomobject]@{ Name = $Name; Known = $false; State = ''; Message = 'dism.exe not found' }
    }

    $output = & $dism /online /get-featureinfo "/featurename:$Name" 2>&1 | Out-String
    $code = $LASTEXITCODE
    $firstLines = @($output -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch '^Deployment Image Servicing' -and $_ -notmatch '^Version:' } | Select-Object -First 3)
    $message = ('exit {0}: {1}' -f $code, ($firstLines -join ' | '))

    if ($code -ne 0) {
        return [pscustomobject]@{ Name = $Name; Known = $false; State = ''; Message = $message }
    }

    $state = ''
    $match = [regex]::Match($output, '(?im)^\s*State\s*:\s*(\w+)')
    if ($match.Success) { $state = $match.Groups[1].Value }

    return [pscustomobject]@{ Name = $Name; Known = $true; State = $state; Message = $message }
}

function Install-FeatureByName {
    <#
        Installs one feature, trying both mechanisms before giving up:

          1. Install-WindowsFeature -Name <feature>
          2. dism /online /enable-feature /featurename:<feature> /all

        The second exists because the first validates the name against a cached
        list. DISM asks the component store directly, so a stale cache does not
        stop it.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Source
    )

    $alreadyInstalled = {
        param($featureName)
        $state = Get-DismFeatureState -Name $featureName
        if ($state.Known -and $state.State -eq 'Enabled') { return $true }
        $moduleState = $null
        try { $moduleState = Get-WindowsFeature -Name $featureName -ErrorAction Stop } catch { }
        return ($moduleState -and $moduleState.InstallState -eq 'Installed')
    }

    # 1. the ServerManager cmdlet
    try {
        $arguments = @{ Name = $Name; ErrorAction = 'Stop' }
        if ($Source) { $arguments['Source'] = $Source }
        $null = Install-WindowsFeature @arguments
        if (& $alreadyInstalled $Name) { return 'Install-WindowsFeature' }
    }
    catch {
        Write-Info ('Install-WindowsFeature refused {0}: {1}' -f $Name, $_.Exception.Message) 'Warn'
    }

    # 2. DISM, which does its own name resolution
    $dism = Join-Path $env:SystemRoot 'System32\dism.exe'
    if (Test-Path -LiteralPath $dism) {
        $dismArguments = @('/online', '/enable-feature', "/featurename:$Name", '/all', '/norestart')
        if ($Source) {
            $dismArguments += "/source:$Source"
            $dismArguments += '/limitaccess'
        }
        Write-Info ('Trying DISM: dism {0}' -f ($dismArguments -join ' '))
        $output = & $dism @dismArguments 2>&1 | Out-String
        $code = $LASTEXITCODE
        if (& $alreadyInstalled $Name) { return 'dism' }
        Write-Info ('DISM returned {0}: {1}' -f $code, (($output -split "`r?`n" | Where-Object { $_.Trim() }) -join ' | ')) 'Warn'
    }

    return ''
}

function Write-FeatureDiagnosis {
    <#
        When a feature cannot be installed, establish which of these is true rather
        than guessing:

          * DISM knows the feature and it is present but disabled  -> something else blocks it
          * DISM runs fine and the feature is simply not listed   -> payload gone from the image
          * DISM cannot enumerate at all                          -> servicing busy or damaged
          * a servicing operation is pending a restart            -> reboot first

        Each leads to a different repair, so the distinction is the whole point.
    #>
    param([Parameter(Mandatory)][string]$Name)

    $state = Get-DismFeatureState -Name $Name
    if ($state.Known) {
        Write-Info ('DISM reports {0} as {1}' -f $Name, $state.State) 'Warn'
        if ($state.State -eq 'Enabled') { return }
    }
    elseif ($state.Message -match '(?i)unknown|not recognized|0x800f080c') {
        Write-Info ('DISM does not answer for {0} (0x800f080c). For a role service that is normal - see below.' -f $Name) 'Warn'
    }
    else {
        Write-Info ('DISM could not report on {0}: {1}' -f $Name, $state.Message) 'Warn'
    }

    $pending = Test-PendingReboot
    if ($pending.Pending) {
        Write-Info ('A servicing operation is pending a restart ({0}). A feature that is being removed or added stays invisible to the feature database until the machine restarts.' -f ($pending.Reasons -join '; ')) 'Warn'
        return
    }

    $list = Get-DismFeatureList -Filter 'ADCS|AD-Certificate'
    if ($list.ExitCode -ne 0) {
        Write-Info ('DISM could not enumerate the image''s features either (exit {0}{1}). Another servicing operation may be in progress - check {2}.' -f `
                $list.ExitCode, $(if ($list.Message) { ': ' + $list.Message } else { '' }), (Join-Path $env:SystemRoot 'Logs\DISM\dism.log')) 'Warn'
    }
    elseif ($list.Names.Count -eq 0) {
        # Normal, and easy to misread: "dism /online /get-features" lists the
        # Foundation package only, so AD CS role services never appear - not even
        # on a server where NDES is installed and working. Absence here proves
        # nothing about the payload.
        Write-Info ('DISM listed {0} feature(s) and no AD CS ones. That is expected: dism /online /get-features covers the Foundation package, and AD CS role services live in their own packages, so DISM cannot be used to install or verify them.' -f $list.Count) 'Warn'
        Write-Info 'The feature list to trust here is Get-WindowsFeature, and it reads Server Manager''s component cache.' 'Warn'
    }
    else {
        Write-Info ('AD CS features DISM offers: {0}' -f ($list.Names -join ', ')) 'Warn'
    }
}

function Repair-FeatureImage {
    <#
        Last resort before giving up on a required feature: repair the component
        store, then try the install again.

        DISM /RestoreHealth is the documented repair for an image that no longer
        offers a feature, and it is slow (and needs Windows Update or a source), so
        it is opt-in. When it works the restore continues instead of stopping.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names,
        [string]$Source,
        [switch]$Auto
    )

    $dism = Join-Path $env:SystemRoot 'System32\dism.exe'
    if (-not (Test-Path -LiteralPath $dism)) { return @() }

    $go = [bool]$Auto
    if (-not $Auto) {
        Write-Info 'The feature payloads for these are not in this image. Repairing the component store is the documented fix, but it downloads from Windows Update and can take 10-20 minutes.' 'Warn'
        $answer = Read-Host ('  Run DISM /Online /Cleanup-Image /RestoreHealth now? [y/N] ')
        $go = ($answer -match '(?i)^\s*y')
    }
    if (-not $go) { return @() }

    $restore = @('/online', '/cleanup-image', '/restorehealth', '/norestart')
    if ($Source) {
        $restore += "/source:$Source"
        $restore += '/limitaccess'
    }

    Write-Info ('Running dism {0}' -f ($restore -join ' '))
    $output = & $dism @restore 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($code -eq 0 -or $code -eq 3010) {
        Write-Info 'Component store repaired' 'Ok'
    }
    else {
        Write-Info ('RestoreHealth returned {0}: {1}' -f $code, ((($output -split "`r?`n") | Where-Object { $_ -match '(?i)error' } | Select-Object -First 2) -join ' | ')) 'Warn'
        return @()
    }

    $recovered = @()
    foreach ($name in $Names) {
        Write-Info ('Retrying {0} after the repair' -f $name)
        $how = Install-FeatureByName -Name $name -Source $Source
        if ($how) {
            Write-Info ('{0} installed ({1})' -f $name, $how) 'Ok'
            $recovered += $name
        }
    }
    return $recovered
}

function Install-NdesFeatures {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Features)

    if (-not (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) {
        throw 'Install-WindowsFeature is not available. This script targets Windows Server.'
    }

    $requested = @($Features + $script:BaselineFeatures | Where-Object { $_ } | Sort-Object -Unique)

    # Drop parents and fresh-server defaults. Install-WindowsFeature installs a
    # feature *and its default children*, so requesting a parent installs a
    # subtree the reference build does not have - AD-Certificate brings the CA
    # role service, RSAT brings every RSAT tool, NET-WCF-Services45 brings MSMQ
    # and the pipe/TCP activations. The parents still get installed; they are
    # dependencies of the leaves below.
    $never = @($requested | Where-Object { $script:NeverRequestFeatures -contains $_ })
    if ($never.Count -gt 0) {
        Write-Info ('Not requesting: {0}' -f ($never -join ', ')) 'Warn'
        Write-Info 'These are parent features (installed anyway as dependencies of the leaves) and fresh-server defaults; requesting them also installs their default children, which the reference build does not have.' 'Warn'
        $requested = @($requested | Where-Object { $script:NeverRequestFeatures -notcontains $_ })
    }

    $all = $requested

    # Request only features this build actually has. A newer Server release drops
    # some of them (PowerShell-V2 for one), and asking for a feature that does not
    # exist fails the whole call.
    $available = @()
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $available = @(Get-WindowsFeature -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    }
    if ($available.Count -gt 0) {
        $absent = @($all | Where-Object { $available -notcontains $_ })
        if ($absent.Count -gt 0) {
            # A feature can be missing from the enumeration and still be installable
            # by name: Get-WindowsFeature serves a cached list that goes stale after
            # a role is removed, which is exactly the state a half-cleaned box is in.
            # Only the features NDES cannot work without are retried that way - for
            # the rest, "not on this build" is a legitimate answer.
            $recovered = @()
            $retry = @($absent | Where-Object { $script:RequiredFeatures -contains $_ })
            foreach ($name in $retry) {
                # "Not in the feature list" is not the same as "not installed": the
                # list comes from Server Manager's component cache, and a role
                # service whose cache entry is gone is invisible there while still
                # being installed and working. Check the machine, not the list.
                $presence = Get-FeaturePresence -Name $name
                if ($presence.CacheInstalled -or $presence.PayloadPresent) {
                    Write-Info ('{0} is installed but not listed by Get-WindowsFeature (cache entry: {1}, payload: {2}) - restoring the cache entry rather than reinstalling' -f `
                            $name, $(if ($presence.CacheInstalled) { 'present' } else { 'missing' }), $(if ($presence.PayloadPresent) { 'present' } else { 'missing' })) 'Warn'
                    Restore-NdesRoleServiceCacheEntry -RoleService $name
                    $recovered += $name
                    continue
                }

                Write-Info ('{0} is not installed and not in this server''s feature list; installing it by name' -f $name) 'Warn'
                $how = Install-FeatureByName -Name $name -Source $FeatureSource
                if ($how) {
                    Write-Info ('{0} installed ({1})' -f $name, $how) 'Ok'
                    $recovered += $name
                }
                else {
                    Write-Info ('{0} could not be installed' -f $name) 'Warn'
                }
            }

            # A role service is only installable once its role is there, so try the
            # parent before concluding anything.
            $stillAbsent = @($absent | Where-Object { $recovered -notcontains $_ })
            if ($stillAbsent.Count -gt 0 -and $stillAbsent -contains 'ADCS-Device-Enrollment') {
                if ($available -notcontains 'AD-Certificate') {
                    Write-Info 'AD-Certificate is not installed either; installing the role first so its role services become available' 'Warn'
                    $how = Install-FeatureByName -Name 'AD-Certificate' -Source $FeatureSource
                    if ($how) {
                        Write-Info ('AD-Certificate installed ({0}); retrying the NDES role service' -f $how) 'Ok'
                        $how = Install-FeatureByName -Name 'ADCS-Device-Enrollment' -Source $FeatureSource
                        if ($how) {
                            Write-Info ('ADCS-Device-Enrollment installed ({0})' -f $how) 'Ok'
                            $recovered += 'ADCS-Device-Enrollment'
                            $stillAbsent = @($stillAbsent | Where-Object { $_ -ne 'ADCS-Device-Enrollment' })
                        }
                    }
                }
            }

            # Features recovered through the cache/payload path are already
            # installed. Asking for them again would fail, because
            # Install-WindowsFeature validates names against the very list that
            # omitted them, so they are dropped from the batch.
            if ($recovered.Count -gt 0) {
                $all = @($all | Where-Object { $recovered -notcontains $_ })
                Write-Info ('Already installed, so not requested: {0}' -f ($recovered -join ', '))
            }

            if ($stillAbsent.Count -gt 0) {
                $fatal = @($stillAbsent | Where-Object { $script:RequiredFeatures -contains $_ })
                if ($fatal.Count -gt 0) {
                    Write-Info ('Required feature(s) could not be installed: {0}' -f ($fatal -join ', ')) 'Warn'
                    Write-Info 'The NDES role service is not installed, so the SCEP ISAPI cannot run.' 'Warn'
                    if (Test-Path -LiteralPath $script:MscepDll) {
                        # The exact trap: the files and the IIS applications survive an
                        # uninstall, so every check that looks at those alone passes
                        # while the role service itself is gone.
                        Write-Info ('{0} is still on disk from an earlier install, and the SCEP IIS applications are still configured, so this box looks ready and is not. Those are leftover files, not an installed role.' -f $script:MscepDll) 'Warn'
                    }
                    foreach ($name in $fatal) { Write-FeatureDiagnosis -Name $name }

                    # Repairing the image is the remaining option, so offer it before
                    # stopping: the operator asked for missing packages to be
                    # installed, not reported.
                    $repaired = @(Repair-FeatureImage -Names $fatal -Source $FeatureSource -Auto:$FixDrift)
                    if ($repaired.Count -gt 0) {
                        $recovered += $repaired
                        $fatal = @($fatal | Where-Object { $repaired -notcontains $_ })
                        $stillAbsent = @($stillAbsent | Where-Object { $repaired -notcontains $_ })
                    }

                    if ($fatal.Count -gt 0) {
                        Write-Info 'The image still does not offer these features. Either revert this server to a build that has them, or supply the payload:' 'Warn'
                        Write-Info ('  .\NDESMigration.ps1 -Restore -Path <bundle> -FeatureSource D:\sources\sxs' ) 'Warn'
                        throw ("Cannot continue without {0}." -f ($fatal -join ', '))
                    }
                    Write-Info 'The repair worked; continuing with the restore' 'Ok'
                }
                else {
                    Write-Info ('Not present on this build, skipped: {0}' -f ($stillAbsent -join ', ')) 'Warn'
                }
                $all = @($all | Where-Object { $stillAbsent -notcontains $_ })
            }
        }
    }

    Write-Step ('Installing roles and features ({0})' -f $all.Count)

    # No -IncludeManagementTools: it installs the management tools of *every*
    # feature in the batch, which is what added the RSAT tree and the IIS 6
    # console. The consoles the reference build has are in the list explicitly.
    $installArguments = @{ Name = $all; ErrorAction = 'Stop' }
    if ($FeatureSource) { $installArguments['Source'] = $FeatureSource }
    try {
        $result = Install-WindowsFeature @installArguments
    }
    catch {
        $withoutDotNet35 = @($all | Where-Object { $script:PayloadDependentFeatures -notcontains $_ })
        Write-Info ('Feature installation failed: {0}' -f $_.Exception.Message) 'Warn'
        Write-Info ('Retrying without the .NET 3.5 payload features ({0}); add them by hand with an alternate source (Sources\SxS) if they are required.' -f (($script:PayloadDependentFeatures | Where-Object { $all -contains $_ }) -join ', ')) 'Warn'
        $retryArguments = @{ Name = $withoutDotNet35; ErrorAction = 'Stop' }
        if ($FeatureSource) { $retryArguments['Source'] = $FeatureSource }
        $result = Install-WindowsFeature @retryArguments
    }

    # Under -WhatIf the cmdlet returns nothing, so $result can be null.
    if ($result -and $result.RestartNeeded -eq 'Yes') {
        Write-Info 'A restart is required before continuing. Reboot, then re-run -Restore.' 'Warn'
        throw 'Restart required: reboot the server and run -Restore again.'
    }

    # Report what actually landed, rather than assuming the call did everything:
    # the final parity check depends on this being true.
    $installed = @(Get-WindowsFeature -ErrorAction SilentlyContinue |
        Where-Object { $_.InstallState -eq 'Installed' } | ForEach-Object { $_.Name })

    # The enumeration can be stale, so a required feature is confirmed by name -
    # and by DISM, which does not depend on the ServerManager cache at all.
    foreach ($name in $script:RequiredFeatures) {
        if ($installed -contains $name) { continue }
        $state = $null
        try { $state = Get-WindowsFeature -Name $name -ErrorAction Stop } catch { }
        if ($state -and $state.InstallState -eq 'Installed') {
            $installed += $name
            if ($all -notcontains $name) { $all += $name }
            continue
        }
        $dismState = Get-DismFeatureState -Name $name
        if ($dismState -and $dismState.State -eq 'Enabled') {
            $installed += $name
            if ($all -notcontains $name) { $all += $name }
        }
    }

    $notInstalled = @($all | Where-Object { $installed -notcontains $_ })

    if ($notInstalled.Count -gt 0) {
        Write-Info ('Requested but not installed: {0}' -f ($notInstalled -join ', ')) 'Warn'
        if ($notInstalled | Where-Object { $script:PayloadDependentFeatures -contains $_ }) {
            Write-Info 'The .NET 3.5 features need the payload: connect to Windows Update, or use Specify an alternate source path (Sources\SxS) as the documentation describes.' 'Warn'
        }
        $missingRequired = @($notInstalled | Where-Object { $script:RequiredFeatures -contains $_ })
        if ($missingRequired.Count -gt 0) {
            throw ("Required feature(s) did not install: {0}. NDES cannot work without them." -f ($missingRequired -join ', '))
        }
    }
    else {
        Write-Info ('All {0} requested feature(s) installed' -f $all.Count) 'Ok'
    }

    Write-Info 'Roles and features installed' 'Ok'
}

function Set-NdesApplicationPool {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]$AppPool,
        [Parameter(Mandatory)][string]$Account,
        [securestring]$Password,
        [switch]$UseGmsa
    )

    Write-Step ('Configuring application pool {0}' -f $AppPool.Name)

    if (Test-AppPool -Name $AppPool.Name) {
        if ($Force) {
            if ($PSCmdlet.ShouldProcess($AppPool.Name, 'Remove existing application pool')) {
                Invoke-AppCmd -Arguments @('delete', 'apppool', $AppPool.Name) -IgnoreExitCode | Out-Null
            }
        }
        else {
            Write-Info 'Application pool already exists; updating settings (-Force to recreate)' 'Warn'
        }
    }

    if (-not (Test-AppPool -Name $AppPool.Name)) {
        if ($PSCmdlet.ShouldProcess($AppPool.Name, 'Create application pool')) {
            Invoke-AppCmd -Arguments @('add', 'apppool', ('/name:{0}' -f $AppPool.Name)) | Out-Null
        }
    }

    $runtime = if ($AppPool.ManagedRuntimeVersion) { $AppPool.ManagedRuntimeVersion } else { 'v4.0' }
    $mode = if ($AppPool.ManagedPipelineMode) { $AppPool.ManagedPipelineMode } else { 'Integrated' }

    if ($PSCmdlet.ShouldProcess($AppPool.Name, "Set runtime=$runtime mode=$mode")) {
        Invoke-AppCmd -Arguments @('set', 'apppool', ('/apppool.name:{0}' -f $AppPool.Name),
            ('/managedRuntimeVersion:{0}' -f $runtime), ('/managedPipelineMode:{0}' -f $mode)) | Out-Null
    }

    # This is the step IIS Manager cannot perform for this configuration, so it
    # is done explicitly here. The password is written by WAS and encrypted with
    # this machine's key; it never touches the bundle.
    #
    # appcmd only accepts the password in clear text on its command line, so it
    # has to leave the SecureString here - this is as far down as it can be kept
    # wrapped.
    #
    # A gMSA has no password to give: LSA logs the identity on from the secret
    # Install-ADServiceAccount created for this host, and the password attribute
    # has to stay empty for WAS to take that path. Writing any value there
    # instead makes the pool fail with "the identity is invalid".
    if ($UseGmsa) {
        if ($PSCmdlet.ShouldProcess($AppPool.Name, "Set identity to $Account (gMSA, no password)")) {
            Invoke-AppCmd -Arguments @('set', 'apppool', ('/apppool.name:{0}' -f $AppPool.Name),
                '/processModel.identityType:SpecificUser',
                ('/processModel.userName:{0}' -f $Account),
                '/processModel.password:',
                '/processModel.idleTimeout:00:00:00') | Out-Null
        }
        Write-Info ("Identity set to {0} (SpecificUser, gMSA - no password stored)" -f $Account) 'Ok'
    }
    else {
        $plainPassword = [System.Net.NetworkCredential]::new('', $Password).Password
        if ($PSCmdlet.ShouldProcess($AppPool.Name, "Set identity to $Account")) {
            Invoke-AppCmd -Arguments @('set', 'apppool', ('/apppool.name:{0}' -f $AppPool.Name),
                '/processModel.identityType:SpecificUser',
                ('/processModel.userName:{0}' -f $Account),
                ('/processModel.password:{0}' -f $plainPassword),
                '/processModel.idleTimeout:00:00:00') | Out-Null
        }
        $plainPassword = $null
        Write-Info ("Identity set to {0} (SpecificUser)" -f $Account) 'Ok'
    }

    # appcmd reports success for a set it did not apply, and for a gMSA the
    # difference is invisible until the pool is started and 503s, so read it back.
    if (-not $WhatIfPreference) {
        $applied = Get-AppPoolIdentity -Name $AppPool.Name
        if ($applied -and $UseGmsa) {
            if ($applied.IdentityType -ne 'SpecificUser' -or $applied.UserName -ne $Account -or $applied.PasswordStored) {
                throw ("The app pool did not take the gMSA identity as written (identityType='{0}', userName='{1}', password stored={2}). " +
                    "Set it by hand: IIS Manager > Application Pools > {3} > Advanced Settings > Identity > Custom account, value {4} with no password.") -f `
                    $applied.IdentityType, $applied.UserName, $applied.PasswordStored, $AppPool.Name, $Account
            }
        }
        elseif ($applied -and $applied.UserName -and $applied.UserName -ne $Account) {
            Write-Info ("The app pool now records {0}, not {1}" -f $applied.UserName, $Account) 'Warn'
        }
    }
}

function Set-NdesApplications {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$Applications)

    Write-Step 'Creating SCEP applications'
    foreach ($app in @($Applications)) {
        $sitePath = ('{0}{1}' -f $script:SiteName, $app.Path)
        $physical = if ($app.PhysicalPath) { $app.PhysicalPath } else { $script:MscepPhysicalPath }
        $pool = if ($app.AppPool) { $app.AppPool } else { $script:AppPoolName }

        if (Test-IisApplication -Path $app.Path) {
            if (-not $Force) {
                Write-Info ("{0} already exists; leaving it in place (-Force to recreate)" -f $app.Path) 'Warn'
                continue
            }
            if ($PSCmdlet.ShouldProcess($app.Path, 'Remove existing application')) {
                Invoke-AppCmd -Arguments @('delete', 'app', $sitePath) -IgnoreExitCode | Out-Null
            }
        }

        if ($PSCmdlet.ShouldProcess($app.Path, 'Create application')) {
            $output = Invoke-AppCmd -Arguments @('add', 'app',
                ('/site.name:{0}' -f $script:SiteName),
                ('/path:{0}' -f $app.Path),
                ('/physicalPath:{0}' -f $physical),
                ('/applicationPool:{0}' -f $pool)) -IgnoreExitCode

            # A re-run must not die just because the application is already
            # there, but a genuine failure still has to surface.
            if ($output -match 'ERROR' -and -not (Test-IisApplication -Path $app.Path)) {
                throw ("appcmd add app failed for {0}: {1}" -f $app.Path, $output.Trim())
            }
        }
        Write-Info ("{0} -> {1} (pool {2})" -f $app.Path, $physical, $pool) 'Ok'
    }
}

function Set-NdesApplicationSettings {
    <#
        Writes the per-application IIS settings NDES needs.

        The one that matters most is handlers accessPolicy: ISAPI-dll requires
        Execute, IIS skips handlers whose access type the current section does not
        allow, and the inherited value is "Read, Script". Without the override the
        SCEP ISAPI never runs and StaticFile serves mscep.dll as a download - the
        handler *order* is irrelevant while the permission is missing.

        Values come from the bundle; the NDES defaults in
        $script:ApplicationIisDefaults fill in bundles that never recorded them.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [AllowEmptyCollection()]$Applications = @(),
        [AllowEmptyCollection()]$Authentication = @()
    )

    Write-Step 'Configuring SCEP application IIS settings'

    foreach ($appPath in $script:AppPaths) {
        $location = ('{0}{1}' -f $script:SiteName, $appPath)
        $app = @($Applications) | Where-Object { $_.Path -eq $appPath } | Select-Object -First 1
        $auth = @($Authentication) | Where-Object { $_.Path -eq $appPath } | Select-Object -First 1
        $defaults = $script:ApplicationIisDefaults[$appPath]

        $anonymous = Get-OptionalProperty -Object $app -Name 'Anonymous'
        if ($null -eq $anonymous) { $anonymous = Get-OptionalProperty -Object $auth -Name 'Anonymous' }
        if ($null -eq $anonymous) { $anonymous = $defaults.Anonymous }

        $windows = Get-OptionalProperty -Object $app -Name 'Windows'
        if ($null -eq $windows) { $windows = Get-OptionalProperty -Object $auth -Name 'Windows' }
        if ($null -eq $windows) { $windows = $defaults.Windows }

        $accessPolicy = [string](Get-OptionalProperty -Object $app -Name 'AccessPolicy')
        if (-not $accessPolicy) { $accessPolicy = $defaults.AccessPolicy }
        if ($accessPolicy -notmatch '(?i)\bExecute\b') {
            Write-Info ("{0}: accessPolicy '{1}' does not allow Execute, so the SCEP ISAPI cannot run; using '{2}'" -f $appPath, $accessPolicy, $defaults.AccessPolicy) 'Warn'
            $accessPolicy = $defaults.AccessPolicy
        }

        $doubleEscaping = Get-OptionalProperty -Object $app -Name 'AllowDoubleEscaping'
        if ($null -eq $doubleEscaping) { $doubleEscaping = $defaults.AllowDoubleEscaping }

        $maxQueryString = Get-OptionalProperty -Object $app -Name 'MaxQueryString'
        if ($null -eq $maxQueryString) { $maxQueryString = $defaults.MaxQueryString }

        $defaultDocument = $defaults.DefaultDocument
        $documents = @(Get-OptionalProperty -Object $app -Name 'DefaultDocuments' | Where-Object { $_ })
        if ($documents.Count -gt 0) { $defaultDocument = $documents[0] }

        if (-not $PSCmdlet.ShouldProcess($location, 'Set SCEP application IIS settings')) { continue }

        $steps = @(
            @{ Section = 'system.webServer/security/authentication/anonymousAuthentication'; Argument = ('/enabled:{0}' -f ([bool]$anonymous)) },
            @{ Section = 'system.webServer/security/authentication/windowsAuthentication'; Argument = ('/enabled:{0}' -f ([bool]$windows)) },
            @{ Section = 'system.webServer/handlers'; Argument = ('/accessPolicy:{0}' -f $accessPolicy) },
            @{ Section = 'system.webServer/security/requestFiltering'; Argument = ('/allowDoubleEscaping:{0}' -f ([bool]$doubleEscaping)) },
            @{ Section = 'system.webServer/security/requestFiltering'; Argument = ('/requestLimits.maxQueryString:{0}' -f [int]$maxQueryString) }
        )

        # The default document is a collection, so adding one that is already
        # there is an error ("Cannot add duplicate collection entry"). Check the
        # effective list first: a re-run must be silent, not noisy.
        $effectiveDefaults = Get-IisApplicationIisSettings -ConfigPath (Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config') -SiteName $script:SiteName -AppPath $appPath
        if (-not ($effectiveDefaults.DefaultDocuments -contains $defaultDocument)) {
            $steps += @{ Section = 'system.webServer/defaultDocument'; Argument = ('/+files.[value=''{0}'']' -f $defaultDocument) }
            $steps += @{ Section = 'system.webServer/defaultDocument'; Argument = '/enabled:true' }
        }

        foreach ($step in $steps) {
            $output = Invoke-AppCmd -Arguments @('set', 'config', $location, ('-section:{0}' -f $step.Section), $step.Argument, '/commit:apphost') -IgnoreExitCode
            if ($output -match 'ERROR') { Write-Info ("{0} {1}: {2}" -f $appPath, $step.Argument, $output.Trim()) 'Warn' }
        }

        Write-Info ("{0}: anonymous={1} windows={2} accessPolicy={3} allowDoubleEscaping={4}" -f `
                $appPath, ([bool]$anonymous).ToString().ToLower(), ([bool]$windows).ToString().ToLower(), $accessPolicy, ([bool]$doubleEscaping).ToString().ToLower()) 'Ok'
    }

    # Read the effective values back: appcmd reports success for a section it did
    # not actually change, and these settings are the difference between a working
    # SCEP endpoint and a download.
    $appHost = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
    foreach ($appPath in $script:AppPaths) {
        $effective = Get-IisApplicationIisSettings -ConfigPath $appHost -SiteName $script:SiteName -AppPath $appPath
        $problems = @()
        if ($effective.AccessPolicy -notmatch '(?i)\bExecute\b') { $problems += ('accessPolicy={0}' -f $effective.AccessPolicy) }
        if ($null -eq $effective.AllowDoubleEscaping -or -not $effective.AllowDoubleEscaping) { $problems += 'allowDoubleEscaping is off' }
        if (-not ($effective.DefaultDocuments -contains 'mscep.dll')) { $problems += 'default document is not mscep.dll' }
        if ($problems.Count -gt 0) {
            Write-Info ("{0}: {1}" -f $appPath, ($problems -join '; ')) 'Warn'
        }
        else {
            Write-Info ("{0}: accessPolicy={1}, allowDoubleEscaping={2}, default document={3}" -f `
                    $appPath, $effective.AccessPolicy, $effective.AllowDoubleEscaping, ($effective.DefaultDocuments -join ', ')) 'Ok'
        }
    }
}

function Set-NdesIsapiRegistration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Step 'Registering the SCEP ISAPI extension'

    if (-not (Test-Path -LiteralPath $script:MscepDll)) {
        throw ("mscep.dll not found at {0}. The ADCS-Device-Enrollment feature did not install its payload." -f $script:MscepDll)
    }

    # The installer records the DLL as "Simple Certificate Enrollment Protocol
    # (SCEP) Add-On" and links it to the application that depends on it (groupId +
    # security/applicationDependencies). Without the group id the entry shows up
    # in IIS Manager as an unmanaged path, which is exactly the drift a rebuild is
    # supposed to avoid.
    $groupId = 'mscep.dll'
    $description = 'Simple Certificate Enrollment Protocol (SCEP) Add-On'

    $list = Invoke-AppCmd -Arguments @('list', 'config', '-section:system.webServer/security/isapiCgiRestriction') -IgnoreExitCode
    if ($list -notmatch [regex]::Escape($script:MscepDll)) {
        if ($PSCmdlet.ShouldProcess($script:MscepDll, 'Allow ISAPI/CGI extension')) {
            $output = Invoke-AppCmd -Arguments @('set', 'config', '-section:system.webServer/security/isapiCgiRestriction',
                ('/+[path=''{0}'',allowed=''true'',groupId=''{1}'',description=''{2}'']' -f $script:MscepDll, $groupId, $description)) -IgnoreExitCode
            if ($output -match 'ERROR') { Write-Info ("isapiCgiRestriction: {0}" -f $output.Trim()) 'Warn' }
        }
    }
    else {
        # Already allowed, but possibly without the group/description the SCEP
        # setup writes. Setting a single property of the existing item is safe;
        # removing and re-adding the collection entry is not.
        foreach ($property in @(
                @{ Name = 'groupId'; Value = $groupId },
                @{ Name = 'description'; Value = $description })) {
            if ($PSCmdlet.ShouldProcess($script:MscepDll, ('Set {0}' -f $property.Name))) {
                $output = Invoke-AppCmd -Arguments @('set', 'config', '-section:system.webServer/security/isapiCgiRestriction',
                    ('/[path=''{0}''].{1}:{2}' -f $script:MscepDll, $property.Name, $property.Value), '/commit:apphost') -IgnoreExitCode
                if ($output -match 'ERROR') { Write-Info ("isapiCgiRestriction {0}: {1}" -f $property.Name, $output.Trim()) 'Warn' }
            }
        }
    }
    Write-Info 'ISAPI extension allowed' 'Ok'

    $dependencies = Invoke-AppCmd -Arguments @('list', 'config', '-section:system.webServer/security/applicationDependencies') -IgnoreExitCode
    if ($dependencies -notmatch [regex]::Escape($groupId)) {
        if ($PSCmdlet.ShouldProcess($groupId, 'Declare the MSCEP application dependency')) {
            $output = Invoke-AppCmd -Arguments @('set', 'config', '-section:system.webServer/security/applicationDependencies',
                ('/+[groupId=''{0}'',name=''MSCEP'']' -f $groupId), '/commit:apphost') -IgnoreExitCode
            if ($output -match 'ERROR') { Write-Info ("applicationDependencies: {0}" -f $output.Trim()) 'Warn' }
            else { Write-Info 'Application dependency MSCEP recorded' 'Ok' }
        }
    }
}

function Get-IisHandlerOrderFix {
    <#
        Pure text transform: move the anchor handler so that it sits immediately
        above the first handler whose name matches $BeforePattern, but never above
        the handler that executes the SCEP ISAPI.

        IIS resolves a request with the first handler that matches it, which makes
        this order load-bearing in two directions:

          * above the ExtensionlessUrlHandler-* entries, so an extensionless
            request is not routed into ASP.NET first;
          * below ISAPI-dll. That handler has path *.dll, which is what makes
            /certsrv/mscep/ (default document mscep.dll) execute the ISAPI. Move
            StaticFile above it and IIS serves mscep.dll as a file - the browser
            saves it as "download" - and SCEP stops answering altogether.

        Returns the (possibly unchanged) lines plus whether anything moved, so the
        caller can apply it, report it, and leave the file alone when it is
        already correct.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines,
        [string]$Anchor = 'StaticFile',
        [string]$BeforePattern = '^ExtensionlessUrlHandler-',
        [string]$AfterPattern = '^ISAPI-dll$'
    )

    $result = [pscustomobject]@{ Lines = $Lines; Changed = $false; Message = '' }

    # Find the global handlers collection: several locations define their own,
    # and only the one that lists the anchor is the one to touch.
    $open = -1
    $close = -1
    for ($index = 0; $index -lt $Lines.Count; $index++) {
        if ($open -lt 0) {
            if ($Lines[$index] -match '<handlers[\s>]') { $open = $index }
            continue
        }
        if ($Lines[$index] -match '</handlers>') {
            $candidate = @($Lines[$open..$index])
            $hasAnchor = @($candidate | Where-Object { $_ -match ('name="{0}"' -f [regex]::Escape($Anchor)) }).Count -gt 0
            if ($hasAnchor) { $close = $index; break }
            $open = -1
        }
    }
    if ($open -lt 0 -or $close -lt 0) {
        $result.Message = 'global handlers collection not found'
        return $result
    }

    $block = @($Lines[$open..$close])
    $anchorIndex = -1
    $beforeIndex = -1
    $afterIndex = -1
    for ($offset = 0; $offset -lt $block.Count; $offset++) {
        if ($block[$offset] -notmatch 'name="([^"]+)"') { continue }
        $name = $Matches[1]
        if ($anchorIndex -lt 0 -and $name -eq $Anchor) { $anchorIndex = $offset }
        if ($beforeIndex -lt 0 -and $name -match $BeforePattern) { $beforeIndex = $offset }
        if ($name -match $AfterPattern) { $afterIndex = $offset }
    }

    if ($anchorIndex -lt 0) {
        $result.Message = ('{0} is not in the global handlers collection' -f $Anchor)
        return $result
    }
    if ($beforeIndex -lt 0) {
        $result.Message = ('no handler name matches {0}, so there is nothing to move {1} above' -f $BeforePattern, $Anchor)
        return $result
    }

    $anchorIsAfter = ($afterIndex -lt 0 -or $anchorIndex -gt $afterIndex)
    if ($anchorIndex -eq $beforeIndex - 1 -and $anchorIsAfter) {
        $result.Message = ('{0} already sits immediately above the matching handlers' -f $Anchor)
        return $result
    }

    $moved = New-Object System.Collections.Generic.List[string]
    foreach ($line in $block) { $moved.Add($line) }
    $anchorLine = $moved[$anchorIndex]
    $moved.RemoveAt($anchorIndex)

    # Indices shift once the anchor is out of the list.
    if ($afterIndex -gt $anchorIndex) { $afterIndex-- }
    $insertAt = if ($anchorIndex -lt $beforeIndex) { $beforeIndex - 1 } else { $beforeIndex }
    if ($afterIndex -ge 0 -and $insertAt -le $afterIndex) { $insertAt = $afterIndex + 1 }
    $moved.Insert($insertAt, $anchorLine)

    $rebuilt = New-Object System.Collections.Generic.List[string]
    if ($open -gt 0) { foreach ($line in $Lines[0..($open - 1)]) { $rebuilt.Add($line) } }
    foreach ($line in $moved) { $rebuilt.Add($line) }
    if ($close -lt ($Lines.Count - 1)) { foreach ($line in $Lines[($close + 1)..($Lines.Count - 1)]) { $rebuilt.Add($line) } }

    $result.Lines = $rebuilt.ToArray()
    $result.Changed = $true
    $result.Message = ('moved {0} immediately above the {1} handler(s)' -f $Anchor, ($BeforePattern -replace '[\^$]', ''))
    return $result
}

function Set-NdesHandlerOrder {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Anchor = 'StaticFile',
        [string]$BeforePattern = '^ExtensionlessUrlHandler-'
    )

    Write-Step 'Normalising IIS handler order'

    $configFile = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
    if (-not (Test-Path -LiteralPath $configFile)) {
        Write-Info ('{0} not found - handler order left alone' -f $configFile) 'Warn'
        return
    }

    $lines = [System.IO.File]::ReadAllLines($configFile)
    $fix = Get-IisHandlerOrderFix -Lines $lines -Anchor $Anchor -BeforePattern $BeforePattern

    if (-not $fix.Changed) {
        Write-Info $fix.Message 'Ok'
        return
    }

    if (-not $PSCmdlet.ShouldProcess($configFile, $fix.Message)) {
        Write-Info ('Would move {0} immediately above the ExtensionlessUrlHandler entries' -f $Anchor) 'Warn'
        return
    }

    $backupDirectory = if ($script:LogFile) { Split-Path -Parent $script:LogFile } else { $env:TEMP }
    $backup = Join-Path $backupDirectory ('applicationHost.config.{0}.bak' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Copy-Item -LiteralPath $configFile -Destination $backup -Force

    # Preserve the file's own encoding; a BOM-less rewrite is fine for IIS but
    # gratuitous when the original had one.
    $bytes = [System.IO.File]::ReadAllBytes($configFile)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $encoding = New-Object System.Text.UTF8Encoding($hasBom)

    try {
        [System.IO.File]::WriteAllLines($configFile, $fix.Lines, $encoding)
    }
    catch {
        Write-Info ('Could not rewrite applicationHost.config ({0}); handler order left alone' -f $_.Exception.Message) 'Warn'
        return
    }

    # IIS reloads the file when it changes. Prove the result is still well formed
    # and that IIS accepts the section before keeping it.
    try {
        $null = [xml](Get-Content -LiteralPath $configFile -Raw)
        $null = Invoke-AppCmd -Arguments @('list', 'config', '-section:system.webServer/handlers')
        Write-Info ('{0} (previous file: {1})' -f $fix.Message, $backup) 'Ok'
    }
    catch {
        Copy-Item -LiteralPath $backup -Destination $configFile -Force
        Write-Info ('Handler order change was rejected ({0}); applicationHost.config restored' -f $_.Exception.Message) 'Warn'
    }
}

function Get-NdesRoleServiceCachePath {
    param([string]$RoleService = 'ADCS-Device-Enrollment')
    return ('HKLM:\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\{0}' -f $RoleService)
}

function Restore-NdesRoleServiceCacheEntry {
    <#
        Recreates the Server Manager component-cache entry for the NDES role
        service.

        This entry is not decoration: Get-WindowsFeature enumerates role services
        from this cache, so an entry that is missing makes the feature invisible to
        Install-WindowsFeature ("the role, role service, or feature name is not
        valid") even though the role service is installed and working. DISM cannot
        help - on Server 2019 it only lists the Foundation package, so AD CS role
        services never appear there at all.

        Every value below is what the working reference server held, taken from the
        T0 side of the capture diff. Recreating them restores the enumeration; the
        values a bundle never recorded are the ones Server Manager itself wrote
        when the role service was installed.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$RoleService = 'ADCS-Device-Enrollment',
        [string]$ConfigurationKeyPath = 'Software\Microsoft\ADCS\NDES',
        [string]$ConfigurationValueName = 'ConfigurationStatus',
        [string]$CachePath,
        [switch]$Force
    )

    if (-not $CachePath) { $CachePath = Get-NdesRoleServiceCachePath -RoleService $RoleService }

    # Idempotent: an entry that is already there and marked installed must not be
    # rewritten. Rewriting would also reset the LastModified_UTC stamp that makes
    # Server Manager re-evaluate the post-deployment tile.
    if ((Test-Path -LiteralPath $CachePath) -and -not $Force) {
        $existing = (Get-ItemProperty -LiteralPath $CachePath -Name 'InstallState' -ErrorAction SilentlyContinue).InstallState
        if ($null -ne $existing -and [int]$existing -eq 1) { return }
    }

    if (-not $PSCmdlet.ShouldProcess($CachePath, 'Recreate the Server Manager component cache entry')) { return }

    if (-not (Test-Path -LiteralPath $CachePath)) { New-Item -Path $CachePath -Force | Out-Null }

    $dwordValues = [ordered]@{
        InstallState              = 1
        ServerComponentType       = 1
        NumericId                 = 204
        InstallWithParentByDefault = 0
        MajorVersion              = 0
        MinorVersion              = 0
    }
    foreach ($name in $dwordValues.Keys) {
        New-ItemProperty -LiteralPath $CachePath -Name $name -Value $dwordValues[$name] -PropertyType DWord -Force | Out-Null
    }

    $stringValues = [ordered]@{
        ParentName              = 'AD-Certificate'
        DisplayName             = 'Network Device Enrollment Service'
        Description             = 'Network Device Enrollment Service makes it possible to issue and manage certificates for routers and other network devices that do not have network accounts.'
        DescriptorClassName     = 'ServerComponent_ADCS_Device_Enrollment'
        ConfigurationKeyPath    = $ConfigurationKeyPath
        ConfigurationValueName  = $ConfigurationValueName
        EventQuery              = ''
        PostInstallDescription  = ''
        PostUninstallDescription = ''
    }
    foreach ($name in $stringValues.Keys) {
        New-ItemProperty -LiteralPath $CachePath -Name $name -Value $stringValues[$name] -PropertyType String -Force | Out-Null
    }

    # Empty multi-string values are what Server Manager writes for "none".
    foreach ($name in 'BestPracticeModels', 'MutualExclusions', 'OptionalCompanion') {
        New-ItemProperty -LiteralPath $CachePath -Name $name -Value @() -PropertyType MultiString -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $CachePath -Name 'Deploys' -Value @('NetworkDeviceEnrollmentServices') -PropertyType MultiString -Force | Out-Null
    New-ItemProperty -LiteralPath $CachePath -Name 'SystemServices' -Value @('w3svc', '1') -PropertyType MultiString -Force | Out-Null
    New-ItemProperty -LiteralPath $CachePath -Name 'NonAncestorDependencies' -PropertyType MultiString -Force -Value @(
        'Web-Static-Content', 'Web-Default-Doc', 'Web-Dir-Browsing', 'Web-Http-Errors', 'Web-Http-Redirect',
        'Web-Http-Logging', 'Web-Log-Libraries', 'Web-Request-Monitor', 'Web-Http-Tracing', 'Web-Stat-Compression',
        'Web-ISAPI-Ext', 'Web-Windows-Auth', 'Web-Metabase'
    ) | Out-Null

    Write-Info ('Recreated the Server Manager cache entry for {0}' -f $RoleService) 'Ok'
}

function Get-FeaturePresence {
    <#
        What the machine says about one feature, from three independent sources,
        because they disagree in exactly the cases that matter:

          Listed          Get-WindowsFeature enumerates it (Server Manager's cache)
          CacheInstalled  the component cache marks it InstallState = 1
          PayloadPresent  the role service's own files are on disk

        A role service whose cache entry was deleted is "not listed" but still
        installed and working. That state has to be recognised as installed, or a
        rebuild starts trying to install something that is already there - and
        fails, because the same cache is what validates the feature name.
    #>
    param([Parameter(Mandatory)][string]$Name)

    $listed = $false
    $installState = ''
    try {
        $feature = Get-WindowsFeature -Name $Name -ErrorAction Stop
        if ($feature) {
            $listed = $true
            $installState = [string]$feature.InstallState
        }
    }
    catch { }

    $cacheInstalled = $false
    $cachePath = Get-NdesRoleServiceCachePath -RoleService $Name
    if (Test-Path -LiteralPath $cachePath) {
        $state = (Get-ItemProperty -LiteralPath $cachePath -Name 'InstallState' -ErrorAction SilentlyContinue).InstallState
        if ($null -ne $state -and [int]$state -eq 1) { $cacheInstalled = $true }
    }

    $payload = ''
    if ($Name -eq 'ADCS-Device-Enrollment') { $payload = $script:MscepDll }
    $payloadPresent = ($payload -and (Test-Path -LiteralPath $payload))

    return [pscustomobject]@{
        Name           = $Name
        Listed         = $listed
        InstallState   = $installState
        CacheInstalled = $cacheInstalled
        PayloadPath    = $payload
        PayloadPresent = [bool]$payloadPresent
        Installed      = ($installState -eq 'Installed' -or $cacheInstalled -or $payloadPresent)
    }
}

function Set-NdesPostDeploymentState {
    <#
        Server Manager decides whether AD CS still needs post-deployment
        configuration by reading the role service's ConfigurationKeyPath from its
        component cache - for NDES that is Software\Microsoft\ADCS\NDES - and
        checking the state recorded there.

        A capture of a working server shows exactly one registry value behind that
        decision: ADCS\NDES\ConfigurationStatus = 2, which the restore writes. The
        cache entry itself is written when the feature is installed, i.e. before
        NDES is configured, so the tile can otherwise survive a completed
        configuration.

        The entry is *not* deleted to make the tile go away. Get-WindowsFeature
        enumerates role services from this cache, so deleting it removes
        ADCS-Device-Enrollment from the feature list - after which every later
        restore reports the NDES role service as missing and cannot reinstall it,
        because the same cache validates the name. Touching LastModified_UTC is
        enough to make Server Manager re-evaluate, and the entry is recreated if it
        is genuinely absent.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$RoleService = 'ADCS-Device-Enrollment')

    Write-Step 'Checking the AD CS post-deployment state'

    $cachePath = Get-NdesRoleServiceCachePath -RoleService $RoleService
    if (-not (Test-Path -LiteralPath $cachePath)) {
        Write-Info ('No Server Manager cache entry for {0}: the role service will not appear in Get-WindowsFeature, so recreating it' -f $RoleService) 'Warn'
        Restore-NdesRoleServiceCacheEntry -RoleService $RoleService
    }

    $keyPath = [string](Get-ItemProperty -LiteralPath $cachePath -Name 'ConfigurationKeyPath' -ErrorAction SilentlyContinue).ConfigurationKeyPath
    if (-not $keyPath) {
        Write-Info ('{0} has no ConfigurationKeyPath; Server Manager cannot tell whether it is configured' -f $RoleService) 'Warn'
        return
    }

    $configurationKey = 'HKLM:\{0}' -f ($keyPath -replace '^HKLM\\', '')
    $status = $null
    if (Test-Path -LiteralPath $configurationKey) {
        $status = (Get-ItemProperty -LiteralPath $configurationKey -Name 'ConfigurationStatus' -ErrorAction SilentlyContinue).ConfigurationStatus
    }

    if ($null -eq $status) {
        Write-Info ('{0} has no ConfigurationStatus - NDES is not marked as configured' -f $configurationKey) 'Warn'
    }
    elseif ([int]$status -ne 2) {
        Write-Info ('{0}\ConfigurationStatus = {1}, expected 2' -f $configurationKey, $status) 'Warn'
    }
    else {
        Write-Info ('{0}\ConfigurationStatus = 2' -f $configurationKey) 'Ok'
    }

    if ($PSCmdlet.ShouldProcess($RoleService, 'Refresh the Server Manager component cache entry')) {
        $stamp = Get-Date -Format 'yyyy/MM/dd/HH:mm:ss'
        New-ItemProperty -LiteralPath $cachePath -Name 'LastModified_UTC' -Value $stamp -PropertyType String -Force | Out-Null
        $cacheRoot = Split-Path -Parent $cachePath
        if (Test-Path -LiteralPath $cacheRoot) {
            New-ItemProperty -LiteralPath $cacheRoot -Name 'LastModified_UTC' -Value $stamp -PropertyType String -Force | Out-Null
        }
        Write-Info 'Server Manager cache entry refreshed (LastModified_UTC); the tile is re-evaluated when Server Manager next starts' 'Ok'
    }
}

function Test-AccountCredential {
    <#
        Validates a domain account's password without changing anything.
        Returns Valid = $true / $false, or $null when it cannot be determined
        (no domain context, DC unreachable), plus the reason.
    #>
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential
    )

    $UserName = if ($UserName) { $UserName } else { $Credential.UserName }
    $plainPassword = $Credential.GetNetworkCredential().Password

    $account = $UserName
    $domain = $null
    if ($UserName -match '^(.+?)\\(.+)$') {
        $domain = $Matches[1]
        $account = $Matches[2]
    }
    if (-not $domain) {
        try { $domain = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain } catch { }
    }
    if (-not $domain -or $domain -eq 'WORKGROUP') {
        return [pscustomobject]@{ Valid = $null; Reason = 'no domain context' }
    }

    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::Domain, $domain)
        try {
            $valid = $context.ValidateCredentials($account, $plainPassword)
            return [pscustomobject]@{ Valid = [bool]$valid; Reason = $null }
        }
        finally { $context.Dispose() }
    }
    catch {
        return [pscustomobject]@{ Valid = $null; Reason = $_.Exception.Message }
    }
}

function Get-TemplateOid {
    <#
        Resolves a certificate template name to its published OID.

        certreq -new rejects "CertificateTemplate = <name>" with ERROR_INVALID_DATA
        when it cannot resolve the name itself, so feeding it the OID removes that
        dependency entirely. Returns $null when the lookup is not possible.
    #>
    param([Parameter(Mandatory)][string]$Template)

    try {
        $naming = Get-DirectoryNamingContexts
        $base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($naming.Configuration)"
        $result = Find-DirectoryObject -Base $base `
            -Filter ("(&(objectClass=pKICertificateTemplate)(cn={0}))" -f (ConvertTo-LdapFilterValue $Template)) `
            -Properties @('msPKI-Cert-Template-OID')
        $oid = Get-ResultFirstProperty -SearchResult $result -Name 'msPKI-Cert-Template-OID'
        if ($oid -and ([string]$oid) -match '^\d+(\.\d+)+$') { return [string]$oid }
    }
    catch { }
    return $null
}

function Install-RaCertificateViaCertReq {
    <#
        Creates the key + CSR in the machine store, then submits the CSR to the CA.

        This exists because Get-Certificate ties the enrolment CONTEXT to the
        store location: -CertStoreLocation LocalMachine\My always means machine
        context, so a user-only template refuses the request before any credential
        is looked at. certreq has no such coupling - it can build a machine-store
        key and submit it as a different user, which is how an RA template that
        only issues to users can still put its certificate in the machine store.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$CAConfig,
        [System.Management.Automation.PSCredential]$Credential
    )

    $certreq = Join-Path $env:SystemRoot 'System32\certreq.exe'
    if (-not (Test-Path -LiteralPath $certreq)) { throw "certreq.exe not found at $certreq" }
    if (-not (Test-Elevated)) { throw 'Creating the RA key in the machine store requires an elevated session.' }

    $workRoot = Join-Path $env:ProgramData 'ndes-ra'
    if (-not (Test-Path -LiteralPath $workRoot)) { New-Item -ItemType Directory -Path $workRoot -Force | Out-Null }

    $safeName = ($Template -replace '[^\w\.-]', '_')
    $infPath = Join-Path $workRoot ('{0}.inf' -f $safeName)
    $reqPath = Join-Path $workRoot ('{0}.req' -f $safeName)
    $cerPath = Join-Path $workRoot ('{0}.cer' -f $safeName)

    # Exportable = FALSE: the key never leaves the machine, which is why no
    # private key has to be exported during a migration.
    #
    # Prefer the template OID: certreq cannot resolve a name it does not like and
    # reports only ERROR_INVALID_DATA, which is indistinguishable from a broken INF.
        $templateRef = $Template
        $refKind = 'name'
        Write-Info ("Template reference : {0} ({1})" -f $templateRef, $refKind)

    $inf = @"
[NewRequest]
Subject = "$Subject"
KeySpec = 1
KeyLength = 2048
Exportable = FALSE
MachineKeySet = TRUE
ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
ProviderType = 24
RequestType = PKCS10
CertificateTemplate = $templateRef
"@

    try {
        Set-Content -LiteralPath $infPath -Value $inf -Encoding ASCII

        if (-not $PSCmdlet.ShouldProcess($Template, 'Create key and CSR in the machine store')) { return $null }

        # 1. key + CSR, in the machine store. No CA contact, so the template's
        #    user/computer capability is not consulted here.
        # -q matters: without it certreq raises a modal dialog and blocks.
        $certreqOutput = (& $certreq -new -q $infPath $reqPath 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $reqPath)) {
            $why = ("certreq -new failed for template '{0}' (exit {1}) using {2} '{3}'.`n  {4}")
            throw ($why -f $Template, $LASTEXITCODE, $refKind, $templateRef, $certreqOutput)
        }

        # 2. submit the CSR and write the issued certificate to a file. Done as the
        #    service account when supplied, so the CA attributes the request to it.
        #    Writing a file (rather than installing) means that account needs no
        #    local administrator rights.
        if ($Credential) {
            $userName = $Credential.UserName
            try {
                $acl = Get-Acl -LiteralPath $workRoot
                if (-not (@($acl.Access | Where-Object { $_.IdentityReference -match [regex]::Escape(($userName -split '\\')[-1]) }).Count -gt 0)) {
                    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($userName, 'Modify', 'Allow')))
                    Set-Acl -LiteralPath $workRoot -AclObject $acl
                }
            }
            catch { Write-Info ("Could not grant {0} write access to {1}: {2}" -f $userName, $workRoot, $_.Exception.Message) 'Warn' }

            $submitArgs = @('-q', '-submit', '-config', $CAConfig, $reqPath, $cerPath)
            $process = Start-Process -FilePath $certreq -ArgumentList $submitArgs -Credential $Credential `
                -Wait -PassThru -WindowStyle Hidden
            $exit = $process.ExitCode
        }
        else {
            $null = & $certreq -q -submit -config $CAConfig $reqPath $cerPath 2>&1
            $exit = $LASTEXITCODE
        }
        if ($exit -ne 0 -or -not (Test-Path -LiteralPath $cerPath)) {
            throw ("certreq -submit failed for template '{0}' (exit {1}) as {2}." -f $Template, $exit,
                $(if ($Credential) { $Credential.UserName } else { 'the current user' }))
        }

        # 3. install it into the machine store, binding to the key made in step 1.
        $null = & $certreq -machine -q -accept $cerPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ("certreq -accept failed for template '{0}' (exit {1})." -f $Template, $LASTEXITCODE)
        }
    }
    finally {
        foreach ($file in $infPath, $reqPath, $cerPath) {
            if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
        }
    }

    $subjectMatch = if ($Subject -match 'CN=([^,]+)') { $Matches[1] } else { 'MSCEP-RA' }
    $issued = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match [regex]::Escape($subjectMatch) } |
        Sort-Object NotBefore -Descending)
    if ($issued.Count -eq 0) {
        throw ("The CA accepted the request for template '{0}' but no certificate appeared in LocalMachine\My." -f $Template)
    }
    return $issued[0]
}

function ConvertFrom-DerOid {
    <#
        Decodes a DER-encoded OBJECT IDENTIFIER, optionally wrapped in a SEQUENCE
        (which is how the Certificate Template extension is encoded). Handles
        long-form lengths, which appear once an OID gets long enough.
    #>
    param([Parameter(Mandatory)][byte[]]$Bytes, [int]$Offset = 0)

    if ($Bytes.Count -lt ($Offset + 2)) { return $null }

    # Step into the SEQUENCE content if we are sitting on one.
    if ($Bytes[$Offset] -eq 0x30) {
        $header = [int]$Bytes[$Offset + 1]
        $content = $Offset + 2
        if (($header -band 0x80) -ne 0) { $content += ($header -band 0x7F) }
        $Offset = $content
    }

    if ($Bytes.Count -lt ($Offset + 2) -or $Bytes[$Offset] -ne 0x06) { return $null }

    $length = [int]$Bytes[$Offset + 1]
    $start = $Offset + 2
    if (($length -band 0x80) -ne 0) {
        $lengthBytes = $length -band 0x7F
        if ($Bytes.Count -lt ($start + $lengthBytes)) { return $null }
        $length = 0
        for ($i = 0; $i -lt $lengthBytes; $i++) { $length = ($length * 256) + [int]$Bytes[$start + $i] }
        $start += $lengthBytes
    }
    if ($Bytes.Count -lt ($start + $length)) { return $null }

    $arcs = New-Object System.Collections.Generic.List[string]
    $first = [int]$Bytes[$start]
    $arcs.Add([string][Math]::Floor($first / 40))
    $arcs.Add([string]($first % 40))

    $value = 0
    for ($i = $start + 1; $i -lt ($start + $length); $i++) {
        $b = [int]$Bytes[$i]
        $value = ($value * 128) + ($b -band 0x7F)
        if (($b -band 0x80) -eq 0) {
            $arcs.Add([string]$value)
            $value = 0
        }
    }
    return ($arcs -join '.')
}

function Get-CertificateTemplateOid {
    <#
        Reads the Certificate Template extension (1.3.6.1.4.1.311.21.7), which is
        how you tell which template actually issued a certificate. Without it the
        only way to judge an existing certificate is its subject, and two
        certificates for different purposes look identical.
    #>
    param([Parameter(Mandatory)]$Certificate)

    $extension = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' }) | Select-Object -First 1
    if (-not $extension) { return $null }
    try {
        # SEQUENCE { OID template, INTEGER major, INTEGER minor } - the decoder
        # steps into the SEQUENCE itself.
        return (ConvertFrom-DerOid -Bytes $extension.RawData -Offset 0)
    }
    catch { return $null }
}

function Test-BatchLogon {
    <#
        Reproduces what WAS does when it starts a worker process for a custom app
        pool identity: LogonUser with LOGON32_LOGON_BATCH. Catches both a wrong
        password (1326) and a missing "Log on as a batch job" right (1385), which
        otherwise only surface later as an invalid-identity event and a 503.
    #>
    param([Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential)

    if (-not ('NdesBatchLogon' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NdesBatchLogon
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
                                        int dwLogonType, int dwLogonProvider, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
'@
    }

    $userName = $Credential.UserName
    $domain = '.'
    $account = $userName
    if ($userName -match '^(.+?)\\(.+)$') {
        $domain = $Matches[1]
        $account = $Matches[2]
    }

    $token = [IntPtr]::Zero
    $ok = [NdesBatchLogon]::LogonUser($account, $domain, $Credential.GetNetworkCredential().Password, 4, 0, [ref]$token)
    if ($ok) {
        [void][NdesBatchLogon]::CloseHandle($token)
        return [pscustomobject]@{ Valid = $true; Reason = $null }
    }

    $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $reason = switch ($code) {
        1326 { 'wrong user name or password' }
        1385 { 'the account is not granted "Log on as a batch job"' }
        1330 { 'the password has expired' }
        1907 { 'the password must be changed before signing in' }
        default { 'Win32 error ' + $code }
    }
    return [pscustomobject]@{ Valid = $false; Reason = $reason }
}

function Test-GmsaReady {
    <#
        Whether a gMSA is usable on this host right now.

        There is no password to check: LSA derives it from the domain's KDS root
        key. What can be established is whether this host has installed the account
        (Install-ADServiceAccount), which is what creates the local secret LSA logs
        the identity on with, and - when the ActiveDirectory module happens to be
        present - whether the password can actually be retrieved, which also proves
        this computer is allowed to read it.
    #>
    param([Parameter(Mandatory)][string]$Account)

    $shortName = (($Account -split '\\')[-1]).TrimEnd('$')

    if (-not (Get-Command Test-ADServiceAccount -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            State  = 'Unknown'
            Detail = ('Test-ADServiceAccount is not available here (no ActiveDirectory module), so this is unchecked; ' +
                'the application pool start below is the real test. Run it manually with: Test-ADServiceAccount -Identity {0}') -f $shortName
        }
    }

    try {
        if (Test-ADServiceAccount -Identity $shortName -ErrorAction Stop) {
            return [pscustomobject]@{ State = 'Ready'; Detail = 'installed on this host and its managed password is readable' }
        }
        return [pscustomobject]@{
            State  = 'Missing'
            Detail = 'Test-ADServiceAccount returned false - Install-ADServiceAccount has not been run on this host, or this computer is not allowed to retrieve the password.'
        }
    }
    catch {
        return [pscustomobject]@{
            State  = 'Missing'
            Detail = ('Test-ADServiceAccount failed: {0}' -f $_.Exception.Message)
        }
    }
}

function Register-NdesGmsaSpn {
    <#
        Registers HTTP/<name> on the gMSA, so Kerberos works for the site.

        IIS registers SPNs for the machine when a pool runs as
        ApplicationPoolIdentity, but not for a custom identity. A gMSA without an
        SPN therefore falls back to NTLM: mscep_admin still authenticates, but
        only with NTLM, and anything that requires Kerberos fails.

        The name must be the one clients type, which is the same name the server
        certificate is issued for. Duplicates are checked first, because an SPN on
        two accounts breaks Kerberos for both - and unlike setspn -S there is no
        switch that does it for us here.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][string]$DnsName,
        [string[]]$Extra = @()
    )

    if (-not (Get-Command Set-ADServiceAccount -ErrorAction SilentlyContinue)) {
        Write-Info 'Set-ADServiceAccount is not available, so no SPN can be registered from here' 'Warn'
        return $false
    }

    $shortName = (($Account -split '\\')[-1]).TrimEnd('$')
    $wanted = @(@(('HTTP/{0}' -f $DnsName.ToLower())) + @($Extra | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) |
        Sort-Object -Unique)

    $object = $null
    try {
        $object = Get-ADServiceAccount -Identity $shortName -Properties ServicePrincipalNames -ErrorAction Stop
    }
    catch {
        Write-Info ("Could not read {0} from the directory, so no SPN was registered: {1}" -f $Account, $_.Exception.Message) 'Warn'
        return $false
    }
    $current = @($object.ServicePrincipalNames | Where-Object { $_ })

    $toAdd = @()
    foreach ($entry in $wanted) {
        if ($current -contains $entry) { Write-Info ("SPN already registered: {0}" -f $entry) 'Ok'; continue }

        # One SPN on two accounts is worse than none: the client asks for a ticket
        # for that name and gets whichever account the KDC picks.
        $elsewhere = @()
        try {
            $elsewhere = @(Get-ADObject -Filter ("servicePrincipalName -eq '{0}'" -f $entry) -Properties servicePrincipalName -ErrorAction Stop |
                Where-Object { $_.DistinguishedName -ne $object.DistinguishedName })
        }
        catch { Write-Info ("Could not check {0} for duplicates: {1}" -f $entry, $_.Exception.Message) 'Warn' }

        if ($elsewhere.Count -gt 0) {
            Write-Info ("SPN {0} is already on {1} - not adding it, because a duplicate SPN breaks Kerberos for both accounts. Remove it there first, or use a name only this server answers on." -f `
                    $entry, (($elsewhere | ForEach-Object { $_.DistinguishedName }) -join ', ')) 'Warn'
            continue
        }
        $toAdd += $entry
    }

    if ($toAdd.Count -eq 0) { return $false }

    if (-not $PSCmdlet.ShouldProcess($Account, ('Register SPN {0}' -f ($toAdd -join ', ')))) {
        Write-Info ("Would register on {0}: {1}" -f $Account, ($toAdd -join ', ')) 'Warn'
        return $false
    }

    try {
        Set-ADServiceAccount -Identity $shortName -ServicePrincipalNames @{ Add = $toAdd } -ErrorAction Stop
    }
    catch {
        Write-Info ("Could not register {0} on {1}: {2}" -f ($toAdd -join ', '), $Account, $_.Exception.Message) 'Warn'
        Write-Info 'This needs write access to servicePrincipalName on the account: delegate it with dsacls, or run setspn -S by hand.' 'Warn'
        return $false
    }

    # Read it back: the attribute is multi-valued and a partial write shows up
    # only when Kerberos quietly falls back to NTLM.
    try {
        $after = @((Get-ADServiceAccount -Identity $shortName -Properties ServicePrincipalNames -ErrorAction Stop).ServicePrincipalNames)
        $missing = @($toAdd | Where-Object { $after -notcontains $_ })
        if ($missing.Count -eq 0) {
            Write-Info ("SPN registered on {0}: {1}" -f $Account, ($toAdd -join ', ')) 'Ok'
            return $true
        }
        Write-Info ("SPN write did not stick: {0}" -f ($missing -join ', ')) 'Warn'
        return $false
    }
    catch {
        Write-Info ("SPN written but could not be read back: {0}" -f $_.Exception.Message) 'Warn'
        return $true
    }
}

function Install-NdesAdModule {
    <#
        Makes the ActiveDirectory module available on this server.

        Install-ADServiceAccount, Test-ADServiceAccount and Get-ADServiceAccount all
        live in it, and a plain NDES server does not have it: RSAT is not part of
        the NDES build. The gMSA path needs all three, so the feature is installed
        the same way the NDES features are and then imported - installing a feature
        does not load its module into a session that is already running.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ((Get-Command Install-ADServiceAccount -ErrorAction SilentlyContinue) -and
        (Get-Command Test-ADServiceAccount -ErrorAction SilentlyContinue)) {
        Write-Info 'ActiveDirectory module already available' 'Ok'
        return [pscustomobject]@{ Ready = $true; Installed = $false }
    }

    $installed = $false

    $feature = 'RSAT-AD-PowerShell'
    $state = ''
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $row = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($row) { $state = [string]$row.InstallState }
    }

    if ($state -eq 'Installed') {
        Write-Info ("{0} is installed" -f $feature) 'Ok'
    }
    elseif (-not (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) {
        Write-Info ('Install-WindowsFeature is not available, so {0} cannot be installed from here' -f $feature) 'Warn'
        return [pscustomobject]@{ Ready = $false; Installed = $false }
    }
    elseif (-not $PSCmdlet.ShouldProcess($feature, 'Install-WindowsFeature')) {
        Write-Info ("Would install {0}, which provides Install-ADServiceAccount" -f $feature) 'Warn'
        return [pscustomobject]@{ Ready = $false; Installed = $false }
    }
    else {
        Write-Step ('Installing {0} (ActiveDirectory module, needed for the gMSA)' -f $feature)
        try {
            $result = Install-WindowsFeature -Name $feature -ErrorAction Stop
            if (-not $result.Success) {
                Write-Info ("{0} did not install (exit code {1}). Install it by hand: Install-WindowsFeature {2}" -f `
                        $feature, $result.ExitCode, $feature) 'Warn'
                return [pscustomobject]@{ Ready = $false; Installed = $false }
            }
            $installed = $true
            Write-Info ("{0} installed" -f $feature) 'Ok'
            if ([string]$result.RestartNeeded -eq 'Yes') {
                Write-Info ("{0} needs a restart before the module can be loaded. Reboot and run the restore again." -f $feature) 'Warn'
                return [pscustomobject]@{ Ready = $false; Installed = $true }
            }
        }
        catch {
            Write-Info ("Install-WindowsFeature {0} failed: {1}" -f $feature, $_.Exception.Message) 'Warn'
            return [pscustomobject]@{ Ready = $false; Installed = $false }
        }
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Info 'ActiveDirectory module imported' 'Ok'
        return [pscustomobject]@{ Ready = $true; Installed = $installed }
    }
    catch { $importError = $_.Exception.Message }

    # A module path the feature install added is not always visible to a session
    # that was already running, so try the location RSAT uses.
    $explicit = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules\ActiveDirectory'
    if (Test-Path -LiteralPath $explicit) {
        try {
            Import-Module $explicit -ErrorAction Stop
            Write-Info 'ActiveDirectory module imported from its install path' 'Ok'
            return [pscustomobject]@{ Ready = $true; Installed = $installed }
        }
        catch { }
    }
    Write-Info ("Could not import the ActiveDirectory module: {0}" -f $importError) 'Warn'
    return [pscustomobject]@{ Ready = $false; Installed = $installed }
}

function Install-NdesGmsa {
    <#
        Registers the gMSA on this host with Install-ADServiceAccount.

        This is host preparation, not NDES configuration: without the local
        credential it creates, LSA cannot log the identity on and the app pool never
        starts. It is called before the preflight - and therefore also when the
        preflight is skipped - because every check about the account depends on it.
        It does change the host, so -WhatIf does not perform it.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][string]$Account)

    $shortName = (($Account -split '\\')[-1]).TrimEnd('$')

    if (-not (Get-Command Install-ADServiceAccount -ErrorAction SilentlyContinue)) {
        Write-Info ('Install-ADServiceAccount is not available here (no ActiveDirectory module), so the gMSA cannot be installed from this server. ' +
            'Run it on the host from a session with RSAT, or add RSAT-AD-PowerShell to this server.') 'Warn'
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess($shortName, 'Install-ADServiceAccount')) {
        Write-Info ("Would install the gMSA on this host: Install-ADServiceAccount -Identity {0}" -f $shortName) 'Warn'
        return $false
    }

    try {
        Install-ADServiceAccount -Identity $shortName -ErrorAction Stop | Out-Null
        Write-Info ("Installed the gMSA on this host: {0}" -f $shortName) 'Ok'
        return $true
    }
    catch {
        Write-Info ("Install-ADServiceAccount failed for {0}: {1}" -f $shortName, $_.Exception.Message) 'Warn'
        Write-Info 'Usual causes: this computer account is not in PrincipalsAllowedToRetrieveManagedPassword, the domain has no KDS root key, or the name is a user account rather than a gMSA.' 'Warn'
        return $false
    }
}

function Grant-CertificateKeyRead {
    <#
        Grants an account read access to a certificate's private key file.

        The key file carries an ACE only for the identity that created it, plus
        Administrators and SYSTEM. The SCEP app pool runs as the service account,
        so without this it cannot use the RA certificates at all.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$Account
    )

    $cert = Get-ChildItem -Path ("Cert:\LocalMachine\My\{0}" -f $Thumbprint) -ErrorAction SilentlyContinue
    if (-not $cert) {
        Write-Info ("Certificate {0} not found; private key access not changed" -f $Thumbprint) 'Warn'
        return
    }

    $container = $null
    try { $container = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName } catch { }
    if (-not $container) {
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if ($rsa -and $rsa.Key) { $container = $rsa.Key.UniqueName }
        }
        catch { }
    }
    if (-not $container) {
        Write-Info ("Could not locate the private key container for {0}; grant {1} access manually" -f $Thumbprint, $Account) 'Warn'
        return
    }

    $candidates = @(
        (Join-Path $env:ProgramData ("Microsoft\Crypto\RSA\MachineKeys\{0}" -f $container)),
        (Join-Path $env:ProgramData ("Microsoft\Crypto\Keys\{0}" -f $container))
    )
    $keyFile = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $keyFile) {
        Write-Info ("Private key file for {0} not found under ProgramData\Microsoft\Crypto" -f $Thumbprint) 'Warn'
        return
    }

    try {
        $acl = Get-Acl -LiteralPath $keyFile
        $already = @($acl.Access | Where-Object { $_.IdentityReference -match [regex]::Escape(($Account -split '\\')[-1]) })
        if ($already.Count -gt 0) {
            Write-Info ("{0} already has access to the private key" -f $Account) 'Ok'
            return
        }

        if ($PSCmdlet.ShouldProcess($keyFile, "Grant Read to $Account")) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Account, 'Read', 'Allow')
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $keyFile -AclObject $acl
        }
        Write-Info ("{0} granted Read on the private key" -f $Account) 'Ok'
    }
    catch {
        Write-Info ("Could not set private key permissions: {0}" -f $_.Exception.Message) 'Warn'
    }
}

function Get-RaEnrolmentHint {
    <#
        Turns a CA/enrolment failure into something actionable. The two cases
        that actually happen are a template that only issues to users, and a
        template whose ACL does not include the identity doing the enrolling.
    #>
    param(
        [AllowEmptyString()][string]$Reason,
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][string]$MscepValue,
        [string]$Identity = '',
        [string]$Url = ''
    )

    if (-not $Identity) { $Identity = $env:COMPUTERNAME }

    if ($Reason -match '(?i)CX509EnrollmentPolicyWebService|0x80070057|ERROR_INVALID_PARAMETER') {
        $text = "That URL is not a certificate enrollment policy (CEP) endpoint. Get-Certificate -Credential needs " +
        "the CEP web service, not Web Enrollment: https://<CA>/ADPolicyProvider_CEP_UsernamePassword/service.svc " +
        '(or ..._CEP_Kerberos/service.svc). Tried: {0}. If the CA has no Certificate Enrollment Policy role ' +
        'service, alternate-credential enrolment is not available at all - run the preflight without a URL for the ' +
        'two supported alternatives.'
        return ($text -f $(if ($Url) { $Url } else { '(none)' }))
    }
    if ($Reason -match '(?i)missing url|url parameter|policy server|cep endpoint') {
        $text = "The enrolment policy endpoint was not usable. Get-Certificate needs an explicit -Url when a " +
        '-Credential is supplied, because it cannot discover the CA as that user. Tried: {0}. Override with ' +
        '-EnrollmentPolicyUrl (normally http://<CA>/certsrv/, or https://<CA>/ADPolicyProvider_CEP_UsernamePassword/service.svc).'
        return ($text -f $(if ($Url) { $Url } else { '(none)' }))
    }
    if ($Reason -match 'ERROR_INVALID_DATA|0x8007000D|-2147024883|certreq -new failed') {
        $text = "certreq could not build a request for template '{0}'. Either the name does not resolve to a " +
        'published template, or the template refuses a supplied subject. The machine-capable pair avoids this ' +
        'entirely - pass -RAEncryptionTemplate CEPEncryption -RASigningTemplate MachineEnrollmentAgent.'
        return ($text -f $Template)
    }
    if ($Reason -match 'issued only to a user|CONTEXT_E_ROLENOTFOUND|0x8004e00c') {
        $text = "Template '{0}' is not machine-capable, so a request into LocalMachine\My is refused before its ACL " +
        "is even consulted. Use 'MachineEnrollmentAgent' (Machine Enrollment Agent) for the signing role - it has " +
        "the Certificate Request Agent EKU and accepts computers. Templates that accept computers have the 0x40 bit " +
        "set in their AD 'flags' attribute. Recorded in the bundle as MSCEP {1}."
        return ($text -f $Template, $MscepValue, $Identity)
    }
    if ($Reason -match 'CERTSRV_E_TEMPLATE_DENIED|0x80094012|do not have permission to request') {
        $text = "The template ACL does not grant Enroll to {0}, which is the identity this request was made as. " +
        "Grant Read and Enroll on template '{1}' to that account, or to a group it belongs to - a group such as " +
        'NDES-Servers covers every NDES server you build later. This permission is an ACL on the template ' +
        'object in AD, not a CA setting, so nothing on the CA has to change - and enrolling the template by ' +
        'hand as a domain admin tests a different ACE, so it can succeed while this still fails.'
        return ($text -f $Identity, $Template)
    }
    $text = "{0} needs Enroll on template '{1}', and needs Request Certificates on the CA. " +
    'Together with the CA policy module, that is what decides whether the request is issued.'
    return ($text -f $Identity, $Template)
}

function Install-NdesRaCertificates {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$EncryptionTemplate,
        [Parameter(Mandatory)][string]$SigningTemplate,
        [string]$Subject,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$EnrollmentPolicyUrl,
        [string]$GrantKeyReadTo,
        [string]$CAConfig
    )

    if (-not (Get-Command Get-Certificate -ErrorAction SilentlyContinue)) {
        throw 'Get-Certificate is not available (PKI module). This script requires Windows Server 2012 or later.'
    }

    if (-not $Subject) { $Subject = 'CN=NDES-MSCEP-RA, C=AU' }
    $subjectMatch = if ($Subject -match 'CN=([^,]+)') { $Matches[1] } else { 'MSCEP-RA' }

    $existing = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match [regex]::Escape($subjectMatch) })
    if ($existing.Count -ge 2 -and -not $Force) {
        Write-Info ("Found {0} existing RA certificate(s) in the machine store" -f $existing.Count)
    }

    # How the request is authenticated:
    #   cep      - Get-Certificate with an explicit credential + CEP policy endpoint
    #   certreq  - key/CSR built in the machine store, CSR submitted (optionally as
    #              the service account). This is the only route that works when the
    #              RA template is user-only, because Get-Certificate ties the
    #              enrolment context to the store location.
    $canUseCredential = (Get-Command Get-Certificate).Parameters.ContainsKey('Credential')
    $useCep = [bool]($Credential -and $EnrollmentPolicyUrl -and $canUseCredential)
    $mode = if ($useCep) { 'cep' } else { 'certreq' }

    # The identity the CA will see as the requester - that is what the template ACL
    # is evaluated against. In the primary machine-context path it is the computer
    # account, whatever -Credential was supplied; that credential is only used in
    # cep mode and in the certreq retry.
    $identity = if ($useCep) { $Credential.UserName }
    else { '{0}$ (computer account)' -f $env:COMPUTERNAME }

    Write-Step 'Enrolling RA certificates (encryption, then signing)'
    Write-Info ("Encryption template: {0} (MSCEP EncryptionTemplate)" -f $EncryptionTemplate)
    Write-Info ("Signing template   : {0} (MSCEP SignatureTemplate)" -f $SigningTemplate)
    Write-Info ("Requesting as      : {0}" -f $identity)
    if ($mode -eq 'cep') { Write-Info ("Policy endpoint    : {0}" -f $EnrollmentPolicyUrl) }
    $requests = @(
        [pscustomobject]@{ Name = $EncryptionTemplate; Purpose = 'encryption'; MscepValue = 'EncryptionTemplate' },
        [pscustomobject]@{ Name = $SigningTemplate; Purpose = 'signing'; MscepValue = 'SignatureTemplate' }
    )

    $enrolmentErrors = @()
    foreach ($request in $requests) {
        if ([string]::IsNullOrWhiteSpace($request.Name)) { throw ('RA {0} template name is missing.' -f $request.Purpose) }

        # Skip only the purpose that already has a certificate from THIS template.
        # Counting by subject cannot tell an encryption certificate from a signing
        # one, and would let a stray duplicate hide a genuinely missing cert.
        if (-not $Force -and $existing.Count -gt 0) {
            $wantedOid = Get-TemplateOid -Template $request.Name
            $presentOids = @($existing | ForEach-Object { Get-CertificateTemplateOid -Certificate $_ } |
                Where-Object { $_ } | Sort-Object -Unique)

            $match = @()
            if ($wantedOid) {
                $match = @($existing | Where-Object { (Get-CertificateTemplateOid -Certificate $_) -eq $wantedOid })
            }

            if ($match.Count -gt 0) {
                Write-Info ("{0}: already enrolled from {1} ({2})" -f $request.Purpose, $request.Name, $match[0].Thumbprint) 'Ok'
                if ($GrantKeyReadTo) { Grant-CertificateKeyRead -Thumbprint $match[0].Thumbprint -Account $GrantKeyReadTo }
                continue
            }

            # Schema v1 templates do not reliably stamp the Certificate Template
            # extension on issued certificates, so there may be nothing to match.
            # Fall back to counting rather than re-enrolling on every run.
            if ($presentOids.Count -eq 0 -and $existing.Count -ge 2) {
                Write-Info ("{0}: {1} RA certificate(s) already present and no template ids are readable; assuming both roles are covered (-Force to re-enrol)" -f `
                        $request.Purpose, $existing.Count) 'Warn'
                continue
            }

            Write-Info ("{0}: nothing from {1} yet (wanted {2}; present: {3})" -f $request.Purpose, $request.Name,
                $(if ($wantedOid) { $wantedOid } else { 'unknown' }),
                $(if ($presentOids) { $presentOids -join ', ' } else { 'no template ids readable' }))
        }

        if (-not $PSCmdlet.ShouldProcess($request.Name, "Enrol RA $($request.Purpose) certificate")) {
            Write-Info ("{0}: would enrol from template {1}" -f $request.Purpose, $request.Name) 'Warn'
            continue
        }

        $certificate = $null
        try {
            if ($mode -eq 'cep') {
                $certificate = (Get-Certificate -Template $request.Name -SubjectName $Subject `
                        -CertStoreLocation 'Cert:\LocalMachine\My' `
                        -Credential $Credential -Url $EnrollmentPolicyUrl -ErrorAction Stop).Certificate
            }
            else {
                # Machine context is the primary path: it is what the guide means by
                # "requested in the computer certificate store", and it works for
                # machine-capable templates (CEP Encryption, Enrollment Agent).
                try {
                    $certificate = (Get-Certificate -Template $request.Name -SubjectName $Subject `
                            -CertStoreLocation 'Cert:\LocalMachine\My' -ErrorAction Stop).Certificate
                }
                catch {
                    $machineError = [string]$_.Exception.Message
                    if ($machineError -notmatch 'CONTEXT_E_ROLENOTFOUND|0x8004e00c|issued only to a user') { throw }

                    # Only a user-only template gets here - retry with certreq, which
                    # can submit as the service account without a CEP endpoint.
                    $retryAs = if ($Credential) { $Credential.UserName } else { 'the current user' }
                    Write-Info ("Template refuses machine requests; retrying via certreq as {0}" -f $retryAs) 'Warn'
                    $certificate = Install-RaCertificateViaCertReq -Template $request.Name -Subject $Subject `
                        -CAConfig $CAConfig -Credential $Credential
                }
            }
        }
        catch {
            $reason = [string]$_.Exception.Message
            $hint = Get-RaEnrolmentHint -Reason $reason -Template $request.Name -MscepValue $request.MscepValue `
                -Identity $identity -Url $EnrollmentPolicyUrl
            # Keep going: the two certificates are independent, and one failing
            # must not hide the result of the other.
            $enrolmentErrors += ("RA {0} certificate request failed for template '{1}'.`n  {2}`n  {3}" -f `
                    $request.Purpose, $request.Name, $reason, $hint)
            Write-Info ("{0}: failed - {1}" -f $request.Purpose, ($reason -split "`n")[0]) 'Warn'
            continue
        }

        if (-not $certificate) {
            Write-Info ("{0}: no certificate returned (nothing was changed)" -f $request.Purpose) 'Warn'
            continue
        }

        Write-Info ("{0} ({1}): {2}" -f $request.Purpose, $request.Name, $certificate.Thumbprint) 'Ok'

        # The subject matters: NDES publishes these certificates in GetCACert and a
        # device matches them by subject. A machine template built from Active
        # Directory takes the computer's name and ignores the requested subject, so
        # say so instead of leaving a certificate that looks right by thumbprint and
        # wrong everywhere else.
        if ($Subject -and $certificate.Subject -ne $Subject) {
            Write-Info ('{0}: the CA issued subject "{1}", not the requested "{2}" - template {3} builds the subject from Active Directory, so the subject cannot be supplied by the requester.' -f `
                    $request.Purpose, $certificate.Subject, $Subject, $request.Name) 'Warn'
            Write-Info 'The certificate still works for NDES (the template and its EKU are what matter), but it will not match the source server, and GetCACert will publish a differently-named RA certificate.' 'Warn'
        }

        # The SCEP app pool runs as the service account and must read this key.
        # Whichever identity enrolled, the key file only carries an ACE for that
        # identity, so grant the service account explicitly.
        if ($GrantKeyReadTo) {
            Grant-CertificateKeyRead -Thumbprint $certificate.Thumbprint -Account $GrantKeyReadTo
        }
    }

    if ($enrolmentErrors.Count -gt 0) {
        throw (($enrolmentErrors -join "`n`n") + ("`n`n{0} of 2 RA certificate(s) could not be enrolled." -f $enrolmentErrors.Count))
    }
}

function Install-NdesServerCertificate {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][string]$DnsName
    )

    Write-Step ('Requesting server certificate ({0}) for {1}' -f $Template, $DnsName)

    $existing = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -match 'NDES' -and $_.Subject -notmatch 'MSCEP-RA' -and $_.NotAfter -gt (Get-Date).AddDays(7) })
    if ($existing.Count -gt 0 -and -not $Force) {
        Write-Info ("Valid server certificate already present: {0}" -f $existing[0].Thumbprint) 'Warn'
        return $existing[0]
    }

    if (-not $PSCmdlet.ShouldProcess($Template, "Request server certificate for $DnsName")) {
        Write-Info ("Would request a server certificate from {0} for {1}" -f $Template, $DnsName) 'Warn'
        return $null
    }

    try {
        $result = Get-Certificate -Template $Template `
            -SubjectName ("CN={0}" -f $DnsName) `
            -DnsName $DnsName `
            -CertStoreLocation 'Cert:\LocalMachine\My' -ErrorAction Stop
    }
    catch {
        throw ("Server certificate request failed for template '{0}': {1}" -f $Template, $_.Exception.Message)
    }

    if ($null -eq $result -or -not $result.Certificate) {
        throw ("Template '{0}' did not return a certificate (status: {1})." -f $Template, $(if ($result) { $result.Status } else { 'unknown' }))
    }

    $cert = $result.Certificate
    try {
        if ($cert.FriendlyName -ne 'NDES web server cert' -and $PSCmdlet.ShouldProcess($cert.Thumbprint, 'Set friendly name')) {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
            $store.Open('ReadWrite')
            $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint } | Select-Object -First 1
            if ($found) { $found.FriendlyName = 'NDES web server cert' }
            $store.Close()
        }
    }
    catch { Write-Info 'Could not set a friendly name (non-fatal)' 'Warn' }

    Write-Info ("Issued: {0}" -f $cert.Thumbprint) 'Ok'
    return $cert
}

function Test-SiteBinding {
    <# Reads bindings from applicationHost.config, which is authoritative, then
       falls back to appcmd's listing. #>
    param(
        [Parameter(Mandatory)][string]$Protocol,
        [Parameter(Mandatory)][string]$Information
    )

    try {
        $appHost = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
        if (Test-Path -LiteralPath $appHost) {
            [xml]$hostConfig = Get-Content -LiteralPath $appHost -Raw
            $node = $hostConfig.SelectSingleNode(
                "/configuration/system.applicationHost/sites/site[@name='$($script:SiteName)']/bindings/binding[@protocol='$Protocol'][@bindingInformation='$Information']")
            if ($node) { return $true }
        }
    }
    catch { }

    $siteInfo = Invoke-AppCmd -Arguments @('list', 'site', $script:SiteName) -IgnoreExitCode
    return ($siteInfo -match ('{0}/\*?:{1}' -f [regex]::Escape($Protocol), [regex]::Escape($Information)))
}

function Set-NdesSiteBinding {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)]$Certificate)

    Write-Step 'Binding HTTPS on the default web site'

    if (-not (Test-SiteBinding -Protocol 'https' -Information '*:443:')) {
        if ($PSCmdlet.ShouldProcess($script:SiteName, 'Add https binding on 443')) {
            # appcmd needs the site identified by /site.name:, not by its path.
            Invoke-AppCmd -Arguments @('set', 'site', ('/site.name:{0}' -f $script:SiteName),
                '/+bindings.[protocol=''https'',bindingInformation=''*:443:'']') | Out-Null
        }
        Write-Info 'https binding added on *:443' 'Ok'
    }
    else { Write-Info 'https binding already present' 'Ok' }

    # IIS itself uses HTTP.SYS for the certificate mapping, so netsh is the
    # reliable way to attach the certificate to the IP:port binding.
    $appId = '{4dc3e181-e14b-4a21-b022-59fc669b0914}'   # IIS
    $ipport = '0.0.0.0:443'
    $current = (& netsh http show sslcert ipport=$ipport 2>&1 | Out-String)

    if ($current -match 'Cannot find the certificate') {
        if ($PSCmdlet.ShouldProcess($ipport, "Bind certificate $($Certificate.Thumbprint)")) {
            $null = & netsh http add sslcert ipport=$ipport certhash=$($Certificate.Thumbprint) appid=$appId certstorename=MY 2>&1
            if ($LASTEXITCODE -ne 0) { throw ("netsh http add sslcert failed for {0}" -f $ipport) }
        }
        Write-Info ("Certificate bound to {0}" -f $ipport) 'Ok'
    }
    elseif ($current -match [regex]::Escape($Certificate.Thumbprint)) {
        Write-Info 'Certificate already bound to 443' 'Ok'
    }
    else {
        # A different certificate is bound; replace it.
        if ($PSCmdlet.ShouldProcess($ipport, 'Replace existing certificate binding')) {
            $null = & netsh http delete sslcert ipport=$ipport 2>&1
            $null = & netsh http add sslcert ipport=$ipport certhash=$($Certificate.Thumbprint) appid=$appId certstorename=MY 2>&1
            if ($LASTEXITCODE -ne 0) { throw ("netsh http add sslcert failed for {0}" -f $ipport) }
        }
        Write-Info 'Existing binding replaced with the new certificate' 'Ok'
    }
}

function Set-NdesServiceGroups {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][string]$Account)

    Write-Step 'Configuring local group membership'

    # Required for the SCEP application pool identity to read the ISAPI payload.
    $iisUsers = 'IIS_IUSRS'
    $members = @(Get-LocalGroupMember -Group $iisUsers -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    if ($members -notcontains $Account) {
        if ($PSCmdlet.ShouldProcess($Account, "Add to $iisUsers")) {
            Add-LocalGroupMember -Group $iisUsers -Member $Account -ErrorAction Stop
        }
        Write-Info ("{0} added to {1}" -f $Account, $iisUsers) 'Ok'
    }
    else { Write-Info ("{0} already in {1}" -f $Account, $iisUsers) 'Ok' }

    # Local Administrators is NOT added by default: the whole point of this
    # method is that the service account does not need standing admin rights.
    $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    if ($admins -contains $Account) {
        Write-Info ("{0} is a member of local Administrators (not required; consider removing)" -f $Account) 'Warn'
    }
}

function Invoke-Restore {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Assert-Elevated

    $bundlePath = Resolve-BundlePath
    $configFile = Join-Path $bundlePath 'ndes-config.json'
    if (-not (Test-Path -LiteralPath $configFile)) { throw "Bundle not found: $configFile" }

    # Logs go beside the bundles, not inside the bundle: the bundle is a
    # read-only artefact that may be kept for later restores.
    $logRoot = 'C:\NDESMigration\logs'
    if (-not (Test-Path -LiteralPath $logRoot)) { New-Item -ItemType Directory -Path $logRoot -Force | Out-Null }
    Initialize-Log -Directory $logRoot
    Write-Step ("Restoring NDES from {0}" -f $configFile)
    Write-ScriptIdentity

    $config = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json

    # --- confirm the values that vary per environment ----------------------
    Write-Step 'Confirming settings (press Enter to accept the backed-up value)'

    $backedUpAccount = ''
    $appPoolConfig = Get-OptionalProperty -Object $config -Name 'AppPool'
    if ($appPoolConfig) {
        $userName = Get-OptionalProperty -Object $appPoolConfig -Name 'UserName'
        if ($userName) { $backedUpAccount = [string]$userName }
    }
    if ($ServiceAccount) { $backedUpAccount = $ServiceAccount }

    $account = Confirm-Value -Label 'Service account (domain\user)' -Default $backedUpAccount
    if ($account -notmatch '\\') {
        throw "Service account must be in DOMAIN\User form. Got: $account"
    }

    # A gMSA has no password anyone can type, so this changes what is asked for
    # next and which preflight checks are meaningful. The '$' suffix is how a
    # gMSA appears as an account name, so it makes a good default; an explicitly
    # supplied password credential settles it without asking.
    $isGmsa = $false
    if ($UseGmsa) { $isGmsa = $true }
    elseif ($ServiceAccountCredential) { $isGmsa = $false }
    else {
        $isGmsa = Confirm-YesNo -Label ("Run {0} as a group Managed Service Account (no password)?" -f $account) `
            -Default ($account.Trim().EndsWith('$'))
    }
    if ($isGmsa -and -not $account.Trim().EndsWith('$')) {
        Write-Info ("{0} does not end in '$', which is how a gMSA is named (its sAMAccountName). Continuing with the name as typed." -f $account) 'Warn'
    }

    $backedUpCA = [string](Get-MscepValue -Config $config -Name 'Configuration')
    if ($CAConfig) { $backedUpCA = $CAConfig }
    $caConfig = Confirm-Value -Label 'CA configuration (CAHost\CAName)' -Default $backedUpCA
    if ($caConfig -notmatch '\\') {
        throw "CA configuration must be in CAHost\CAName form. Got: $caConfig"
    }

    # Enrolling as the service account rules out AD discovery, so it needs a CEP
    # policy endpoint. A default CA does not publish one, so this is opt-in: with
    # no URL the request runs in machine context and the RA template must grant
    # the computer account Enroll.
    #
    # A gMSA cannot take that path at all: -Credential needs a password, and
    # alternate-credential enrolment is the only thing the URL is for.
    $policyUrl = $EnrollmentPolicyUrl
    if ($isGmsa -and $policyUrl) {
        Write-Info 'A gMSA has no password, so alternate-credential (CEP) enrolment cannot be used; enrolling in machine context instead.' 'Warn'
        $policyUrl = ''
    }

    $recordedTemplate = Get-OptionalProperty -Object $config -Name 'ServerCertificateTemplate'
    $templateDefault = if ($ServerCertificateTemplate) { $ServerCertificateTemplate }
    elseif ($recordedTemplate) { [string]$recordedTemplate }
    else { $script:DefaultServerTemplate }
    $serverTemplate = Confirm-Value -Label 'Server certificate template' -Default $templateDefault

    # The RA certificates must come from the templates NDES looks them up by
    # (MSCEP EncryptionTemplate / SignatureTemplate), otherwise the service finds
    # nothing even though the certificates exist.
    $raEncryptionDefault = if ($RAEncryptionTemplate) { $RAEncryptionTemplate }
    else {
        $recorded = [string](Get-MscepValue -Config $config -Name 'EncryptionTemplate')
        if ($recorded) { $recorded } else { $script:DefaultEncryptionTemplate }
    }
    $raEncryption = Confirm-Value -Label 'RA encryption template (MSCEP EncryptionTemplate)' -Default $raEncryptionDefault

    $raSigningDefault = if ($RASigningTemplate) { $RASigningTemplate }
    else {
        $recorded = [string](Get-MscepValue -Config $config -Name 'SignatureTemplate')
        if ($recorded) { $recorded } else { $script:DefaultSigningTemplate }
    }
    $raSigning = Confirm-Value -Label 'RA signing template (MSCEP SignatureTemplate)' -Default $raSigningDefault

    $dnsDefault = ''
    if ($env:USERDNSDOMAIN) { $dnsDefault = ('{0}.{1}' -f $env:COMPUTERNAME.ToLower(), $env:USERDNSDOMAIN.ToLower()) }
    else {
        $domain = $null
        try { $domain = (Get-CimInstance Win32_ComputerSystem).Domain } catch { }
        if ($domain -and $domain -ne 'WORKGROUP') { $dnsDefault = ('{0}.{1}' -f $env:COMPUTERNAME.ToLower(), $domain.ToLower()) }
        else { $dnsDefault = $env:COMPUTERNAME.ToLower() }
    }
    $dnsName = Confirm-Value -Label 'Server FQDN for the certificate' -Default $dnsDefault

    # -Verify: read the server, compare with the bundle, change nothing, and do not
    # ask for credentials - the comparison needs none.
    if ($Verify) {
        Write-Step 'Verify only - nothing will be changed'
        $verified = Compare-NdesTargetToBundle -Config $config -Account $account -CAConfig $caConfig
        Write-Step 'Summary'
        if ($verified -eq 0) { Write-Info 'This server matches the bundle.' 'Ok' }
        else { Write-Info ("{0} difference(s) - see the list above." -f $verified) 'Warn' }
        Write-Info ("Log: {0}" -f $script:LogFile)
        return
    }

    # --- credentials -------------------------------------------------------
    $secret = $null
    $gmsaInstalled = $false
    $prereqChanges = @()
    if ($isGmsa) {
        if ($ServiceAccountCredential) {
            Write-Info 'A credential was supplied as well; it is ignored, because a gMSA password cannot be entered by anyone.' 'Warn'
            $ServiceAccountCredential = $null
        }
        # The cmdlets this path needs live in the ActiveDirectory module, which a
        # plain NDES server does not have.
        $adModule = Install-NdesAdModule
        if ($adModule.Installed) { $prereqChanges += 'RSAT-AD-PowerShell' }
        $gmsaReady = Test-GmsaReady -Account $account
        if ($gmsaReady.State -ne 'Ready') {
            # Runs before the preflight and therefore also under -SkipPreflight: the
            # registration is what everything else about the account depends on.
            $gmsaInstalled = Install-NdesGmsa -Account $account
            if ($gmsaInstalled) { $prereqChanges += 'the gMSA registration' }
            $gmsaReady = Test-GmsaReady -Account $account
        }
        if ($gmsaReady.State -eq 'Missing') {
            throw ("{0} is not usable on this host: {1} " +
                'Run Install-ADServiceAccount as an administrator on this server, and make sure this computer account is allowed to read the gMSA password (PrincipalsAllowedToRetrieveManagedPassword).') -f `
                $account, $gmsaReady.Detail
        }
        Write-Info ("Service account is a gMSA: {0} - {1}" -f $account, $gmsaReady.Detail) $(if ($gmsaReady.State -eq 'Ready') { 'Ok' } else { 'Warn' })

        # Kerberos for the site name. IIS does not do this for a custom identity,
        # and without it mscep_admin authenticates over NTLM only.
        if (Register-NdesGmsaSpn -Account $account -DnsName $dnsName -Extra $Spn) {
            $prereqChanges += 'the HTTP SPN'
        }
    }
    else {
        if (-not $ServiceAccountCredential) {
            $ServiceAccountCredential = Get-Credential -UserName $account -Message "Password for $account (used for the SCEP application pool identity)"
            if (-not $ServiceAccountCredential) { throw 'Credentials are required to set the application pool identity.' }
        }
        $secret = $ServiceAccountCredential.Password

        # Validate before touching anything. WAS enforces a batch logon for a custom
        # app pool identity, and a wrong password there only surfaces later as an
        # invalid identity and HTTP 503.
        $batchLogon = Test-BatchLogon -Credential $ServiceAccountCredential
        if (-not $batchLogon.Valid) {
            throw ("The SCEP application pool could not log on as {0}: {1}. " +
                'IIS would disable the pool and every request would return HTTP 503.') -f `
                $account, $batchLogon.Reason
        }
        Write-Info ("Service account can log on for IIS: {0}" -f $account) 'Ok'
    }

    # --- registry targets: build now, write in step 4 ----------------------
    # Doing this before the certificates matters: the certificates must come from
    # the templates -RAEncryptionTemplate / -RASigningTemplate name, and the
    # registry is corrected to the wizard's own values further down.
    $targets = @(Get-BundleRegistryTargets -Config $config | ForEach-Object {
            [pscustomobject]@{
                Key    = [string]$_.Key
                Values = @($_.Values | ForEach-Object {
                        [pscustomobject]@{ Path = [string]$_.Path; Name = [string]$_.Name; Kind = [string]$_.Kind; Value = $_.Value }
                    })
            }
        })

    # The CA differs per environment.
    $mscepTarget = $targets | Where-Object { $_.Key -match '\\Cryptography\\MSCEP$' } | Select-Object -First 1
    if ($mscepTarget) {
        $caEntry = $mscepTarget.Values | Where-Object { $_.Name -eq 'Configuration' } | Select-Object -First 1
        if ($caEntry) { $caEntry.Value = $caConfig }
        else { $mscepTarget.Values += [pscustomobject]@{ Path = 'CAInfo'; Name = 'Configuration'; Kind = 'String'; Value = $caConfig } }
    }
    else {
        throw ("The bundle has no MSCEP registry values ({0} was never written), so NDES would have no configuration." -f $script:MSCEPKeyNative)
    }

    # The wizard writes the same template name into all three MSCEP values, and
    # NDES wants them that way: a server whose EncryptionTemplate/SignatureTemplate
    # name the templates the RA certificates were enrolled from answers every
    # request with "You do not have sufficient permission to enroll with SCEP",
    # with both certificates present and valid. GeneralPurposeTemplate is the one
    # that keeps the wizard's value, so it is the source for the other two.
    $generalPurposeTemplate = [string](Get-MscepValue -Config $config -Name 'GeneralPurposeTemplate')
    if ($generalPurposeTemplate) {
        Set-MscepTargetValue -Targets $targets -Name 'EncryptionTemplate' -Value $generalPurposeTemplate
        Set-MscepTargetValue -Targets $targets -Name 'SignatureTemplate' -Value $generalPurposeTemplate
    }
    else {
        Write-Info 'The bundle has no MSCEP GeneralPurposeTemplate, so the other two template values are restored as captured.' 'Warn'
    }

    Write-Info ("Service account : {0}" -f $account)
    Write-Info ("CA configuration: {0}" -f $caConfig)
    Write-Info ("RA enrolment    : encryption={0}, signing={1}" -f $raEncryption, $raSigning)
    if ($generalPurposeTemplate) {
        Write-Info ("MSCEP templates : encryption={0}, signing={1}, general={2}" -f `
                $generalPurposeTemplate, $generalPurposeTemplate, $generalPurposeTemplate)
    }
    Write-Info ("Policy endpoint : {0}" -f $policyUrl)
    Write-Info ("Server template : {0}" -f $serverTemplate)
    Write-Info ("Server FQDN     : {0}" -f $dnsName)

    # --- 0. preflight -------------------------------------------------------
    # Read-only checks, deliberately before the first change. -WhatIf alone only
    # suppresses writes; it cannot tell you whether they would have worked.
    if (-not $SkipPreflight) {
        $preflight = Invoke-Preflight -Account $account -CAConfig $caConfig -ServerTemplate $serverTemplate `
            -EncryptionTemplate $raEncryption -SigningTemplate $raSigning -Credential $ServiceAccountCredential `
            -EnrollmentPolicyUrl $policyUrl -UseGmsa:$isGmsa
        $preflightCounts = Write-PreflightReport -Results $preflight

        if ($Preflight) {
            Write-Step 'Preflight only'
            if ($prereqChanges.Count -gt 0) {
                Write-Info ('Changed on this host first: {0}. Nothing else was changed (-Preflight).' -f ($prereqChanges -join ', ')) 'Warn'
            }
            else { Write-Info 'No changes were made (-Preflight).' }
            if ($preflightCounts['Fail'] -gt 0) { Write-Info ("{0} check(s) would block a restore." -f $preflightCounts['Fail']) 'Warn' }
            return
        }

        if ($preflightCounts['Fail'] -gt 0) {
            Write-Info ("{0} preflight check(s) failed - stopping before any change." -f $preflightCounts['Fail']) 'Warn'
            Write-Info 'Fix them, or re-run with -SkipPreflight to proceed anyway.' 'Warn'
            throw ("Preflight failed: {0} check(s). See the report above." -f $preflightCounts['Fail'])
        }
    }
    else { Write-Info 'Preflight skipped (-SkipPreflight)' 'Warn' }

    # --- 1. features -------------------------------------------------------
    Install-NdesFeatures -Features @($config.Features)
    Assert-IisPresent

    # --- 2. IIS ------------------------------------------------------------
    Set-NdesApplicationPool -AppPool $config.AppPool -Account $account -Password $secret -UseGmsa:$isGmsa
    Set-NdesApplications -Applications $config.Applications

    # Bundles captured before schema 3 never recorded these settings - the
    # Authentication block was a constant fallback, not a reading of the server,
    # and it said "anonymous off" for the device endpoint, which no working NDES
    # has. Trusting it would rebuild the broken state, so for those bundles the
    # NDES defaults are used instead and the operator is told to re-capture.
    $capturedAuthentication = $config.Authentication
    $schemaVersion = 0
    $schemaValue = Get-OptionalProperty -Object $config -Name 'SchemaVersion'
    if ($null -ne $schemaValue) { $schemaVersion = [int]$schemaValue }
    if ($schemaVersion -lt 3) {
        $capturedAuthentication = @()
        Write-Info ("Bundle schema {0} did not record the per-application IIS settings; using the NDES defaults (mscep anonymous, mscep_admin authenticated, handlers Read+Execute). Re-run -Backup on the working server to capture the real values." -f $schemaVersion) 'Warn'
    }

    Set-NdesApplicationSettings -Applications $config.Applications -Authentication $capturedAuthentication
    Set-NdesIsapiRegistration
    Set-NdesHandlerOrder
    Set-NdesServiceGroups -Account $account

    # --- 3. certificates ---------------------------------------------------
    # Defined outside the skip branch: the repair step needs it even when
    # enrolment was skipped for this run.
    $raSubject = [string](Get-OptionalProperty -Object $config -Name 'RACertificateSubject')
    if (-not $raSubject) { $raSubject = 'CN=NDES-MSCEP-RA, C=AU' }

    if (-not $SkipRACertificates) {
        Install-NdesRaCertificates -EncryptionTemplate $raEncryption -SigningTemplate $raSigning `
            -Subject $raSubject -Credential $ServiceAccountCredential `
            -EnrollmentPolicyUrl $policyUrl -GrantKeyReadTo $account -CAConfig $caConfig
    }
    else { Write-Info 'RA certificate enrolment skipped (-SkipRACertificates)' 'Warn' }

    $serverCert = $null
    if (-not $SkipServerCertificate) {
        $serverCert = Install-NdesServerCertificate -Template $serverTemplate -DnsName $dnsName
        if ($serverCert) { Set-NdesSiteBinding -Certificate $serverCert }
        else { Write-Info 'No server certificate was issued, so no binding was changed' 'Warn' }
    }
    else { Write-Info 'Server certificate skipped (-SkipServerCertificate)' 'Warn' }

    # --- 4. registry -------------------------------------------------------
    Write-Step 'Writing registry configuration'

    Import-RegistryTargets -Targets $targets
    $valueTotal = (@($targets | ForEach-Object { @($_.Values).Count } | Measure-Object -Sum).Sum)
    $keyTotal = (@($targets | ForEach-Object { $_.Key }) | Sort-Object -Unique).Count
    if ($WhatIfPreference) {
        Write-Info ("Would write {0} value(s) across {1} key(s)" -f $valueTotal, $keyTotal) 'Warn'
    }
    else {
        Write-Info ("Wrote {0} value(s) across {1} key(s)" -f $valueTotal, $keyTotal) 'Ok'
    }

    Set-NdesPostDeploymentState

    # --- 5. restart IIS ----------------------------------------------------
    Write-Step 'Restarting IIS'
    if ($PSCmdlet.ShouldProcess('IIS', 'Restart')) {
        & iisreset.exe /restart | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Info "iisreset returned $LASTEXITCODE" 'Warn' }
    }
    Start-Sleep -Seconds 3
    Write-Info 'IIS restarted' 'Ok'

    # A worker-process crash during earlier failed attempts can trip IIS
    # rapid-fail protection, which disables the pool and surfaces as HTTP 503.
    $poolListing = Invoke-AppCmd -Arguments @('list', 'apppool', $script:AppPoolName) -IgnoreExitCode
    if ($poolListing -match 'State:(\w+)') {
        $state = $Matches[1]
        Write-Info ("Application pool {0}: {1}" -f $script:AppPoolName, $state)
        if ($state -ne 'Started') {
            if ($PSCmdlet.ShouldProcess($script:AppPoolName, 'Start application pool')) {
                Invoke-AppCmd -Arguments @('start', 'apppool', $script:AppPoolName) -IgnoreExitCode | Out-Null
                Start-Sleep -Seconds 2
                $poolListing = Invoke-AppCmd -Arguments @('list', 'apppool', $script:AppPoolName) -IgnoreExitCode
                if ($poolListing -match 'State:(\w+)') { Write-Info ("Application pool {0}: {1}" -f $script:AppPoolName, $Matches[1]) 'Warn' }
            }
        }
    }

    if (Get-MscepValue -Config $config -Name 'MaxFieldLength') {
        Write-Info 'HTTP\Parameters limits are read by http.sys at start-up. iisreset does not restart http.sys - reboot before testing large SCEP requests.' 'Warn'
    }

    # --- 6. verify ---------------------------------------------------------
    # Two layers: the individual checks that say whether each step worked, then the
    # source-vs-target comparison that says whether the result is the same server.
    $stepFailures = Test-NdesConfiguration -ExpectedCA $caConfig -Targets $targets -Features @($config.Features) `
        -ServiceAccountCredential $ServiceAccountCredential -ServiceAccountName $account -UseGmsa:$isGmsa

    $remedy = @{
        Config            = $config
        Authentication    = $capturedAuthentication
        Account           = $account
        Secret            = $secret
        UseGmsa           = $isGmsa
        Targets           = $targets
        ServerCertificate = $serverCert
        EncryptionTemplate = $raEncryption
        SigningTemplate   = $raSigning
        RaSubject         = $raSubject
        Credential        = $ServiceAccountCredential
        EnrollmentPolicyUrl = $policyUrl
        CAConfig          = $caConfig
    }

    $drift = Compare-NdesTargetToBundle -Config $config -Account $account -CAConfig $caConfig

    if ($drift -gt 0) {
        Write-Step 'Repairing the differences'
        $applied = @(Invoke-DriftRemediation -Rows @($script:DriftReport) -Context $remedy -Auto:$FixDrift)
        if ($applied.Count -gt 0) {
            Write-Step 'Re-checking after the repair'
            $drift = Compare-NdesTargetToBundle -Config $config -Account $account -CAConfig $caConfig
        }
    }

    Write-Step 'Summary'
    if ($stepFailures -eq 0 -and $drift -eq 0) {
        Write-Info 'Restore complete; this server matches the bundle.' 'Ok'
        Write-Info 'Test a real enrolment with an OTP from mscep_admin.'
    }
    else {
        if ($stepFailures -gt 0) { Write-Info ("{0} configuration check(s) reported problems." -f $stepFailures) 'Warn' }
        if ($drift -gt 0) { Write-Info ("{0} difference(s) between this server and the bundle remain." -f $drift) 'Warn' }
        Write-Info 'Review the list above - each difference names the setting it concerns.' 'Warn'
    }
    Write-Info ("Log: {0}" -f $script:LogFile)
}

function Get-NdesEndpointResponse {
    <#
        One HTTP probe that returns a status code and the raw body, instead of
        throwing on every non-2xx. Both the status and the *content* matter here:
        a 200 whose body is a PE image is the "mscep.dll served as a file" failure,
        which no status-code check can see.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$TimeoutSec = 20,
        [switch]$UseDefaultCredentials,
        [System.Management.Automation.PSCredential]$Credential
    )

    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Method = 'GET'
    $request.Timeout = $TimeoutSec * 1000
    $request.AllowAutoRedirect = $true
    $request.UserAgent = 'NDESMigration'
    $request.KeepAlive = $false
    if ($Credential) { $request.Credentials = $Credential.GetNetworkCredential() }
    elseif ($UseDefaultCredentials) { $request.UseDefaultCredentials = $true }

    $response = $null
    try { $response = $request.GetResponse() }
    catch [System.Net.WebException] {
        if (-not $_.Exception.Response) { return $null }
        $response = $_.Exception.Response
    }

    try {
        $status = [int]$response.StatusCode
        $bytes = @()
        $stream = $response.GetResponseStream()
        if ($stream) {
            $buffer = New-Object System.IO.MemoryStream
            $stream.CopyTo($buffer)
            $bytes = $buffer.ToArray()
            $stream.Dispose(); $buffer.Dispose()
        }

        $isExecutable = ($bytes.Length -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A)
        $text = ''
        if (-not $isExecutable -and $bytes.Length -gt 0) {
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        }

        return [pscustomobject]@{
            StatusCode   = $status
            Bytes        = $bytes
            Text         = $text
            IsExecutable = $isExecutable
        }
    }
    finally { $response.Close() }
}

function New-DriftRow {
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Item,
        [AllowEmptyString()][string]$Source,
        [AllowEmptyString()][string]$Target,
        # Which repair applies to this row. Empty means nothing can be fixed
        # automatically and the row is reported only.
        [string]$Fix = ''
    )

    $status = if ($Source -eq $Target) { 'same' } elseif ([string]::IsNullOrEmpty($Target)) { 'missing' } else { 'DIFFERENT' }
    return [pscustomobject]@{ Area = $Area; Item = $Item; Source = $Source; Target = $Target; Status = $status; Fix = $Fix }
}

function Write-DriftLine {
    # Drift rows are printed straight, not through Write-Info: a 60-column table of
    # them is unreadable once every line carries a verdict prefix.
    param([Parameter(Mandatory)][string]$Line, [string]$Level = 'Same')

    $colour = switch ($Level) {
        'Diff' { 'Yellow' }
        'Area' { 'DarkCyan' }
        default { 'Gray' }
    }
    Write-Host $Line -ForegroundColor $colour
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $Line }
}

function Compare-NdesTargetToBundle {
    <#
        Reads the server's *effective* configuration back and compares it with the
        bundle, item by item. Everything here is read from the live machine -
        applicationHost.config, the registry, the certificate store, the feature
        list and the endpoints - not from what the restore believes it wrote.

        This exists because a restore can report success for every individual step
        and still produce a server that does not match its source: appcmd accepts
        settings that a locked section ignores, an application that "already
        exists" keeps its old values, and a feature that is skipped leaves the
        previous install's files behind. Comparing the two states is the only
        check that answers "is this server the same as the one I backed up?".
    #>
    param(
        [Parameter(Mandatory)]$Config,
        [string]$Account,
        [string]$CAConfig,
        [string]$AppHostPath
    )

    Write-Step 'Comparing this server with the bundle'

    $rows = New-Object System.Collections.Generic.List[object]
    $appHost = if ($AppHostPath) { $AppHostPath } else { Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config' }
    $generalPurposeTemplate = [string](Get-MscepValue -Config $Config -Name 'GeneralPurposeTemplate')

    # --- registry: every value the bundle recorded --------------------------
    foreach ($target in @($script:RegistryTargets)) {
        $captured = @(Get-BundleRegistryTargets -Config $Config) | Where-Object { $_.Key -eq $target.Key } | Select-Object -First 1
        if (-not $captured) { continue }
        $live = @(Export-RegistryTree -KeyPath (ConvertTo-PSPath -Key $target.Key))

        foreach ($value in @($captured.Values)) {
            $label = if ($value.Path) { '{0}\{1}' -f $value.Path, $value.Name } else { $value.Name }
            $found = $live | Where-Object { $_.Name -eq $value.Name -and ([string]$_.Path) -eq ([string]$value.Path) } | Select-Object -First 1

            # The CA differs per site. The three template values must all equal
            # GeneralPurposeTemplate - that is what the restore writes, and a target
            # whose EncryptionTemplate/SignatureTemplate name the enrolment
            # templates is the difference that breaks SCEP.
            $expected = [string]$value.Value
            if ($target.Key -match '\\Cryptography\\MSCEP$') {
                if ($value.Name -eq 'Configuration' -and $CAConfig) { $expected = $CAConfig }
                if ($generalPurposeTemplate -and ($value.Name -eq 'EncryptionTemplate' -or $value.Name -eq 'SignatureTemplate')) {
                    $expected = $generalPurposeTemplate
                }
            }

            $actual = if ($found) { [string]$found.Value } else { '' }
            $rows.Add((New-DriftRow -Area 'Registry' -Item ('{0} :: {1}' -f ($target.Key -replace '^HKEY_LOCAL_MACHINE\\', ''), $label) -Source $expected -Target $actual -Fix 'Registry'))
        }
    }

    # --- application pool ---------------------------------------------------
    $poolNode = $null
    if (Test-Path -LiteralPath $appHost) {
        try {
            [xml]$ah = Get-Content -LiteralPath $appHost -Raw
            $poolNode = $ah.SelectSingleNode("/configuration/system.applicationHost/applicationPools/add[@name='$($script:AppPoolName)']")
        }
        catch { }
    }
    $expectedPool = Get-OptionalProperty -Object $Config -Name 'AppPool'
    if ($expectedPool) {
        $rows.Add((New-DriftRow -Area 'AppPool' -Item 'name' -Source ([string]$expectedPool.Name) -Target $(if ($poolNode) { $script:AppPoolName } else { '' }) -Fix 'ApplicationPool'))
        foreach ($pair in @(
                @{ Item = 'managedRuntimeVersion'; XPath = 'managedRuntimeVersion'; Expected = [string]$expectedPool.ManagedRuntimeVersion },
                @{ Item = 'managedPipelineMode'; XPath = 'managedPipelineMode'; Expected = [string]$expectedPool.ManagedPipelineMode })) {
            $actual = ''
            if ($poolNode) { $actual = [string](Get-XmlAttr -Node $poolNode -Name $pair.XPath) }
            $rows.Add((New-DriftRow -Area 'AppPool' -Item $pair.Item -Source $pair.Expected -Target $actual -Fix 'ApplicationPool'))
        }
        $processModel = if ($poolNode) { $poolNode.SelectSingleNode('processModel') } else { $null }
        $identityType = if ($processModel) { [string](Get-XmlAttr -Node $processModel -Name 'identityType') } else { '' }
        $identityUser = if ($processModel) { [string](Get-XmlAttr -Node $processModel -Name 'userName') } else { '' }
        $rows.Add((New-DriftRow -Area 'AppPool' -Item 'identityType' -Source ([string]$expectedPool.IdentityType) -Target $identityType -Fix 'ApplicationPool'))
        $rows.Add((New-DriftRow -Area 'AppPool' -Item 'userName' -Source ([string]$expectedPool.UserName) -Target $identityUser -Fix 'ApplicationPool'))
    }

    # --- applications and their per-application IIS settings ----------------
    foreach ($app in @($Config.Applications)) {
        $appPath = [string]$app.Path
        $exists = Test-IisApplication -Path $appPath
        $rows.Add((New-DriftRow -Area 'IIS' -Item ('{0} :: application' -f $appPath) -Source 'present' -Target $(if ($exists) { 'present' } else { '' }) -Fix 'Applications'))

        $expectedPhysical = [string]$app.PhysicalPath
        $expectedPoolName = [string]$app.AppPool
        $actualPhysical = ''; $actualPool = ''
        if ($exists -and (Test-Path -LiteralPath $appHost)) {
            try {
                [xml]$ah2 = Get-Content -LiteralPath $appHost -Raw
                $appNode = $ah2.SelectSingleNode("/configuration/system.applicationHost/sites/site[@name='$($script:SiteName)']/application[@path='$appPath']")
                if ($appNode) {
                    $actualPool = [string](Get-XmlAttr -Node $appNode -Name 'applicationPool')
                    $vdir = $appNode.SelectSingleNode('virtualDirectory')
                    if ($vdir) { $actualPhysical = [string](Get-XmlAttr -Node $vdir -Name 'physicalPath') }
                }
            }
            catch { }
        }
        $rows.Add((New-DriftRow -Area 'IIS' -Item ('{0} :: physicalPath' -f $appPath) -Source $expectedPhysical -Target $actualPhysical -Fix 'Applications'))
        $rows.Add((New-DriftRow -Area 'IIS' -Item ('{0} :: applicationPool' -f $appPath) -Source $expectedPoolName -Target $actualPool -Fix 'Applications'))

        # The four settings that decide whether the ISAPI runs and who can reach it.
        $effective = Get-IisApplicationIisSettings -ConfigPath $appHost -SiteName $script:SiteName -AppPath $appPath
        $defaults = $script:ApplicationIisDefaults[$appPath]

        $expectedAnonymous = Get-OptionalProperty -Object $app -Name 'Anonymous'
        if ($null -eq $expectedAnonymous) { $expectedAnonymous = $defaults.Anonymous }
        $actualAnonymous = if ($null -ne $effective.Anonymous) { ([bool]$effective.Anonymous).ToString().ToLower() } else { '' }
        $actualWindows = if ($null -ne $effective.Windows) { ([bool]$effective.Windows).ToString().ToLower() } else { '' }
        $actualDoubleEscaping = if ($null -ne $effective.AllowDoubleEscaping) { ([bool]$effective.AllowDoubleEscaping).ToString().ToLower() } else { '' }
        $actualDefaultDocument = if ($effective.DefaultDocuments -contains 'mscep.dll') { 'true' } else { 'false' }

        $rows.Add((New-DriftRow -Area 'IIS' -Item ('{0} :: anonymous' -f $appPath) -Source ([bool]$expectedAnonymous).ToString().ToLower() -Target $actualAnonymous -Fix 'ApplicationSettings'))
        $rows.Add((New-DriftRow -Area 'IIS' -Item ('{0} :: windows' -f $appPath) -Source ([bool]$defaults.Windows).ToString().ToLower() -Target $actualWindows -Fix 'ApplicationSettings'))

        # accessPolicy is reported as Execute-present/absent: the exact text is not
        # the point, whether it allows the ISAPI to run is.
        $targetPolicy = if ($effective.AccessPolicy) { $effective.AccessPolicy } else { '' }
        $rows.Add([pscustomobject]@{
                Area   = 'IIS'
                Item   = ('{0} :: handlers accessPolicy' -f $appPath)
                Source = 'Read, Execute'
                Target = $targetPolicy
                Status = if ($targetPolicy -match '(?i)\bExecute\b') { 'same' } elseif (-not $targetPolicy) { 'missing' } else { 'DIFFERENT' }
                Fix    = 'ApplicationSettings'
            })

        $rows.Add((New-DriftRow -Area 'IIS' -Item ('{0} :: allowDoubleEscaping' -f $appPath) -Source 'true' -Target $actualDoubleEscaping -Fix 'ApplicationSettings'))
        $rows.Add((New-DriftRow -Area 'IIS' -Item ('{0} :: default document mscep.dll' -f $appPath) -Source 'true' -Target $actualDefaultDocument -Fix 'ApplicationSettings'))
    }

    # --- ISAPI restriction and application dependency ----------------------
    $isapiXml = Get-AppCmdXml -Arguments @('list', 'config', '-section:system.webServer/security/isapiCgiRestriction')
    $isapiAllowed = $false
    $isapiGroupId = ''
    if ($isapiXml) {
        foreach ($node in $isapiXml.SelectNodes('//add')) {
            if ([string](Get-XmlAttr -Node $node -Name 'path') -eq $script:MscepDll) {
                $isapiAllowed = ([string](Get-XmlAttr -Node $node -Name 'allowed') -eq 'true')
                $isapiGroupId = [string](Get-XmlAttr -Node $node -Name 'groupId')
            }
        }
    }
    $rows.Add((New-DriftRow -Area 'IIS' -Item 'ISAPI restriction mscep.dll allowed' -Source 'true' -Target $(if ($isapiAllowed) { 'true' } else { 'false' }) -Fix 'Isapi'))
    $rows.Add((New-DriftRow -Area 'IIS' -Item 'ISAPI restriction groupId' -Source 'mscep.dll' -Target $isapiGroupId -Fix 'Isapi'))

    $dependencies = Invoke-AppCmd -Arguments @('list', 'config', '-section:system.webServer/security/applicationDependencies') -IgnoreExitCode
    $dependencyTarget = if ($dependencies -match 'MSCEP') { 'present' } else { '' }
    $rows.Add((New-DriftRow -Area 'IIS' -Item 'application dependency MSCEP/mscep.dll' -Source 'present' -Target $dependencyTarget -Fix 'Isapi'))

    # --- handler order ------------------------------------------------------
    $order = $null
    if (Test-Path -LiteralPath $appHost) {
        $lines = @(Get-Content -LiteralPath $appHost)
        $order = Get-IisHandlerOrderFix -Lines $lines
    }
    $rows.Add([pscustomobject]@{
            Area   = 'IIS'
            Item   = 'handler order (ISAPI-dll < StaticFile < Extensionless)'
            Source = 'correct'
            Target = if ($null -eq $order) { '' } elseif ($order.Changed) { 'needs normalising' } else { 'correct' }
            Status = if ($null -eq $order) { 'missing' } elseif ($order.Changed) { 'DIFFERENT' } else { 'same' }
            Fix    = 'HandlerOrder'
        })

    # --- features -----------------------------------------------------------
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $installed = @(Get-WindowsFeature -ErrorAction SilentlyContinue |
            Where-Object { $_.InstallState -eq 'Installed' } | ForEach-Object { $_.Name })
        $required = @($script:RequiredFeatures)
        foreach ($name in $required) {
            $presence = Get-FeaturePresence -Name $name
            if ($installed -contains $name -or $presence.Installed) {
                # "installed but not listed" is a stale cache, not a difference:
                # the feature works, and the first comparison would otherwise
                # report drift on every run and offer to reinstall it forever.
                $how = if ($installed -contains $name) { 'Installed' } else { 'Installed (not listed by Get-WindowsFeature)' }
                $rows.Add([pscustomobject]@{
                        Area   = 'Features'
                        Item   = $name
                        Source = 'Installed'
                        Target = $how
                        Status = 'same'
                        Fix    = ''
                    })
            }
            else {
                $rows.Add((New-DriftRow -Area 'Features' -Item $name -Source 'Installed' -Target 'not installed' -Fix 'Features'))
            }
        }
        $expectedFeatures = @(@(Get-OptionalProperty -Object $Config -Name 'Features') + $script:BaselineFeatures |
            Where-Object { $_ } | Sort-Object -Unique)
        $missing = @($expectedFeatures | Where-Object {
                if ($installed -contains $_) { return $false }
                return (-not (Get-FeaturePresence -Name $_).Installed)
            })
        $rows.Add([pscustomobject]@{
                Area   = 'Features'
                Item   = ('bundle feature set ({0})' -f $expectedFeatures.Count)
                Source = 'all installed'
                Target = if ($missing.Count -eq 0) { 'all installed' } else { 'missing: ' + ($missing -join ', ') }
                Status = if ($missing.Count -eq 0) { 'same' } else { 'DIFFERENT' }
                Fix    = 'Features'
            })
    }

    # --- HTTPS binding and certificate --------------------------------------
    $binding = Invoke-AppCmd -Arguments @('list', 'site', $script:SiteName) -IgnoreExitCode
    $hasHttps = ($binding -match 'https/\*:443')
    $rows.Add((New-DriftRow -Area 'Binding' -Item 'https *:443' -Source 'present' -Target $(if ($hasHttps) { 'present' } else { '' }) -Fix 'Binding'))
    $ssl = (& netsh http show sslcert 2>&1 | Out-String)
    $sslTarget = if ($ssl -match '0\.0\.0\.0:443') { 'present' } else { '' }
    $rows.Add((New-DriftRow -Area 'Binding' -Item 'certificate bound to 0.0.0.0:443' -Source 'present' -Target $sslTarget -Fix 'Binding'))

    # --- RA certificates ----------------------------------------------------
    $ra = @(Get-RaCertificates)
    $expectedSubject = ''
    if ($Config) {
        $recordedSubject = Get-OptionalProperty -Object $Config -Name 'RACertificateSubject'
        if ($recordedSubject) { $expectedSubject = [string]$recordedSubject }
    }

    # NDES needs one encryption and one signing certificate. More than that means a
    # previous enrolment left certificates behind, and NDES publishes whichever it
    # selects in GetCACert - so a device is offered a certificate the source server
    # never had. That is the difference worth repairing.
    $countRow = New-DriftRow -Area 'Certificates' -Item 'RA certificates (one encryption, one signing)' -Source '2' -Target ([string]$ra.Count)
    if ($ra.Count -ne 2) { $countRow.Fix = 'RaCertificates' }
    $rows.Add($countRow)

    # A differing subject is reported, not repaired, and not counted as drift: a
    # machine-type template builds the subject from Active Directory and ignores
    # what the requester supplies, so this cannot be fixed from here - and the
    # certificate is still a usable RA certificate.
    if ($expectedSubject) {
        $strays = @($ra | Where-Object { $_.Subject -ne $expectedSubject })
        if ($strays.Count -gt 0) {
            Write-Info ('{0} RA certificate(s) have a subject other than "{1}": {2}' -f `
                    $strays.Count, $expectedSubject, (($strays | ForEach-Object { $_.Subject } | Sort-Object -Unique) -join ', ')) 'Warn'
            Write-Info 'That is the template, not the restore: a machine template builds the subject from Active Directory. The certificate still works for NDES; it only differs from the source.' 'Warn'
        }
    }

    foreach ($certificate in $ra) {
        $keyTarget = if ($certificate.HasPrivateKey) { 'true' } else { 'false' }
        $rows.Add((New-DriftRow -Area 'Certificates' -Item ('{0} {1} private key readable' -f $certificate.Thumbprint.Substring(0, 8), $certificate.Subject) -Source 'true' -Target $keyTarget))
    }

    # --- endpoints: the only checks that prove the ISAPI actually runs ------
    $caps = Get-NdesEndpointResponse -Uri ('http://localhost{0}/mscep.dll?operation=GetCACaps' -f $script:AppPaths[0])
    $capsTarget = 'no response'
    $capsStatus = 'missing'
    if ($caps) {
        if ($caps.IsExecutable) {
            # The DLL answered - which means IIS served it instead of running it.
            $capsTarget = 'mscep.dll served as a file'
            $capsStatus = 'DIFFERENT'
            $rows.Add((New-DriftRow -Area 'Endpoint' -Item '/CertSrv/mscep anonymous GetCACaps' -Source 'isapi executed' -Target 'mscep.dll served as a file'))
        }
        elseif ($caps.StatusCode -eq 401) {
            $capsTarget = 'HTTP 401'
            $capsStatus = 'DIFFERENT'
        }
        elseif ($caps.StatusCode -eq 200 -and $caps.Text -match '(?i)POSTPKIOperation|Renewal|SHA-') {
            $capsTarget = 'HTTP 200 with capabilities'
            $capsStatus = 'same'
        }
        else {
            $capsTarget = ('HTTP {0}' -f $caps.StatusCode)
            $capsStatus = 'DIFFERENT'
        }
    }
    $rows.Add([pscustomobject]@{
            Area = 'Endpoint'; Item = '/CertSrv/mscep anonymous GetCACaps'
            Source = 'HTTP 200 with capabilities'; Target = $capsTarget; Status = $capsStatus; Fix = 'IIS'
        })

    $adminAnonymous = Get-NdesEndpointResponse -Uri ('http://localhost{0}/' -f $script:AppPaths[1])
    $adminAnonymousTarget = 'no response'
    if ($null -ne $adminAnonymous) {
        if ($adminAnonymous.IsExecutable) { $adminAnonymousTarget = 'mscep.dll served as a file' }
        else { $adminAnonymousTarget = ('HTTP {0}' -f $adminAnonymous.StatusCode) }
    }
    $adminAnonymousStatus = 'DIFFERENT'
    if ($null -ne $adminAnonymous -and -not $adminAnonymous.IsExecutable -and
        (@(401, 403) -contains $adminAnonymous.StatusCode)) { $adminAnonymousStatus = 'same' }
    $rows.Add([pscustomobject]@{
            Area   = 'Endpoint'
            Item   = '/CertSrv/mscep_admin anonymous'
            Source = 'HTTP 401'
            Target = $adminAnonymousTarget
            Status = $adminAnonymousStatus
            Fix    = 'IIS'
        })

    $admin = Get-NdesEndpointResponse -Uri ('http://localhost{0}/' -f $script:AppPaths[1]) -UseDefaultCredentials
    $adminTarget = 'no response'
    $adminStatus = 'missing'
    if ($admin) {
        if ($admin.IsExecutable) { $adminTarget = 'mscep.dll served as a file'; $adminStatus = 'DIFFERENT' }
        elseif ($admin.StatusCode -eq 200 -and $admin.Text -match '(?i)password') { $adminTarget = 'HTTP 200 password page'; $adminStatus = 'same' }
        else { $adminTarget = ('HTTP {0}' -f $admin.StatusCode); $adminStatus = 'DIFFERENT' }
    }
    $rows.Add([pscustomobject]@{
            Area = 'Endpoint'; Item = '/CertSrv/mscep_admin authenticated'
            Source = 'HTTP 200 password page'; Target = $adminTarget; Status = $adminStatus; Fix = 'IIS'
        })

    # --- report -------------------------------------------------------------
    $different = @($rows | Where-Object { $_.Status -ne 'same' })
    $width = ($rows | ForEach-Object { $_.Item.Length } | Measure-Object -Maximum).Maximum
    if ($width -lt 20) { $width = 20 }
    if ($width -gt 56) { $width = 56 }

    $area = ''
    foreach ($row in $rows) {
        if ($row.Area -ne $area) {
            $area = $row.Area
            Write-DriftLine ('  -- {0}' -f $area) 'Area'
        }

        $marker = switch ($row.Status) { 'same' { '  ' } 'missing' { '! ' } default { '~ ' } }
        $item = $row.Item
        if ($item.Length -gt $width) { $item = $item.Substring(0, $width - 3) + '...' }
        $detail = if ($row.Status -eq 'same') {
            $row.Target
        }
        elseif ($row.Status -eq 'missing') {
            'source={0} ; this server has nothing' -f $row.Source
        }
        else {
            'source={0} ; this server={1}' -f $row.Source, $row.Target
        }

        $level = if ($row.Status -eq 'same') { 'Same' } else { 'Diff' }
        Write-DriftLine ('   {0}{1}  {2}' -f $marker, $item.PadRight($width), $detail) $level
    }

    $summary = '{0} comparison(s): {1} match, {2} differ' -f $rows.Count, ($rows.Count - $different.Count), $different.Count
    Write-DriftLine ('   ' + $summary) $(if ($different.Count -eq 0) { 'Same' } else { 'Diff' })
    if ($different.Count -gt 0) {
        Write-Info 'A difference means this server is not the same as the source. Fix the listed items, or re-run -Restore and read the step that owns them.' 'Warn'
        Write-Info '  !  = the setting is missing   ~  = the setting is present but different' 'Warn'
        $script:DriftReport = $different
    }
    else { $script:DriftReport = @() }

    return $different.Count
}

function Invoke-DriftRemediation {
    <#
        Offers to repair the differences the comparison found, one repair at a
        time, naming what each one covers. Nothing is changed without a yes
        (or -Auto), because the operator is the only one who can say whether a
        difference is drift to correct or a deliberate local choice.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Rows,
        [Parameter(Mandatory)][hashtable]$Context,
        [switch]$Auto
    )

    $fixable = @($Rows | Where-Object { $_.Fix })
    $unfixable = @($Rows | Where-Object { -not $_.Fix })
    if ($unfixable.Count -gt 0) {
        Write-Info ('{0} difference(s) have no automatic repair:' -f $unfixable.Count) 'Warn'
        foreach ($row in $unfixable) { Write-Info ('  {0}' -f $row.Item) 'Warn' }
    }
    if ($fixable.Count -eq 0) { return @() }

    $applied = @()
    $needsIisRestart = $false

    foreach ($group in ($fixable | Group-Object Fix)) {
        $fix = $group.Name
        $items = @($group.Group | ForEach-Object { $_.Item })

        $description = switch ($fix) {
            'Registry' { 'write the registry values the bundle recorded' }
            'ApplicationPool' { 'rewrite the SCEP application pool' }
            'Applications' { 'recreate the SCEP applications' }
            'ApplicationSettings' { 'rewrite the per-application IIS settings' }
            'Isapi' { 're-register the SCEP ISAPI extension and its application dependency' }
            'HandlerOrder' { 'normalise the IIS handler order' }
            'Features' { 'install the missing roles and features' }
            'RaCertificates' { 'remove RA certificates whose subject is not the one in the bundle' }
            'Binding' { 'recreate the HTTPS binding and its certificate binding' }
            'IIS' { 'rewrite the SCEP IIS configuration and restart IIS' }
            default { $fix }
        }

        Write-Host ''
        Write-Info ('{0} difference(s): {1}' -f $items.Count, ($items -join '; ')) 'Warn'

        $go = [bool]$Auto
        if (-not $Auto) {
            $answer = Read-Host ('  {0}? [Y/n] ' -f $description)
            $go = ($answer -notmatch '^(?i)\s*n')
        }

        if (-not $go) {
            Write-Info ('left unchanged: {0}' -f $description) 'Warn'
            continue
        }

        try {
            switch ($fix) {
                'Registry' { Import-RegistryTargets -Targets $Context.Targets }
                'ApplicationPool' {
                    Set-NdesApplicationPool -AppPool $Context.Config.AppPool -Account $Context.Account -Password $Context.Secret -UseGmsa:$Context.UseGmsa
                    $needsIisRestart = $true
                }
                'Applications' {
                    # Recreating is the only way to change a physical path or pool:
                    # appcmd will not move an application, and Set-NdesApplications
                    # deliberately leaves existing ones alone.
                    foreach ($app in @($Context.Config.Applications)) {
                        if (Test-IisApplication -Path $app.Path) {
                            Invoke-AppCmd -Arguments @('delete', 'app', ('{0}{1}' -f $script:SiteName, $app.Path)) -IgnoreExitCode | Out-Null
                        }
                    }
                    Set-NdesApplications -Applications $Context.Config.Applications
                    $needsIisRestart = $true
                }
                'ApplicationSettings' {
                    Set-NdesApplicationSettings -Applications $Context.Config.Applications -Authentication $Context.Authentication
                    $needsIisRestart = $true
                }
                'Isapi' {
                    Set-NdesIsapiRegistration
                    $needsIisRestart = $true
                }
                'HandlerOrder' {
                    Set-NdesHandlerOrder
                    $needsIisRestart = $true
                }
                'Features' { Install-NdesFeatures -Features @($Context.Config.Features) }
                'RaCertificates' {
                    # Reset rather than prune: with duplicates and certificates from
                    # templates this run did not use, there is no way to tell which
                    # two NDES should keep. Removing all of them and enrolling one
                    # per role leaves exactly the set the source has.
                    $existing = @(Get-RaCertificates)
                    foreach ($certificate in $existing) {
                        Write-Info ('Removing {0} ({1})' -f $certificate.Subject, $certificate.Thumbprint)
                        Remove-Item -LiteralPath $certificate.PSPath -Force
                    }
                    Write-Info ('Removed {0} RA certificate(s); enrolling one per role' -f $existing.Count) 'Ok'
                    Install-NdesRaCertificates -EncryptionTemplate $Context.EncryptionTemplate `
                        -SigningTemplate $Context.SigningTemplate -Subject $Context.RaSubject `
                        -Credential $Context.Credential -EnrollmentPolicyUrl $Context.EnrollmentPolicyUrl `
                        -GrantKeyReadTo $Context.Account -CAConfig $Context.CAConfig
                    $needsIisRestart = $true
                }
                'Binding' {
                    if ($Context.ServerCertificate) { Set-NdesSiteBinding -Certificate $Context.ServerCertificate }
                    else { Write-Info 'No server certificate is available in this run; re-run without -SkipServerCertificate to recreate the binding.' 'Warn' }
                }
                'IIS' {
                    Set-NdesApplicationSettings -Applications $Context.Config.Applications -Authentication $Context.Authentication
                    Set-NdesIsapiRegistration
                    Set-NdesHandlerOrder
                    $needsIisRestart = $true
                }
            }
            Write-Info ('applied: {0}' -f $description) 'Ok'
            $applied += $fix
        }
        catch {
            Write-Info ('{0} failed: {1}' -f $description, $_.Exception.Message) 'Warn'
        }
    }

    if ($needsIisRestart -and $applied.Count -gt 0) {
        Write-Info 'Restarting IIS to apply the changes above'
        & iisreset.exe /restart | Out-Null
        Start-Sleep -Seconds 3
    }

    return $applied
}

function Get-RaCertificates {
    <#
        NDES's RA certificates in the machine store, identified the way NDES
        identifies them rather than by subject.

        A subject filter is not enough: a certificate enrolled from a template that
        builds its subject from Active Directory is named after the computer
        (CN=ndes.contoso.com), and filtering on "MSCEP-RA" then misses it
        entirely - so the one certificate that differs from the source is the one
        that stays invisible.
    #>
    param([string]$StorePath = 'Cert:\LocalMachine\My')

    if (-not (Test-Path -Path $StorePath)) { return @() }

    return @(Get-ChildItem -Path $StorePath -ErrorAction SilentlyContinue | Where-Object {
            if ($_.Subject -match 'MSCEP-RA') { return $true }
            foreach ($extension in $_.Extensions) {
                if ($extension.Oid.Value -ne '2.5.29.37') { continue }
                $eku = $extension -as [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
                if (-not $eku) { continue }
                foreach ($usage in $eku.EnhancedKeyUsages) {
                    if ($usage.Value -eq '1.3.6.1.4.1.311.20.2.1') { return $true }
                }
            }
            return $false
        })
}

function Test-CaConnectivity {
    <#
        Proves the NDES server can actually talk to the CA, as a given identity.

        Port 135 being open proves only that the endpoint mapper answers. mscep.dll
        imports certcli.dll and certca.dll and talks to the CA over DCOM, which
        needs a dynamic port range as well - and when that call fails it renders
        "You do not have sufficient permission to enroll with SCEP", a message that
        describes neither the real failure nor the identity that hit it.

        certutil -ping performs the same RPC round trip NDES needs, so it answers the
        question directly: as the current user, and - when a credential is supplied -
        in that account's own logon session.
    #>
    param(
        [Parameter(Mandatory)][string]$CAConfig,
        [System.Management.Automation.PSCredential]$Credential
    )

    $certutil = Join-Path $env:SystemRoot 'System32\certutil.exe'
    if (-not (Test-Path -LiteralPath $certutil)) {
        return [pscustomobject]@{ Identity = 'current user'; Ok = $null; Detail = 'certutil.exe not found' }
    }

    $identity = 'current user'
    if ($Credential) { $identity = $Credential.UserName }

    $result = [pscustomobject]@{ Identity = $identity; Ok = $false; Detail = '' }

    if (-not $Credential) {
        $output = & $certutil -ping -config $CAConfig 2>&1 | Out-String
        $result.Ok = ($LASTEXITCODE -eq 0)
        $result.Detail = if ($result.Ok) { 'certutil -ping succeeded' }
        else { ((($output -split "`r?`n") | Where-Object { $_ -match '\S' } | Select-Object -Last 3) -join ' | ') }
        return $result
    }

    # A credential means the call has to run in that account's own session:
    # Start-Process -Credential is the only supported way to do that from
    # PowerShell, so the output goes through temporary files.
    $outFile = Join-Path $env:TEMP ('ca-ping-{0}.out' -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $errFile = "$outFile.err"
    try {
        $process = Start-Process -FilePath $certutil -ArgumentList @('-ping', '-config', $CAConfig) `
            -Credential $Credential -WindowStyle Hidden -Wait -PassThru `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile -ErrorAction Stop
        $result.Ok = ($process.ExitCode -eq 0)
        $text = ''
        foreach ($file in $outFile, $errFile) {
            if (Test-Path -LiteralPath $file) { $text += (Get-Content -LiteralPath $file -Raw) }
        }
        $result.Detail = if ($result.Ok) { 'certutil -ping succeeded' }
        else { ((($text -split "`r?`n") | Where-Object { $_ -match '\S' } | Select-Object -Last 3) -join ' | ') }
    }
    catch {
        $result.Detail = $_.Exception.Message
    }
    finally {
        foreach ($file in $outFile, $errFile) {
            if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
        }
    }

    return $result
}

function Get-MscepEventLogTail {
    <#
        Recent MSCEP/NDES events from the Application log.

        mscep.dll records why it refused a request there (EVENT_MSCEP_NO_PASSWORD,
        EVENT_MSCEP_INVALID_USAGE_FOR_PASSWORD, EVENT_MSCEP_FAILED_DECRYPT_PASSWORD
        and friends), and the admin page itself only says "You do not have
        sufficient permission to enroll with SCEP" - which names no cause. The
        event is the cause.
    #>
    param([int]$MaxEvents = 60, [int]$Count = 8)

    try {
        $events = Get-WinEvent -LogName Application -MaxEvents $MaxEvents -ErrorAction Stop |
            Where-Object { $_.ProviderName -match '(?i)MSCEP|NDES|Certificate Services' }
    }
    catch { return @() }

    return @($events | Select-Object -First $Count | ForEach-Object {
            [pscustomobject]@{ TimeCreated = $_.TimeCreated; Level = $_.LevelDisplayName; Provider = $_.ProviderName; Id = $_.Id; Message = ($_.Message -split "`r?`n")[0] }
        })
}

function Write-MscepAdminHint {
    <#
        What to check when mscep_admin answers 200 without a password.

        This page fails for a reason, but it renders the same sentence whatever the
        reason is, so the checks below are ordered by how often they are the answer.
        The caller's own group membership is first because it is the only one that
        can be settled from the client side.
    #>
    param([string]$PageText = '')

    if ($PageText -match '(?i)sufficient permission') {
        Write-Info 'The page says "You do not have sufficient permission to enroll with SCEP".' 'Warn'
    }

    Write-Info 'Checks, in the order they usually matter:' 'Warn'
    Write-Info '  1. The CALLER must be a local Administrator on the NDES server (mscep_admin mints passwords only for administrators).' 'Warn'
    Write-Info ('     whoami /groups | findstr /i "S-1-5-32-544"   -- on the account you are authenticating as') 'Warn'
    Write-Info '  2. NDES must be able to read its RA certificates, and they must both exist: one signing (Certificate Request Agent EKU)' 'Warn'
    Write-Info '     and one encryption. The app pool identity needs Read on their private keys.' 'Warn'
    Write-Info ('     Get-ChildItem Cert:\LocalMachine\My | Where Subject -match "MSCEP-RA" | Select Subject,Thumbprint,HasPrivateKey') 'Warn'
    Write-Info '     MSCEP EncryptionTemplate/SignatureTemplate are NOT what picks these up: on a working server they still say NDESUser.' 'Warn'
    Write-Info '  3. The service account needs "Request Certificates" on the CA, and the CA must be reachable from this server.' 'Warn'

    # @() around the call: a single event comes back unwrapped, and under
    # Set-StrictMode a PSCustomObject has no .Count.
    $events = @(Get-MscepEventLogTail)
    if ($events.Count -gt 0) {
        Write-Info 'Recent MSCEP/AD CS events on this server:' 'Warn'
        foreach ($event in $events) {
            Write-Info ('  {0:HH:mm:ss} [{1}] {2} {3}: {4}' -f $event.TimeCreated, $event.Level, $event.Provider, $event.Id, $event.Message) 'Warn'
        }
    }
    else {
        Write-Info 'No MSCEP or AD CS events in the Application log - if the page failed, nothing was recorded, which itself suggests the request was refused before NDES ran.' 'Warn'
    }

    Write-Info 'In IIS, check the response for /certsrv/mscep_admin/ directly: the page body carries the whole message, and -SaveAdminPage keeps it.' 'Warn'
}

function Test-FeatureParity {
    <#
        Reports how the target's feature set differs from the one the bundle
        describes.

        Missing features are a restore defect and are counted as failures. Extra AD
        CS role services are counted too, because they change what the host is: the
        CA role service installed but unconfigured is exactly what keeps Server
        Manager offering post-deployment configuration, and it is what a rebuild
        picks up when something other than this script ran on the box (the AD CS
        configuration wizard installs it). Nothing is uninstalled automatically -
        only the operator can say whether an extra role service is wanted.
    #>
    param(
        [AllowEmptyCollection()][string[]]$Expected = @(),
        # Features installed on purpose that the reference build does not have, so
        # they are not reported as over-installation.
        [AllowEmptyCollection()][string[]]$AllowExtra = @()
    )

    if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) { return 0 }

    $failures = 0
    $wanted = @(@($Expected) + $script:BaselineFeatures | Where-Object { $_ } | Sort-Object -Unique)
    $installed = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.InstallState -eq 'Installed' })
    $installedNames = @($installed | ForEach-Object { $_.Name })

    $missing = @($wanted | Where-Object { $installedNames -notcontains $_ })
    if ($missing.Count -gt 0) {
        # A role service can be installed and absent from the enumeration at the
        # same time; only the machine's own evidence settles it.
        $reallyInstalled = @($missing | Where-Object { (Get-FeaturePresence -Name $_).Installed })
        $missing = @($missing | Where-Object { $reallyInstalled -notcontains $_ })
        foreach ($name in $reallyInstalled) {
            Write-Info ('Features absent from Get-WindowsFeature but installed on disk: {0} (Server Manager cache entry is stale - the restore refreshes it)' -f $name) 'Warn'
            Restore-NdesRoleServiceCacheEntry -RoleService $name
        }
    }
    if ($missing.Count -gt 0) {
        Write-Info ('Features expected but not installed: {0}' -f ($missing -join ', ')) 'Warn'
        $failures += $missing.Count
    }
    else {
        Write-Info ('Feature parity: all {0} requested feature(s) installed' -f $wanted.Count) 'Ok'
    }

    $unexpected = @($installedNames | Where-Object { $_ -like 'ADCS-*' -and $wanted -notcontains $_ })
    if ($unexpected.Count -gt 0) {
        Write-Info ('AD CS role services installed but not expected: {0}' -f ($unexpected -join ', ')) 'Warn'
        if ($unexpected -contains 'ADCS-Cert-Authority') {
            Write-Info 'ADCS-Cert-Authority is the CA role service. The documented NDES installation clears the Certification Authority check box and selects only Network Device Enrollment Service, so a precise install never creates it. Installed and unconfigured it is also what keeps the Server Manager post-deployment tile showing.' 'Warn'
        }
        $failures += $unexpected.Count
    }

    # These only appear when a parent feature is requested (or when the box was
    # built by hand): the reference build has none of them. Reported, not counted
    # - they may pre-date the restore.
    $overInstalled = @($installedNames | Where-Object {
            $script:OverInstallIndicators -contains $_ -and $unexpected -notcontains $_ -and $AllowExtra -notcontains $_
        })
    if ($overInstalled.Count -gt 0) {
        Write-Info ('Features the reference build does not have: {0}' -f ($overInstalled -join ', ')) 'Warn'
        Write-Info 'Each of these is a default child of a parent feature (AD-Certificate, RSAT, RSAT-ADCS, NET-WCF-Services45, Web-Mgmt-Tools/Compat). Requesting the parent installs the whole group; requesting the leaves installs only what is needed. Remove the parent from the bundle feature list, or uninstall these by hand.' 'Warn'
    }

    $allowed = @($installedNames | Where-Object { $AllowExtra -contains $_ })
    if ($allowed.Count -gt 0) {
        Write-Info ('Installed by this run and expected here: {0} (the gMSA path needs the ActiveDirectory module)' -f ($allowed -join ', ')) 'Ok'
    }

    return $failures
}

function Test-NdesConfiguration {
    param(
        [string]$ExpectedCA,
        $Targets,
        [AllowEmptyCollection()][string[]]$Features = @(),
        [System.Management.Automation.PSCredential]$ServiceAccountCredential,
        [string]$ServiceAccountName,
        [switch]$UseGmsa
    )

    Write-Step 'Verifying configuration'
    $failures = 0

    # MSCEP values (nested layout - search the whole tree by value name)
    $tree = @(Export-RegistryTree -KeyPath $script:MSCEPKeyPath)
    $required = 'Configuration', 'CAType', 'CertsInMYStore', 'SignatureTemplate', 'EncryptionTemplate'
    foreach ($name in $required) {
        $entry = $tree | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $entry -or [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            Write-Info ("MSCEP value '{0}' is missing" -f $name) 'Warn'
            $failures++
        }
        else {
            $where = if ($entry.Path) { "MSCEP\$($entry.Path)\$name" } else { "MSCEP\$name" }
            Write-Info ("{0} = {1}" -f $where, $entry.Value) 'Ok'
        }
    }

    # Remaining registry targets (ADCS\NDES, HTTP\Parameters) must read back
    # exactly as captured. Configuration is excluded - it is deliberately
    # replaced with the target's own CA.
    if ($Targets) {
        foreach ($target in @($Targets)) {
            $psPath = ConvertTo-PSPath -Key $target.Key
            $checked = 0
            foreach ($want in @($target.Values)) {
                if ($null -eq $want -or $want.Name -eq 'Configuration') { continue }
                $probe = if ($want.Path) { Join-Path $psPath $want.Path } else { $psPath }
                $label = '{0}\{1}' -f $target.Key, $(if ($want.Path) { "$($want.Path)\" } else { '' }) + $want.Name
                if (-not (Test-Path -LiteralPath $probe)) {
                    Write-Info ("{0} is missing" -f $label) 'Warn'; $failures++; continue
                }
                $key = Get-Item -LiteralPath $probe
                $raw = $key.GetValue($want.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($null -eq $raw) { Write-Info ("{0} is missing" -f $label) 'Warn'; $failures++; continue }

                $actual = if ($want.Kind -in 'DWord', 'QWord') { [string][int64]$raw }
                elseif ($want.Kind -eq 'MultiString') { (@($raw) -join ';') }
                else { [string]$raw }
                $expected = if ($want.Kind -eq 'MultiString') { (@($want.Value) -join ';') } else { [string]$want.Value }

                if ($actual -ne $expected) { Write-Info ("{0} = {1}, expected {2}" -f $label, $actual, $expected) 'Warn'; $failures++ }
                else { Write-Info ("{0} = {1}" -f $label, $actual) 'Ok' }
                $checked++
            }
            if ($checked -eq 0) { Write-Info ("{0}: nothing to verify" -f $target.Key) 'Warn' }
        }
    }

    # RA certificates
    $ra = @(Get-RaCertificates)
    if ($ra.Count -ge 2) { Write-Info ("RA certificates: {0}" -f $ra.Count) 'Ok' }
    else { Write-Info ("RA certificates: found {0}, expected 2" -f $ra.Count) 'Warn'; $failures++ }
    $oddSubjects = @($ra | Where-Object { $_.Subject -notmatch 'MSCEP-RA' })
    if ($oddSubjects.Count -gt 0) {
        Write-Info ('{0} RA certificate(s) carry a subject other than MSCEP-RA ({1}); GetCACert publishes whichever NDES selects, so a device sees that name' -f `
                $oddSubjects.Count, (($oddSubjects | ForEach-Object { $_.Subject } | Sort-Object -Unique) -join ', ')) 'Warn'
    }

    # ISAPI payload
    if (Test-Path -LiteralPath $script:MscepDll) { Write-Info 'mscep.dll present' 'Ok' }
    else { Write-Info 'mscep.dll missing' 'Warn'; $failures++ }

    # --- endpoint probes ---------------------------------------------------
    # A real SCEP operation, not "something answered". These three outcomes have
    # different causes and all of them mean NDES is broken:
    #
    #   a 401                      the device endpoint requires authentication
    #                              (devices have no domain account)
    #   a PE image in the body     mscep.dll was served as a file - the ISAPI did
    #                              not run, which is the handlers accessPolicy /
    #                              handler order problem
    #   404                        the URL does not reach the ISAPI at all
    $probe = Get-NdesEndpointResponse -Uri 'http://localhost/certsrv/mscep/mscep.dll?operation=GetCACaps'
    if ($null -eq $probe) {
        Write-Info 'Device endpoint: no response' 'Warn'
        $failures++
    }
    elseif ($probe.IsExecutable) {
        Write-Info ("Device endpoint: HTTP {0} returned mscep.dll itself - IIS is not executing the ISAPI" -f $probe.StatusCode) 'Warn'
        Write-Info ("Check that handlers accessPolicy for {0}{1} includes Execute, and that ISAPI-dll precedes StaticFile." -f $script:SiteName, '/CertSrv/mscep') 'Warn'
        $failures++
    }
    elseif ($probe.StatusCode -eq 401) {
        Write-Info 'Device endpoint: HTTP 401 - /CertSrv/mscep must allow anonymous authentication (SCEP devices have no domain account)' 'Warn'
        $failures++
    }
    elseif ($probe.StatusCode -eq 200 -and $probe.Text -match '(?i)POSTPKIOperation|Renewal|SHA-256|SHA-1') {
        $capabilities = @($probe.Text -split "`r?`n" | Where-Object { $_.Trim() })
        Write-Info ("Device endpoint: GetCACaps HTTP 200, {0} capability(ies)" -f $capabilities.Count) 'Ok'
    }
    else {
        Write-Info ("Device endpoint: GetCACaps returned HTTP {0}" -f $probe.StatusCode) 'Warn'
        $failures++
    }

    # Admin endpoint must challenge anonymous callers, then serve the password page
    # to an authenticated administrator.
    $anonymousAdmin = Get-NdesEndpointResponse -Uri 'http://localhost/certsrv/mscep_admin/'
    if ($anonymousAdmin -and $anonymousAdmin.StatusCode -in 401, 403) {
        Write-Info ("Admin endpoint rejects anonymous access (HTTP {0})" -f $anonymousAdmin.StatusCode) 'Ok'
    }
    elseif ($anonymousAdmin -and $anonymousAdmin.StatusCode -eq 200) {
        Write-Info 'Admin endpoint answered anonymously - /CertSrv/mscep_admin should require Windows authentication' 'Warn'
        $failures++
    }
    elseif ($anonymousAdmin) {
        Write-Info ("Admin endpoint: HTTP {0}" -f $anonymousAdmin.StatusCode) 'Warn'
        $failures++
    }

    $admin = Get-NdesEndpointResponse -Uri 'http://localhost/certsrv/mscep_admin/' -UseDefaultCredentials
    if ($null -eq $admin) {
        Write-Info 'Admin endpoint: no response with the current credentials' 'Warn'
        $failures++
    }
    elseif ($admin.StatusCode -eq 503) {
        $poolListing = Invoke-AppCmd -Arguments @('list', 'apppool', $script:AppPoolName) -IgnoreExitCode
        $poolState = if ($poolListing -match 'State:(\w+)') { $Matches[1] } else { 'unknown' }
        Write-Info ("Admin endpoint returned 503; application pool {0} is {1}" -f $script:AppPoolName, $poolState) 'Warn'
        Write-Info ('503 means no worker process: start it with "appcmd start apppool {0}", and check the Application log for WAS or mscep errors.' -f $script:AppPoolName) 'Warn'
        $failures++
    }
    elseif ($admin.IsExecutable) {
        Write-Info 'Admin endpoint returned mscep.dll itself - the ISAPI is not executing there either' 'Warn'
        $failures++
    }
    elseif ($admin.StatusCode -eq 200 -and $admin.Text -match '(?i)password') {
        Write-Info 'Admin endpoint: HTTP 200, password page served' 'Ok'
    }
    elseif ($admin.StatusCode -eq 200) {
        Write-Info 'Admin endpoint: HTTP 200 but no password page - NDES answered and refused to mint a password' 'Warn'

        # Which identity does it refuse? The page mints passwords only for a
        # permitted caller, so trying the service account says whether this is
        # about the caller or about the server.
        if ($ServiceAccountCredential) {
            $asService = Get-NdesEndpointResponse -Uri ('http://localhost{0}/' -f $script:AppPaths[1]) -Credential $ServiceAccountCredential
            $who = if ($ServiceAccountName) { $ServiceAccountName } else { $ServiceAccountCredential.UserName }
            if ($asService -and $asService.StatusCode -eq 200 -and $asService.Text -match '(?i)password') {
                Write-Info ('The same page works as {0}: the caller identity is what matters, and the current user ({1}) is not permitted to mint passwords.' -f $who, [Security.Principal.WindowsIdentity]::GetCurrent().Name) 'Warn'
            }
            elseif ($asService -and $asService.StatusCode -eq 200) {
                Write-Info ('Also refused as {0} (HTTP 200, same page): the caller is not the problem.' -f $who) 'Warn'
            }
            elseif ($asService) {
                # 401 is an authentication result, not the permission page, so it says
                # nothing about whether NDES would mint a password for that account.
                Write-Info ('The probe as {0} was refused with HTTP {1} - IIS did not accept that credential over this binding, so it neither confirms nor rules out the caller.' -f $who, $asService.StatusCode) 'Warn'
            }
        }

        Write-MscepAdminHint -PageText ([string]$admin.Text)
        $failures++
    }
    else {
        Write-Info ("Admin endpoint: HTTP {0}" -f $admin.StatusCode) 'Warn'
        $failures++
    }

    # CA reachability: the DCOM round trip NDES itself needs, not just the port
    if ($ExpectedCA) {
        $caHost = $ExpectedCA.Split('\')[0]
        $reach = Test-NetConnection -ComputerName $caHost -Port 135 -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($reach) { Write-Info ("CA endpoint mapper reachable: {0}:135" -f $caHost) 'Ok' }
        else { Write-Info ("CA not reachable on 135: {0}" -f $caHost) 'Warn'; $failures++ }

        if ($UseGmsa) {
            Write-Info (('CA call as the service account: not attempted - a gMSA has no password to start a process with. ' +
                    'To prove that identity can reach the CA, log on as it elsewhere and run: certutil -ping -config {0}') -f $ExpectedCA)
        }

        foreach ($probe in @(
                @{ Credential = $null; Label = 'this session' },
                @{ Credential = $ServiceAccountCredential; Label = 'the service account' })) {
            if ($probe.Label -ne 'this session' -and -not $probe.Credential) { continue }
            $ping = Test-CaConnectivity -CAConfig $ExpectedCA -Credential $probe.Credential
            if ($ping.Ok) {
                Write-Info ("CA call as {0}: {1}" -f $ping.Identity, $ping.Detail) 'Ok'
            }
            else {
                Write-Info ("CA call as {0} FAILED: {1}" -f $ping.Identity, $ping.Detail) 'Warn'
                $failures++
            }
        }
    }

    # Feature parity with the bundle (and with the baseline this script installs).
    # A gMSA needs the ActiveDirectory module, which the reference build has no
    # reason to carry, so that one feature is expected rather than over-installed.
    $allowedExtra = @()
    if ($UseGmsa) { $allowedExtra = @('RSAT-AD-PowerShell') }
    $failures += (Test-FeatureParity -Expected $Features -AllowExtra $allowedExtra)

    return $failures
}

# ---------------------------------------------------------------------- main ---

if ($Backup) { Invoke-Backup }
elseif ($Restore) { Invoke-Restore }
