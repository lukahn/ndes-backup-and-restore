<#
.SYNOPSIS
    Tests Microsoft NDES/SCEP enrolment end to end, over HTTP and HTTPS.

.DESCRIPTION
    Replaces the sscep + openssl recipe with code that already ships with Windows.
    Everything here comes from the operating system:

      * Invoke-WebRequest-style HTTP is done with System.Net.HttpWebRequest
      * the SCEP protocol (PKCS#7 PKIOperation, CertRep handling) is built by
        CertEnroll.dll through the inbox COM interface IX509SCEPEnrollment, which
        is the same client Windows MDM uses
      * the challenge password is read from the mscep_admin page, where mscep.dll
        renders it as a 16-character hex token

    For each protocol it reports:

      1. GetCACaps    - does mscep.dll answer at all, and with which capabilities
      2. GetCACert    - the CA chain and the RA certificates NDES publishes
      3. Admin auth   - the admin endpoint must refuse anonymous callers
      4. Challenge    - a one-time password from mscep_admin (or -ChallengePassword)
      5. PKIOperation - a real enrolment, and the certificate that comes back

    The two failure modes that matter most are diagnosed explicitly, because both
    look like "NDES is broken" while the server is otherwise healthy:

      * a PE image in the response body - IIS served mscep.dll as a file, so the
        ISAPI never ran. Handler Mappings > Edit Feature Permissions must allow
        Execute for the SCEP applications, and StaticFile must sit below ISAPI-dll.
      * HTTP 401 on the device endpoint - /certsrv/mscep must allow anonymous
        authentication; SCEP devices have no domain account.

    A real enrolment consumes one challenge password, so pass -SkipEnroll to run
    only the read-only checks.

.PARAMETER Server
    NDES host name - prefer the FQDN, because the HTTPS certificate must match it.

.PARAMETER Protocol
    Http, Https or Both (default Both).

.PARAMETER HttpPort
    Port for the HTTP test. Default 80.

.PARAMETER HttpsPort
    Port for the HTTPS test. Default 443.

.PARAMETER ScepVdir
    Virtual directory of the SCEP service. Default /certsrv/mscep.

.PARAMETER AdminVdir
    Virtual directory of the password page. Default /certsrv/mscep_admin.

.PARAMETER CaIdentifier
    Sent as the 'message' parameter of GetCACert. Omit it unless the server
    publishes more than one CA.

.PARAMETER ChallengePassword
    Use this one-time password instead of reading mscep_admin. Required when the
    admin endpoint is not reachable from where you run this.

.PARAMETER Subject
    Subject of the test request. Default CN=NDES-EnrollmentTest-<random>.

.PARAMETER KeyLength
    RSA key length for the test key. Default 2048.

.PARAMETER KeyStorageProvider
    Key storage provider for the test key. Default Microsoft Software Key Storage Provider.

.PARAMETER MachineContext
    Create the key and request in the machine context instead of the current user.
    Requires an elevated session.

.PARAMETER Credential
    Account used for the SCEP endpoint and for the mscep_admin page. When it is
    omitted and an endpoint answers 401, you are prompted once and the credential
    is reused for the rest of the run.

.PARAMETER UseDefaultCredentials
    Send the current user's credentials instead of prompting. Use this when
    running on the NDES server itself, or in a scheduled job under a service
    account that has access.

.PARAMETER SkipEnroll
    Run only the read-only checks (caps, certificates, admin authentication).

.PARAMETER NoPrompt
    Never prompt for credentials. Without this, an endpoint that answers 401
    triggers a single Get-Credential prompt; with it, the run fails with guidance
    instead, which is what an unattended run wants.

.PARAMETER Cleanup
    Remove the test request, private key and certificate once the result has been
    reported. Without it they are kept, so the issued certificate can be inspected
    (or exported with its key) after the run.

.PARAMETER OutFile
    Write the issued certificate to this file (DER). Implies nothing else.

.PARAMETER AllowUntrustedTls
    Do not validate the HTTPS certificate. Use only in a lab: it hides exactly the
    TLS misconfiguration that breaks real devices.

.PARAMETER SaveAdminPage
    Write the raw mscep_admin response to this path. Use it when the password
    cannot be found: the page layout differs between builds, and the saved copy
    shows exactly what the server returned.

.PARAMETER TimeoutSec
    Per-request timeout. Default 30 seconds.

.EXAMPLE
    .\Test-NdesEnrollment.ps1 -Server ndes.contoso.com

    Tests http and https, including a real enrolment on each. A challenge password
    is fetched from mscep_admin for every attempt, because NDES issues one per
    request when UseSinglePassword = 0.

.EXAMPLE
    .\Test-NdesEnrollment.ps1 -Server ndes.contoso.com -SkipEnroll

    Read-only: capabilities, published certificates and admin authentication.

.EXAMPLE
    .\Test-NdesEnrollment.ps1 -Server ndes.contoso.com -SkipEnroll -SaveAdminPage .\admin.htm

    Read-only, and keep the mscep_admin response so the page can be inspected.

.EXAMPLE
    .\Test-NdesEnrollment.ps1 -Server ndes.contoso.com -Protocol Https `
        -ChallengePassword A1B2C3D4E5F60718 -Subject 'CN=SCEPTest-01'

    Enrol over HTTPS only, using a password you already have. NDES passwords are
    hex, 16 characters at the default PasswordLength.

.NOTES
    Runs on Windows 8.1 / Server 2012 R2 or later (IX509SCEPEnrollment). The
    enrolment path additionally needs the SCEP client objects to be registered,
    which is the case on any supported Windows.
#>
# `#Requires` must not precede the help block: it stops Get-Help recognising it.
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Server,

    [ValidateSet('Http', 'Https', 'Both')]
    [string]$Protocol = 'Both',

    [ValidateRange(1, 65535)]
    [int]$HttpPort = 80,

    [ValidateRange(1, 65535)]
    [int]$HttpsPort = 443,

    [string]$ScepVdir = '/certsrv/mscep',

    [string]$AdminVdir = '/certsrv/mscep_admin',

    [string]$CaIdentifier,

    [string]$ChallengePassword,

    [string]$Subject,

    [ValidateRange(1024, 8192)]
    [int]$KeyLength = 2048,

    [string]$KeyStorageProvider = 'Microsoft Software Key Storage Provider',

    [switch]$MachineContext,

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$UseDefaultCredentials,

    [switch]$SkipEnroll,

    [switch]$NoPrompt,

    # The test request, key and certificate are kept by default: they are the
    # evidence that enrolment worked, and the certificate can be inspected or
    # exported. -Cleanup removes them once the result is reported.
    [switch]$Cleanup,

    [string]$OutFile,

    [switch]$AllowUntrustedTls,

    # Saves the raw mscep_admin response next to the log so the page layout can be
    # inspected when the password cannot be located.
    [string]$SaveAdminPage,

    [ValidateRange(5, 600)]
    [int]$TimeoutSec = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# XCN_CRYPT_STRING_* values from cryptdlg.h
$script:Base64 = 1
$script:Hex = 4

# X509SCEPDisposition from CertPol.h
$script:ScepDisposition = @{
    -1 = 'Unknown'
    0  = 'Success'
    2  = 'Failure'
    3  = 'Pending'
    11 = 'PendingChallenge'
}

# X509SCEPFailInfo / szOIDVerisign_FailInfo
$script:ScepFailInfo = @{
    0 = 'badAlg'
    1 = 'badMessageCheck'
    2 = 'badRequest'
    3 = 'badTime'
    4 = 'badCertId'
}

$script:OidCertificateRequestAgent = '1.3.6.1.4.1.311.20.2.1'

# ---------------------------------------------------------------- output ---

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host "== $Message" -ForegroundColor Cyan
}

function Write-Info {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Ok', 'Warn', 'Info', 'Fail')][string]$Level = 'Info'
    )
    $prefix = switch ($Level) { 'Ok' { '  [ok]  ' } 'Warn' { '  [warn]' } 'Fail' { '  [fail]' } default { '  ' } }
    $colour = switch ($Level) { 'Ok' { 'Green' } 'Warn' { 'Yellow' } 'Fail' { 'Red' } default { 'Gray' } }
    Write-Host ($prefix + ' ' + $Message) -ForegroundColor $colour
}

function Test-Elevated {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ------------------------------------------------------------------ http ---

function Initialize-TlsTrust {
    <#
        HttpWebRequest still honours ServicePointManager on every PowerShell
        version, which keeps this working on 5.1 and 7 alike. TLS 1.2 is enabled
        explicitly because 5.1 does not offer it by default.
    #>
    param([switch]$AllowUntrusted)

    try {
        $protocols = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::SecurityProtocol = $protocols
    }
    catch { Write-Verbose "Could not raise SecurityProtocol: $($_.Exception.Message)" }

    $script:AllowUntrustedTls = [bool]$AllowUntrusted
    if ($AllowUntrusted) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
}

function Invoke-ScepHttp {
    <#
        One HTTP request, returning the status, the raw body and, when the body is
        text, the decoded text. Binary is kept as bytes because SCEP responses are
        CMS blobs and PowerShell 5.1 does not reliably hand those back as bytes.

        HttpClient is used rather than HttpWebRequest because .NET Core (and so
        PowerShell 7) no longer consults ServicePointManager's certificate
        callback, which would make -AllowUntrustedTls silently ineffective there.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [byte[]]$Body,
        [string]$ContentType,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$UseDefaultCredentials,
        [int]$TimeoutSec = 30
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $true
    $handler.UseCookies = $false

    if ($Credential) { $handler.Credentials = $Credential.GetNetworkCredential() }
    elseif ($UseDefaultCredentials) { $handler.UseDefaultCredentials = $true }

    if ($script:AllowUntrustedTls -and
        [System.Net.Http.HttpClientHandler].GetProperty('DangerousAcceptAnyServerCertificateValidator')) {
        # A scriptblock cannot serve as this callback on .NET Core: it is invoked on
        # a thread-pool thread with no runspace. The built-in validator has no such
        # problem. On .NET Framework the property is absent, and the
        # ServicePointManager callback that Initialize-TlsTrust set is what applies,
        # because HttpClient rides on HttpWebRequest there.
        $handler.ServerCertificateCustomValidationCallback =
        [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
    }

    $client = New-Object System.Net.Http.HttpClient -ArgumentList $handler
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)

    $result = [pscustomobject]@{
        Uri         = $Uri
        Method      = $Method
        StatusCode  = 0
        StatusText  = ''
        ContentType = ''
        Bytes       = $null
        Text        = ''
        Headers     = @{}
        Error       = ''
    }

    try {
        $httpMethod = New-Object System.Net.Http.HttpMethod -ArgumentList $Method
        $request = New-Object System.Net.Http.HttpRequestMessage -ArgumentList $httpMethod, $Uri
        $request.Headers.TryAddWithoutValidation('User-Agent', 'Test-NdesEnrollment/1.0') | Out-Null

        if ($null -ne $Body) {
            $request.Content = New-Object System.Net.Http.ByteArrayContent -ArgumentList (, $Body)
            if (-not $ContentType) { $ContentType = 'application/x-pki-message' }
            $request.Content.Headers.ContentType =
            New-Object System.Net.Http.Headers.MediaTypeHeaderValue -ArgumentList $ContentType
        }

        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            $result.StatusCode = [int]$response.StatusCode
            $result.StatusText = [string]$response.ReasonPhrase
            if ($response.Content -and $response.Content.Headers.ContentType) {
                $result.ContentType = [string]$response.Content.Headers.ContentType.MediaType
            }
            foreach ($header in $response.Headers) { $result.Headers[$header.Key] = ($header.Value -join ', ') }
            if ($response.Content) {
                foreach ($header in $response.Content.Headers) { $result.Headers[$header.Key] = ($header.Value -join ', ') }
                $result.Bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            }
        }
        finally { $response.Dispose() }
    }
    catch [System.Threading.Tasks.TaskCanceledException] {
        $result.Error = ('timed out after {0}s' -f $TimeoutSec)
        return $result
    }
    catch [System.Exception] {
        $exception = $_.Exception
        while ($exception.InnerException) { $exception = $exception.InnerException }
        $result.Error = $exception.Message
        return $result
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }

    if ($result.Bytes -and $result.Bytes.Length -gt 0 -and
        $result.ContentType -notmatch '(?i)application/x-pki-message') {
        # Honour the declared charset: a page decoded with the wrong one is
        # indistinguishable from a page that does not contain the password.
        $encoding = [System.Text.Encoding]::UTF8
        $contentTypeHeader = ''
        if ($result.Headers.ContainsKey('Content-Type')) { $contentTypeHeader = [string]$result.Headers['Content-Type'] }
        $charset = [regex]::Match($contentTypeHeader, '(?i)charset\s*=\s*"?([\w\-]+)')
        if ($charset.Success) {
            try { $encoding = [System.Text.Encoding]::GetEncoding($charset.Groups[1].Value) } catch { }
        }
        elseif ($result.Bytes.Length -gt 2 -and $result.Bytes[0] -eq 0xFF -and $result.Bytes[1] -eq 0xFE) { $encoding = [System.Text.Encoding]::Unicode }
        elseif ($result.Bytes.Length -gt 2 -and $result.Bytes[0] -eq 0xFE -and $result.Bytes[1] -eq 0xFF) { $encoding = [System.Text.Encoding]::BigEndianUnicode }
        try { $result.Text = $encoding.GetString($result.Bytes) } catch { $result.Text = '' }
    }

    return $result
}

function Get-HttpSummary {
    param($Response)
    $text = if ($Response.StatusText) { ([string]$Response.StatusText).Trim() } else { '' }
    $status = ('{0} {1}' -f $Response.StatusCode, $text).Trim()
    if ($Response.Error -and $Response.StatusCode -eq 0) { $status = 'no response' }
    return $status
}

function Get-ResponseSnippet {
    <#
        A short, single-line extract of an error page. NDES and IIS both return
        useful text (and sometimes an ASP.NET stack trace) when a request is
        rejected, and that is usually the whole diagnosis.
    #>
    param($Response, [int]$Length = 300)
    if (-not $Response.Text) { return '' }
    $text = $Response.Text -replace '(?s)<script.*?</script>', ' '
    $text = $text -replace '<[^>]+>', ' '
    $text = $text -replace '\s+', ' '
    $text = $text.Trim()
    if ($text.Length -gt $Length) { $text = $text.Substring(0, $Length) + '...' }
    return $text
}

# ------------------------------------------------------------------ scep ---

function Get-ScepEndpointCredential {
    <#
        Returns the credential to present to the SCEP endpoint, prompting once if
        the endpoint asks for one and nothing was supplied.

        NDES is frequently configured with anonymous access disabled on
        /certsrv/mscep - that is what the restore writes when the source had it -
        and then even GetCACaps answers 401. Prompting on demand keeps unattended
        runs working while still letting an interactive run get past it.
    #>
    param([string]$Reason)

    if ($script:ScepCredential) {
        return @{ Credential = $script:ScepCredential; UseDefault = $false }
    }
    if ($script:ScepUseDefaultCredentials) {
        return @{ Credential = $null; UseDefault = $true }
    }
    if (-not $script:ScepAllowPrompt) { return $null }
    if (-not [Environment]::UserInteractive) { return $null }

    Write-Info ('The endpoint requested authentication ({0})' -f $Reason) 'Warn'

    $credential = $null
    try {
        $credential = Get-Credential -Message ('Credentials for the NDES SCEP endpoint ({0})' -f $Reason) -ErrorAction Stop
    }
    catch {
        Write-Info ('No credential was supplied: {0}' -f $_.Exception.Message) 'Warn'
        return $null
    }
    if (-not $credential) {
        Write-Info 'No credential was supplied' 'Warn'
        return $null
    }

    $script:ScepCredential = $credential
    return @{ Credential = $credential; UseDefault = $false }
}

function Invoke-ScepEndpoint {
    <#
        Wraps Invoke-ScepHttp for the SCEP endpoint: applies the credential in use
        and, when the endpoint answers 401 and none was configured, asks for one
        and retries the same request. The credential is remembered for the rest of
        the run, so a two-protocol test prompts at most once.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = 'GET',
        [byte[]]$Body,
        [string]$ContentType,
        [int]$TimeoutSec = 30
    )

    $auth = $null
    if ($script:ScepCredential) { $auth = @{ Credential = $script:ScepCredential; UseDefault = $false } }
    elseif ($script:ScepUseDefaultCredentials) { $auth = @{ Credential = $null; UseDefault = $true } }

    $parameters = @{
        Uri         = $Uri
        Method      = $Method
        TimeoutSec  = $TimeoutSec
    }
    if ($null -ne $Body) { $parameters['Body'] = $Body }
    if ($ContentType) { $parameters['ContentType'] = $ContentType }
    if ($auth) {
        $parameters['Credential'] = $auth.Credential
        $parameters['UseDefaultCredentials'] = [bool]$auth.UseDefault
    }

    $response = Invoke-ScepHttp @parameters

    if ($response.StatusCode -ne 401) { return $response }

    $prompted = Get-ScepEndpointCredential -Reason (Get-HttpSummary -Response $response)
    if (-not $prompted) { return $response }

    $identity = if ($prompted.Credential) { $prompted.Credential.UserName } else { 'the current user' }
    Write-Info ('Retrying as {0}' -f $identity) 'Ok'

    $parameters['Credential'] = $prompted.Credential
    $parameters['UseDefaultCredentials'] = [bool]$prompted.UseDefault
    return (Invoke-ScepHttp @parameters)
}

function Test-ServedAsStaticFile {
    <#
        When IIS serves mscep.dll instead of executing it, the request still looks
        healthy at the HTTP level: 200, a body, no error page. The body is a PE
        image, which is why a browser offers it as a download - and it means the
        handler order is wrong, not the SCEP configuration.
    #>
    param($Response)

    if (-not $Response.Bytes -or $Response.Bytes.Length -lt 2) { return $false }
    return ($Response.Bytes[0] -eq 0x4D -and $Response.Bytes[1] -eq 0x5A)
}

function Invoke-ScepOperation {
    <#
        Builds the SCEP URL for an operation and submits it, trying both path
        forms NDES is reachable under:

            /certsrv/mscep/mscep.dll?operation=...             (ISAPI executes)
            /certsrv/mscep/mscep.dll/pkiclient.exe?operation=... (client compatibility)

        The second form relies on IIS mapping the .dll as a script and treating the
        rest as PATH_INFO; when that mapping does not apply, the request falls
        through to StaticFile and comes back as 404.0. Trying the documented form
        first and remembering whichever one answers keeps the tool honest about
        what the server actually accepts.
    #>
    param(
        [Parameter(Mandatory)][string]$BaseUri,
        [Parameter(Mandatory)][string]$Operation,
        [string]$Message,
        [string]$Method = 'GET',
        [byte[]]$Body,
        [string]$ContentType,
        [int]$TimeoutSec = 30
    )

    $paths = if ($script:ScepPath) { @($script:ScepPath) } else { $script:ScepPaths }
    $attempted = @()
    $last = $null

    foreach ($path in $paths) {
        $uri = '{0}{1}?operation={2}' -f $BaseUri, $path, $Operation
        if ($Message) { $uri += '&message=' + [uri]::EscapeDataString($Message) }
        $attempted += $uri

        $response = Invoke-ScepEndpoint -Uri $uri -Method $Method -Body $Body -ContentType $ContentType -TimeoutSec $TimeoutSec
        $last = [pscustomobject]@{
            Response  = $response
            Uri       = $uri
            Method    = $Method
            Attempted = $attempted
        }

        if ($response.StatusCode -eq 0) {
            # Transport failure: the other path form cannot help.
            return $last
        }

        if ($response.StatusCode -ne 404) {
            if (-not $script:ScepPath) {
                $script:ScepPath = $path
                $displayPath = if ($path) { $path } else { '/' }
                Write-Info ('SCEP endpoint resolved to {0}?operation=...' -f $displayPath) 'Ok'
            }
            return $last
        }
    }

    return $last
}

function Get-ScepCapabilities {
    <#
        GetCACaps is the cheapest possible "is the SCEP endpoint alive" probe: it
        is small and answered by mscep.dll itself. It needs no authentication on a
        default NDES build, but a server with anonymous access disabled will ask
        for one.
    #>
    param(
        [Parameter(Mandatory)][string]$BaseUri,
        [int]$TimeoutSec = 30
    )

    $operation = Invoke-ScepOperation -BaseUri $BaseUri -Operation 'GetCACaps' -TimeoutSec $TimeoutSec

    $uri = $operation.Uri
    $response = $operation.Response
    $caps = @()

    # A PE image in the body means IIS served the DLL instead of executing it;
    # treating those bytes as capability text produces nonsense.
    if ($response.StatusCode -eq 200 -and $response.Text -and -not (Test-ServedAsStaticFile -Response $response)) {
        $caps = @($response.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    return [pscustomobject]@{
        Response     = $response
        Uri          = $uri
        Attempted    = $operation.Attempted
        Capabilities = $caps
        Text         = ($caps -join "`n")
    }
}

function Get-ScepCaCertificates {
    <#
        GetCACert returns a CMS blob holding the CA chain and, on Microsoft NDES,
        the two RA certificates. IX509SCEPEnrollment needs that blob verbatim and
        needs the CA certificate to be self-issued, so both are reported here.
    #>
    param(
        [Parameter(Mandatory)][string]$BaseUri,
        [string]$CaIdentifier,
        [int]$TimeoutSec = 30
    )

    $operation = Invoke-ScepOperation -BaseUri $BaseUri -Operation 'GetCACert' -Message $CaIdentifier -TimeoutSec $TimeoutSec
    $uri = $operation.Uri
    $response = $operation.Response
    $certificates = @()
    $serverCertificatesBase64 = ''

    if ($response.StatusCode -eq 200 -and $response.Bytes -and $response.Bytes.Length -gt 0) {
        # Windows PowerShell does not have System.Security loaded by default, so
        # SignedCms would otherwise be an unknown type there.
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        try {
            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
            $cms.Decode($response.Bytes)
            $certificates = @($cms.Certificates)
            # Hand the client exactly what the server sent.
            $serverCertificatesBase64 = [Convert]::ToBase64String($response.Bytes)
        }
        catch {
            # A CA with a single certificate may answer with bare DER.
            try {
                $single = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($response.Bytes)
                $certificates = @($single)
                $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                [void]$collection.Add($single)
                $serverCertificatesBase64 = [Convert]::ToBase64String(
                    $collection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7))
            }
            catch {
                Write-Verbose "GetCACert body was neither CMS nor a certificate: $($_.Exception.Message)"
            }
        }
    }

    return [pscustomobject]@{
        Response                 = $response
        Uri                      = $uri
        Certificates             = $certificates
        ServerCertificatesBase64 = $serverCertificatesBase64
        ContentType  = $response.ContentType
    }
}

function ConvertTo-DerOid {
    <#
        DER encoding of a dotted OID, so an extension blob can be searched for it.
        This avoids depending on how any particular Windows version chooses to
        format an Enhanced Key Usage extension.
    #>
    param([Parameter(Mandatory)][string]$Oid)

    $parts = @($Oid.Split('.') | ForEach-Object { [int]$_ })
    if ($parts.Count -lt 2) { throw "Not a dotted OID: $Oid" }

    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.Add([byte](40 * $parts[0] + $parts[1]))

    for ($index = 2; $index -lt $parts.Count; $index++) {
        $value = $parts[$index]
        $encoded = New-Object System.Collections.Generic.List[byte]
        $encoded.Add([byte]($value -band 0x7F))
        $value = [math]::Floor($value / 128)
        while ($value -gt 0) {
            $encoded.Insert(0, [byte](($value -band 0x7F) -bor 0x80))
            $value = [math]::Floor($value / 128)
        }
        foreach ($byte in $encoded) { $bytes.Add($byte) }
    }

    return $bytes.ToArray()
}

function Test-ByteSequence {
    param(
        [Parameter(Mandatory)][byte[]]$Haystack,
        [Parameter(Mandatory)][byte[]]$Needle
    )

    if ($Needle.Length -eq 0 -or $Haystack.Length -lt $Needle.Length) { return $false }
    $last = $Haystack.Length - $Needle.Length
    for ($start = 0; $start -le $last; $start++) {
        $matched = $true
        for ($offset = 0; $offset -lt $Needle.Length; $offset++) {
            if ($Haystack[$start + $offset] -ne $Needle[$offset]) { $matched = $false; break }
        }
        if ($matched) { return $true }
    }
    return $false
}

function Get-CertificatePurpose {
    <#
        Short human label for a certificate: is it a CA, an RA signing certificate
        (Certificate Request Agent), or something else. This is what decides
        whether IX509SCEPEnrollment can find what it needs.
    #>
    param([Parameter(Mandatory)]$Certificate)

    $isCa = $false
    try {
        $basic = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
        if ($basic) { $isCa = $basic.Format($false) -match '(?i)subject\s*type\s*=\s*CA' }
    }
    catch { $isCa = $false }
    if ($Certificate.Subject -eq $Certificate.Issuer) { $isCa = $true }

    if ($isCa) { return 'CA' }

    try {
        $eku = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
        if ($eku) {
            $needle = ConvertTo-DerOid -Oid $script:OidCertificateRequestAgent
            if (Test-ByteSequence -Haystack $eku.RawData -Needle $needle) {
                return 'RA signing (Certificate Request Agent)'
            }
        }
    }
    catch { Write-Verbose "Could not read the EKU of $($Certificate.Subject): $($_.Exception.Message)" }

    # Everything else NDES publishes alongside its CA is the RA encryption
    # certificate: there are only ever two RA certificates.
    return 'RA encryption'
}

function Get-Md5Hex {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [System.Security.Cryptography.MD5]::Create()
    try {
        return (($algorithm.ComputeHash($Bytes)) | ForEach-Object { $_.ToString('X2') }) -join ''
    }
    finally { $algorithm.Dispose() }
}

function Find-CertificateByHash {
    <#
        The hash mscep_admin prints is the MD5 of the CA certificate - the same
        value the SCEP client sends as the CA identifier - so identifying the
        certificate means matching that hash, not decoding it.

        Looked for in the certificates GetCACert published first (no local store
        needed), then in the local stores, where a copy carries the friendly name
        the CA was installed with.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Hash,
        [AllowEmptyCollection()][object[]]$Published = @()
    )

    $target = ($Hash -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if (-not $target) { return @() }

    $found = @()
    foreach ($certificate in @($Published)) {
        if (-not $certificate) { continue }
        if ((Get-Md5Hex -Bytes $certificate.RawData) -eq $target) {
            $found += [pscustomobject]@{ Source = 'GetCACert'; Store = ''; Certificate = $certificate }
        }
    }

    foreach ($store in @(
            'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\My', 'Cert:\LocalMachine\TrustedPeople',
            'Cert:\CurrentUser\Root', 'Cert:\CurrentUser\CA', 'Cert:\CurrentUser\My')) {
        if (-not (Test-Path -Path $store)) { continue }
        foreach ($certificate in @(Get-ChildItem -Path $store -ErrorAction SilentlyContinue)) {
            if ((Get-Md5Hex -Bytes $certificate.RawData) -eq $target) {
                $found += [pscustomobject]@{ Source = 'store'; Store = $store; Certificate = $certificate }
            }
        }
    }

    return $found
}

function Write-CaCertificateLookup {
    <#
        Names the certificate behind an MD5 hash: the subject it belongs to, the
        friendly name if one was set when it was installed, and where a local copy
        lives so it can be opened in certlm.msc.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Hash,
        [AllowEmptyCollection()][object[]]$Published = @(),
        [string]$Indent = '           '
    )

    if (-not $Hash) { return }

    $found = @(Find-CertificateByHash -Hash $Hash -Published $Published)
    if ($found.Count -eq 0) {
        Write-Info ('{0}no certificate with this hash in GetCACert or the local stores' -f $Indent)
        return
    }

    $local = @($found | Where-Object { $_.Source -eq 'store' })
    $published = $found | Where-Object { $_.Source -eq 'GetCACert' } | Select-Object -First 1

    $subject = if ($local.Count -gt 0) { $local[0].Certificate.Subject } else { $published.Certificate.Subject }
    $where = if ($local.Count -gt 0) { $local[0].Store } else { 'GetCACert' }
    Write-Info ('{0}subject      : {1}  ({2})' -f $Indent, $subject, $where)

    $names = @($found | ForEach-Object { $_.Certificate.FriendlyName } | Where-Object { $_ } | Sort-Object -Unique)
    if ($names.Count -gt 0) {
        Write-Info ('{0}friendly name: {1}' -f $Indent, (($names | ForEach-Object { '"{0}"' -f $_ }) -join ', '))
    }
    elseif ($local.Count -gt 0) {
        Write-Info ('{0}friendly name: not set on the local copy' -f $Indent)
    }
    else {
        Write-Info ('{0}friendly name: not available (only the published copy was found, and that carries no name)' -f $Indent)
    }

    foreach ($entry in $local) {
        Write-Info ('{0}local copy   : {1}\{2}' -f $Indent, $entry.Store, $entry.Certificate.Thumbprint)
    }
}

function Get-AdministratorChallengePassword {
    <#
        mscep_admin needs Windows authentication and, on a working server, returns
        the one-time password directly: mscep.dll renders IDR_HTML_NETWORK.HTML and
        the password is a 16-character hex token (PasswordLength bits of hex, 16
        characters at the default). There is no form to submit - the page that is
        returned by the authenticated GET *is* the password page.

        The credential is the one already in use for the SCEP endpoint, so a run
        that had to authenticate never asks twice.
    #>
    param(
        [Parameter(Mandatory)][string]$AdminUri,
        [int]$TimeoutSec = 30
    )

    $auth = $null
    if ($script:ScepCredential) { $auth = @{ Credential = $script:ScepCredential; UseDefault = $false } }
    elseif ($script:ScepUseDefaultCredentials) { $auth = @{ Credential = $null; UseDefault = $true } }

    $parameters = @{ Uri = $AdminUri; TimeoutSec = $TimeoutSec }
    if ($auth) {
        $parameters['Credential'] = $auth.Credential
        $parameters['UseDefaultCredentials'] = [bool]$auth.UseDefault
    }

    $first = Invoke-ScepHttp @parameters
    if ($first.StatusCode -in 401, 403) {
        $prompted = Get-ScepEndpointCredential -Reason ('mscep_admin returned ' + (Get-HttpSummary -Response $first))
        if ($prompted) {
            $parameters['Credential'] = $prompted.Credential
            $parameters['UseDefaultCredentials'] = [bool]$prompted.UseDefault
            $first = Invoke-ScepHttp @parameters
        }
    }
    if ($first.StatusCode -ne 200) {
        return [pscustomobject]@{
            Response = $first
            Password = ''
            Method   = 'GET'
            Detail   = ('admin page returned ' + (Get-HttpSummary -Response $first))
        }
    }

    Save-AdminPage -Response $first

    $caThumbprint = Find-CaThumbprint -Html $first.Text
    $password = Find-ChallengePassword -Html $first.Text
    if ($password) {
        return [pscustomobject]@{
            Response     = $first
            Password     = $password
            Method       = 'GET'
            Detail       = 'shown directly on the page'
            CaThumbprint = $caThumbprint
        }
    }

    # Some builds put the password behind a link instead of rendering it. Follow a
    # single "get password"-style link before giving up.
    $link = [regex]::Match($first.Text, '(?is)<a\b[^>]*href\s*=\s*"([^"]*)"[^>]*>(?:(?!</a>).){0,80}?password')
    if ($link.Success) {
        $href = [System.Net.WebUtility]::HtmlDecode($link.Groups[1].Value)
        if ($href -and $href -notmatch '^(?i)(mailto|javascript):') {
            try { $next = [uri]::new([uri]$AdminUri, $href).AbsoluteUri } catch { $next = $null }
            if ($next) {
                $followed = Invoke-ScepHttp -Uri $next -TimeoutSec $TimeoutSec -Credential $parameters['Credential'] `
                    -UseDefaultCredentials:([bool]$parameters['UseDefaultCredentials'])
                if ($followed.StatusCode -eq 200) {
                    Save-AdminPage -Response $followed
                    $caThumbprint = Find-CaThumbprint -Html $followed.Text
                    $password = Find-ChallengePassword -Html $followed.Text
                    if ($password) {
                        return [pscustomobject]@{
                            Response     = $followed
                            Password     = $password
                            Method       = 'GET'
                            Detail       = ('from ' + $next)
                            CaThumbprint = $caThumbprint
                        }
                    }
                    $first = $followed
                }
            }
        }
    }

    # Nothing matched. Report what the page actually said - this is the only useful
    # thing a first run against an unfamiliar build can produce.
    $plain = ConvertTo-PlainText -Html $first.Text
    # Long enough to include the sentence that follows the headline: the reason
    # mscep.dll gives is at the end of the paragraph, not the start.
    $snippet = if ($plain.Length -gt 800) { $plain.Substring(0, 800) + '...' } else { $plain }

    return [pscustomobject]@{
        Response     = $first
        Password     = ''
        Method       = 'GET'
        Detail       = ('no password on the page (body starts: {0})' -f $snippet)
        CaThumbprint = $caThumbprint
    }
}

function Save-AdminPage {
    param($Response)

    if (-not $SaveAdminPage) { return }
    try {
        $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SaveAdminPage)
        [System.IO.File]::WriteAllBytes($path, [byte[]]$Response.Bytes)
        Write-Info ('mscep_admin response saved to {0}' -f $path)
    }
    catch { Write-Info ("Could not save the admin page: {0}" -f $_.Exception.Message) 'Warn' }
}

function ConvertTo-PlainText {
    param([string]$Html)
    if (-not $Html) { return '' }
    $text = $Html -replace '(?s)<script\b.*?</script>', ' ' -replace '(?s)<style\b.*?</style>', ' '
    $text = $text -replace '<[^>]+>', ' '
    $text = [System.Net.WebUtility]::HtmlDecode($text)
    return (($text -replace '\s+', ' ').Trim())
}

function Get-HtmlAttribute {
    param([Parameter(Mandatory)][string]$Tag, [Parameter(Mandatory)][string]$Attribute)
    $match = [regex]::Match($Tag, ('(?i)\b{0}\s*=\s*(?:"([^"]*)"|''([^'']*)''|([^\s>]+))' -f [regex]::Escape($Attribute)))
    if (-not $match.Success) { return $null }
    foreach ($group in 1..3) {
        if ($match.Groups[$group].Success) { return $match.Groups[$group].Value }
    }
    return $null
}

function Find-ChallengePassword {
    <#
        Locates the one-time password in the mscep_admin page.

        The page is generated from the IDR_HTML_NETWORK.HTML resource and the
        password itself is hex - 16 characters at the default PasswordLength - so
        the search is layered from specific to general, and it also looks inside
        attributes, because a build that renders the value in a link or a hidden
        control would otherwise be invisible to a tag-stripping parser:

          1. <input>/<textarea> values that look like a token
          2. text next to a "password" label (gaps allowed: it can be cells away)
          3. a bare 16-character hex token anywhere in the document
          4. any 8+ character hex token

        Empty means "not found", never a guess that happens to match.
    #>
    param([string]$Html)

    if (-not $Html) { return '' }

    $clean = $Html -replace '(?s)<script\b.*?</script>', ' ' -replace '(?s)<style\b.*?</style>', ' '
    $plain = ConvertTo-PlainText -Html $clean

    # 1. Form controls. Buttons and other non-value controls are skipped: their
    #    labels contain the word "password" too.
    foreach ($match in [regex]::Matches($clean, '(?is)<input\b[^>]*>')) {
        $tag = $match.Value
        $type = Get-HtmlAttribute -Tag $tag -Attribute 'type'
        if ($type -and $type -match '(?i)^(submit|button|reset|image|checkbox|radio)$') { continue }
        $value = Get-HtmlAttribute -Tag $tag -Attribute 'value'
        if ($value -and $value -match '^[0-9A-Fa-f]{8,64}$') { return $value }
    }
    foreach ($match in [regex]::Matches($clean, '(?is)<textarea\b[^>]*>([^<]+)</textarea>')) {
        $value = $match.Groups[1].Value.Trim()
        if ($value -match '^[0-9A-Fa-f]{8,64}$') { return $value }
    }

    # 2. Next to a label, in the flattened text. The real page reads
    #         "The enrollment challenge password is: 0582D6BA48EEFC86"
    #    so the gap between label and value contains whole words, not just
    #    punctuation. Allowing anything but digits keeps the match from running
    #    past the value into the CA thumbprint printed above it.
    foreach ($pattern in @(
            '(?i)enrollment\s+challenge\s+password[^0-9]{0,200}?([0-9A-Fa-f]{8,64})',
            '(?i)challenge\s+password[^0-9]{0,200}?([0-9A-Fa-f]{8,64})',
            '(?i)password[^0-9]{0,200}?([0-9A-Fa-f]{8,64})',
            '(?i)password[^0-9]{0,200}?([A-Za-z0-9]{8,64})')) {
        $match = [regex]::Match($plain, $pattern)
        if ($match.Success) { return $match.Groups[1].Value }
    }

    # 3. The documented shape, anywhere in the raw document (attributes included).
    #    Left at 16 characters on purpose: a longer hex run on this page is the CA
    #    thumbprint, and returning it as the password would turn a clear "not
    #    found" into a puzzling rejection later. A build that uses a different
    #    PasswordLength is still covered by the label search above.
    $hex16 = [regex]::Matches($clean, '\b[0-9A-Fa-f]{16}\b')
    if ($hex16.Count -ge 1) { return $hex16[0].Value }

    return ''
}

function Format-Thumbprint {
    <#
        Group hex in 8-character blocks, which is how mscep_admin prints the CA
        thumbprint - so the value this tool reports can be compared character for
        character with the page a device administrator sees.
    #>
    param([string]$Hex)

    if (-not $Hex) { return '' }
    $clean = ($Hex -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($clean.Length -le 8) { return $clean }

    $blocks = @()
    for ($index = 0; $index -lt $clean.Length; $index += 8) {
        $blocks += $clean.Substring($index, [Math]::Min(8, $clean.Length - $index))
    }
    return ($blocks -join ' ')
}

function Find-CaThumbprint {
    <#
        The password page also prints the CA certificate hash it is bound to:

            The thumbprint (hash value) for the CA certificate is:
            E2AB19C1 AAEA9209 E8F7D50C C38C4733

        That is the same MD5 the SCEP client has to send as the CA identifier, so
        printing both lets an operator see at a glance whether the NDES service and
        the CA it is configured for agree.
    #>
    param([string]$Html)

    if (-not $Html) { return '' }
    $plain = ConvertTo-PlainText -Html $Html
    # The label is "The thumbprint (hash value) for the CA certificate is:" - the
    # words in between contain hex letters, so the gap has to allow any character.
    $match = [regex]::Match($plain,
        '(?i)thumbprint.{0,80}?((?:[0-9A-Fa-f]{4,8}\s+){2,}[0-9A-Fa-f]{4,8}|[0-9A-Fa-f]{32,64})')
    if (-not $match.Success) { return '' }
    return ($match.Groups[1].Value -replace '\s', '')
}

function New-TestSubjectName {
    <#
        A subject that is not already in the store and not already used earlier in
        this run. Two endpoints in one run must not share it: the certificate the
        first one installs would make the second indistinguishable from it, and any
        cleanup keyed on the subject would remove both.
    #>
    param(
        [string]$StoreLocation = 'CurrentUser',
        [string]$Prefix = 'CN=NDES-EnrollmentTest-'
    )

    $storePath = if ($StoreLocation -eq 'LocalMachine') { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }
    $existing = @()
    if (Test-Path -Path $storePath) {
        $existing = @(Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue | ForEach-Object { $_.Subject })
    }

    for ($attempt = 0; $attempt -lt 25; $attempt++) {
        $candidate = $Prefix + ([guid]::NewGuid().ToString('N').Substring(0, 8))
        if ($existing -notcontains $candidate -and $script:UsedSubjects -notcontains $candidate) {
            $script:UsedSubjects += $candidate
            return $candidate
        }
    }
    throw 'Could not generate an unused test subject name; remove the leftover NDES-EnrollmentTest certificates and retry.'
}

function New-ScepEnrollment {
    <#
        Builds the PKCS#10 request and hands it, with the server certificates, to
        the inbox SCEP client.

        Two details are easy to get wrong and both are required:
          * the CA is identified by the MD5 digest of its DER encoding, hex, not
            by the SHA-1 thumbprint Windows usually shows
          * the CA certificate must be self-issued, because CertEnroll locates it
            by that digest inside the blob it is given
    #>
    param(
        [Parameter(Mandatory)][string]$ServerCertificatesBase64,
        [Parameter(Mandatory)]$RootCertificate,
        [Parameter(Mandatory)][string]$SubjectName,
        [int]$KeyLength = 2048,
        [string]$ProviderName = 'Microsoft Software Key Storage Provider',
        [switch]$MachineContext,
        [string]$ChallengePassword,
        [string]$ServerCapabilities
    )

    $context = if ($MachineContext) { 2 } else { 1 }
    $contextName = if ($MachineContext) { 'LocalMachine\My' } else { 'CurrentUser\My' }

    $privateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
    $privateKey.ProviderName = $ProviderName
    $privateKey.Length = $KeyLength
    $privateKey.ExportPolicy = 0
    $privateKey.MachineContext = [bool]$MachineContext
    $privateKey.Create()

    $request = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
    $request.InitializeFromPrivateKey($context, $privateKey, '')

    $distinguishedName = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    $distinguishedName.Encode($SubjectName, 0)
    $request.Subject = $distinguishedName

    if ($ChallengePassword) { $request.ChallengePassword = $ChallengePassword }

    $scep = New-Object -ComObject X509Enrollment.CX509SCEPEnrollment
    $scep.Initialize(
        $request,
        (Get-Md5Hex -Bytes $RootCertificate.RawData),
        $script:Hex,
        $ServerCertificatesBase64,
        $script:Base64
    )

    if ($ServerCapabilities) {
        try { $scep.ServerCapabilities = $ServerCapabilities }
        catch { Write-Verbose "ServerCapabilities rejected the caps text: $($_.Exception.Message)" }
    }

    return [pscustomobject]@{
        Enrollment    = $scep
        Request       = $request
        PrivateKey    = $privateKey
        ContextName   = $contextName
        StoreLocation = $(if ($MachineContext) { 'LocalMachine' } else { 'CurrentUser' })
        KeyContainer  = [string]$privateKey.ContainerName
    }
}

function Remove-TestRequestArtifacts {
    <#
        DeleteRequest only works while the SCEP object is in a valid state, and a
        request that failed during ProcessResponseMessage is not. Without this the
        test key would be left in the profile, so remove it by name as a fallback.
    #>
    param(
        [string]$StoreLocation = 'CurrentUser',
        [string]$SubjectName,
        [string]$ProviderName,
        [string]$ContainerName
    )

    $removed = 0
    $storePath = if ($StoreLocation -eq 'LocalMachine') { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }

    foreach ($certificate in @(Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -eq $SubjectName })) {
        try {
            Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction Stop
            $removed++
        }
        catch { Write-Verbose "Could not remove $($certificate.Thumbprint): $($_.Exception.Message)" }
    }

    if ($ContainerName) {
        $certutil = Join-Path $env:SystemRoot 'System32\certutil.exe'
        $arguments = @('-csp', $ProviderName, '-delkey', $ContainerName)
        if ($StoreLocation -ne 'LocalMachine') { $arguments = @('-user') + $arguments }
        try { $null = & $certutil @arguments 2>&1 } catch { Write-Verbose "certutil -delkey failed: $($_.Exception.Message)" }
    }

    return $removed
}

function Send-ScepPkiOperation {
    <#
        Submits the message the SCEP client built. RFC 8894 allows either a POST
        of the raw blob or a GET with the base64 in the 'message' parameter; NDES
        advertises which through POSTPKIOperation.
    #>
    param(
        [Parameter(Mandatory)][string]$BaseUri,
        [Parameter(Mandatory)][string]$MessageBase64,
        [string[]]$Capabilities = @(),
        [int]$TimeoutSec = 30
    )

    $usePost = ($Capabilities -contains 'POSTPKIOperation')
    if ($usePost) {
        return Invoke-ScepOperation -BaseUri $BaseUri -Operation 'PKIOperation' -Method 'POST' `
            -Body ([Convert]::FromBase64String($MessageBase64)) `
            -ContentType 'application/x-pki-message' -TimeoutSec $TimeoutSec
    }

    return Invoke-ScepOperation -BaseUri $BaseUri -Operation 'PKIOperation' `
        -Message $MessageBase64 -TimeoutSec $TimeoutSec
}

# ------------------------------------------------------------------ main ---

Initialize-TlsTrust -AllowUntrusted:$AllowUntrustedTls

# Credential state for the whole run: -Credential wins, otherwise the first 401
# triggers a single prompt (unless -NoPrompt or a non-interactive host).
$script:ScepCredential = $Credential
$script:ScepUseDefaultCredentials = [bool]$UseDefaultCredentials
$script:ScepAllowPrompt = -not $NoPrompt

# URL forms NDES answers on, in the order they are tried. The ISAPI form is the
# documented one; the pkiclient path is what several third-party clients use and
# only works where IIS maps the DLL as a script and the remainder as PATH_INFO.
$script:ScepPath = $null
$script:ScepPaths = @('/mscep.dll', '/mscep.dll/pkiclient.exe')

if ($script:ScepCredential) {
    Write-Info ('Authenticating as {0}' -f $script:ScepCredential.UserName)
}
elseif ($script:ScepUseDefaultCredentials) {
    Write-Info 'Authenticating as the current user'
}

$serverName = $Server
if ($serverName -match '^[a-z]+://') {
    throw "Server must be a host name, not a URL. Use -Protocol to choose the scheme (got '$Server')."
}

# One subject per endpoint, unless one was supplied: the two protocols must not
# install certificates that look identical.
$subjectBase = $Subject
$script:UsedSubjects = @()
if ($subjectBase) { Write-Info ('Subject supplied on the command line: {0}' -f $subjectBase) }

if ($MachineContext -and -not (Test-Elevated)) {
    throw 'MachineContext requires an elevated session.'
}

if (-not (Get-Command -Name 'New-Object' -ErrorAction SilentlyContinue)) {
    throw 'This script requires Windows PowerShell 5.1 or later.'
}

try {
    $null = New-Object -ComObject X509Enrollment.CX509SCEPEnrollment
}
catch {
    throw ('The inbox SCEP client (IX509SCEPEnrollment, CertEnroll.dll) is not available: {0}' -f $_.Exception.Message)
}

$endpoints = switch ($Protocol) {
    'Http' { @([pscustomobject]@{ Scheme = 'http'; Port = $HttpPort }) }
    'Https' { @([pscustomobject]@{ Scheme = 'https'; Port = $HttpsPort }) }
    default {
        @(
            [pscustomobject]@{ Scheme = 'http'; Port = $HttpPort }
            [pscustomobject]@{ Scheme = 'https'; Port = $HttpsPort }
        )
    }
}

$results = @()

foreach ($endpoint in $endpoints) {
    $authority = if (($endpoint.Scheme -eq 'http' -and $endpoint.Port -eq 80) -or
        ($endpoint.Scheme -eq 'https' -and $endpoint.Port -eq 443)) {
        $serverName
    }
    else {
        '{0}:{1}' -f $serverName, $endpoint.Port
    }

    $baseUri = '{0}://{1}{2}' -f $endpoint.Scheme, $authority, $ScepVdir.TrimEnd('/')
    $adminUri = '{0}://{1}{2}/' -f $endpoint.Scheme, $authority, $AdminVdir.TrimEnd('/')

    $result = [pscustomobject]@{
        Protocol    = $endpoint.Scheme
        BaseUri     = $baseUri
        Capabilities = @()
        CaCertificates = @()
        RootFound   = $false
        RaSigningFound = $false
        AdminStatus = ''
        AdminRequiresAuth = $false
        Challenge   = ''
        CaThumbprint = ''
        Disposition = ''
        Issued      = $null
        IssuedThumbprint = ''
        Problem     = ''
    }

    Write-Step ('Testing {0}' -f $baseUri)

    # ---------------------------------------------------------- GetCACaps ---
    $caps = Get-ScepCapabilities -BaseUri $baseUri -TimeoutSec $TimeoutSec

    if (Test-ServedAsStaticFile -Response $caps.Response) {
        Write-Info 'The endpoint returned a Windows executable instead of a SCEP answer.' 'Fail'
        Write-Info 'IIS is serving mscep.dll as a static file, so the ISAPI never runs. Two things make IIS do that, and the first one is not visible in Handler Mappings:' 'Warn'
        Write-Info ('   1. Handler Mappings > Edit Feature Permissions for {0}: Execute must be allowed (handlers accessPolicy "Read, Execute"). ISAPI-dll requires Execute and IIS skips it with the inherited "Read, Script".' -f $ScepVdir) 'Warn'
        Write-Info '   2. StaticFile (path *) must sit BELOW ISAPI-dll (path *.dll) in the handler list.' 'Warn'
        Write-Info 'NDESMigration -Restore writes both. To check by hand: appcmd list config "<site>/CertSrv/mscep" -section:system.webServer/handlers' 'Warn'
        $result.Problem = 'mscep.dll served as a static file'
        $results += $result
        continue
    }
    $result.Capabilities = $caps.Capabilities

    if ($caps.Response.StatusCode -eq 200 -and $caps.Capabilities.Count -gt 0) {
        Write-Info ('GetCACaps: {0}, {1} capability(ies)' -f (Get-HttpSummary -Response $caps.Response), $caps.Capabilities.Count) 'Ok'
        Write-Info ('           {0}' -f ($caps.Capabilities -join ', '))
    }
    else {
        $summary = Get-HttpSummary -Response $caps.Response
        Write-Info ('GetCACaps failed: {0}' -f $summary) 'Fail'
        if ($caps.Response.Error) { Write-Info ("           {0}" -f $caps.Response.Error) 'Warn' }
        $snippet = Get-ResponseSnippet -Response $caps.Response
        if ($snippet) { Write-Info ('           {0}' -f $snippet) 'Warn' }
        if ($caps.Response.StatusCode -eq 404) {
            Write-Info ('           Check that {0} is the SCEP virtual directory and that the SCEP service is installed.' -f $ScepVdir) 'Warn'
            if ($caps.Attempted) {
                Write-Info ('           Tried: {0}' -f ($caps.Attempted -join ' and ')) 'Warn'
                Write-Info '           A 404 on both forms means the request is not reaching mscep.dll: check that ISAPI-dll precedes StaticFile in Handler Mappings.' 'Warn'
            }
        }
        elseif ($caps.Response.StatusCode -eq 503) {
            Write-Info '           HTTP 503 is the SCEP application pool, not the site. Check that apppool SCEP is started and its identity can log on.' 'Warn'
        }
        elseif ($caps.Response.StatusCode -eq 401) {
            Write-Info '           The endpoint requires authentication and did not accept what was sent. Pass -Credential (or -UseDefaultCredentials on the NDES server itself); without -NoPrompt the script offers to prompt.' 'Warn'
            Write-Info '           A working NDES answers GetCACaps anonymously: SCEP devices have no domain account. If /certsrv/mscep requires authentication, enable Anonymous Authentication on that application.' 'Warn'
            if ($snippet -match '(?i)401\.2') {
                Write-Info '           401.2 means IIS found no authentication provider it could use for this client: check that the mscep application has the same authentication settings as the source server.' 'Warn'
            }
        }
        $result.Problem = 'GetCACaps failed'
        $results += $result
        continue
    }

    if ($endpoint.Scheme -eq 'http') {
        Write-Info 'Testing over HTTP: the SCEP message and the admin credentials are not protected by TLS.' 'Warn'
    }

    # ---------------------------------------------------------- GetCACert ---
    $caInfo = Get-ScepCaCertificates -BaseUri $baseUri -CaIdentifier $CaIdentifier -TimeoutSec $TimeoutSec
    $result.CaCertificates = $caInfo.Certificates

    if ($caInfo.Response.StatusCode -eq 200 -and $caInfo.Certificates.Count -gt 0) {
        Write-Info ('GetCACert: {0}, {1} certificate(s)' -f (Get-HttpSummary -Response $caInfo.Response), $caInfo.Certificates.Count) 'Ok'
        foreach ($certificate in $caInfo.Certificates) {
            $purpose = Get-CertificatePurpose -Certificate $certificate
            Write-Info ('           {0,-42} {1}' -f $certificate.Subject, $purpose)
            if ($purpose -eq 'CA') { $result.RootFound = $true }
            if ($purpose -like 'RA signing*') { $result.RaSigningFound = $true }
        }
        if (-not $result.RootFound) {
            Write-Info 'No self-issued CA certificate in the response: the SCEP client cannot locate the CA. Check that the CA chain is published and pass -CaIdentifier.' 'Warn'
        }
        if (-not $result.RaSigningFound) {
            Write-Info 'No Certificate Request Agent certificate in the response: enrolment will fail. Check that NDES has its RA certificates (MSCEP SignatureTemplate).' 'Warn'
        }
    }
    else {
        Write-Info ('GetCACert failed: {0}' -f (Get-HttpSummary -Response $caInfo.Response)) 'Fail'
        if ($caInfo.Response.Error) { Write-Info ("           {0}" -f $caInfo.Response.Error) 'Warn' }
        $snippet = Get-ResponseSnippet -Response $caInfo.Response
        if ($snippet) { Write-Info ('           {0}' -f $snippet) 'Warn' }
        $result.Problem = 'GetCACert failed'
        $results += $result
        continue
    }

    # ------------------------------------------------ which CA is this? ---
    # Identified before the admin step so the read-only run (-SkipEnroll) names it
    # too. The SCEP CA identifier is the MD5 of the CA certificate, which is also
    # the hash mscep_admin prints for the device administrator.
    $rootCertificate = $caInfo.Certificates | Where-Object { $_.Subject -eq $_.Issuer } | Select-Object -First 1
    if (-not $rootCertificate) {
        $rootCertificate = ($caInfo.Certificates | Where-Object { (Get-CertificatePurpose -Certificate $_) -eq 'CA' } | Select-Object -First 1)
    }
    if (-not $rootCertificate) {
        Write-Info 'Cannot enrol: no CA certificate to identify the server with' 'Fail'
        $result.Problem = 'no CA certificate'
        $results += $result
        continue
    }

    $caIdentifier = Get-Md5Hex -Bytes $rootCertificate.RawData
    $result.CaThumbprint = $caIdentifier
    Write-Info ('CA thumbprint: {0}' -f (Format-Thumbprint $caIdentifier))
    Write-CaCertificateLookup -Hash $caIdentifier -Published $caInfo.Certificates

    # -------------------------------------------------------- admin auth ---
    $anonymous = Invoke-ScepHttp -Uri $adminUri -TimeoutSec $TimeoutSec
    $result.AdminStatus = Get-HttpSummary -Response $anonymous
    $result.AdminRequiresAuth = ($anonymous.StatusCode -in 401, 403)

    if ($result.AdminRequiresAuth) {
        Write-Info ('mscep_admin rejects anonymous access ({0})' -f $result.AdminStatus) 'Ok'
    }
    elseif ($anonymous.StatusCode -eq 200) {
        Write-Info 'mscep_admin answered an anonymous request. It should require Windows authentication: anyone who can reach it can mint challenge passwords.' 'Warn'
    }
    else {
        Write-Info ('mscep_admin returned {0}' -f $result.AdminStatus) 'Warn'
    }

    if ($SkipEnroll) {
        Write-Info 'Enrolment skipped (-SkipEnroll)'
        $results += $result
        continue
    }

    # --------------------------------------------------------- challenge ---
    $password = $ChallengePassword
    $pageThumbprint = ''
    if ($password) {
        Write-Info 'Challenge password supplied on the command line'
        Write-Info ('           {0}' -f $password)
    }
    else {
        # The admin page uses the same credential as the SCEP endpoint; the
        # anonymous probe above deliberately sends none.
        $challenge = Get-AdministratorChallengePassword -AdminUri $adminUri -TimeoutSec $TimeoutSec
        if ($challenge.Password) {
            $password = $challenge.Password
            $pageThumbprint = $challenge.CaThumbprint
            Write-Info ('Challenge password: obtained ({0}, {1})' -f $challenge.Method, $challenge.Detail) 'Ok'
            Write-Info ('           password {0}' -f $password)
            Write-Info '           one-time: it is consumed by this run and expires within 60 minutes by default'
        }
        else {
            Write-Info ('Could not read a challenge password from mscep_admin ({0})' -f $challenge.Detail) 'Fail'
            Write-Info 'Pass -ChallengePassword <otp> to reuse a password you already have, or -SkipEnroll for the read-only checks.' 'Warn'
            Write-Info 'The page text is printed above; -SaveAdminPage <path> keeps the raw response for inspection.' 'Warn'
            if ($endpoint.Scheme -eq 'http') {
                Write-Info 'Over HTTP the page cannot negotiate Kerberos, so NTLM credentials travel in the clear.' 'Warn'
            }
            if ($challenge.Response -and $challenge.Response.Text -match '(?i)sufficient permission') {
                Write-Info 'The page says "You do not have sufficient permission to enroll with SCEP", which names no cause. In practice it is one of:' 'Warn'
                Write-Info '  * the app pool identity has no "Request Certificates" on the CA. mscep_admin mints the password by' 'Warn'
                Write-Info '    calling the CA as that identity, so check this first: certsrv.msc > right-click the CA >' 'Warn'
                Write-Info '    Properties > Security > the application pool account' 'Warn'
                Write-Info '  * the account you authenticated as is not a local Administrator on the NDES server' 'Warn'
                Write-Info '    (whoami /groups | findstr S-1-5-32-544)' 'Warn'
                Write-Info "  * the app pool identity cannot read the RA certificates' private keys in the machine store" 'Warn'
                Write-Info '  * the CA is unreachable from this server: the call is DCOM, so an open port 135 is not enough' 'Warn'
                Write-Info 'If the Application log has no MSCEP event, the failure happened during the CA call, before NDES could log it.' 'Warn'
            }
            $result.Problem = 'no challenge password'
            $results += $result
            continue
        }
    }
    $result.Challenge = $password

    # The page names the CA it is bound to; identify it inside the published chain.
    if ($pageThumbprint) {
        $pageMatch = $caInfo.Certificates |
            Where-Object { (Get-Md5Hex -Bytes $_.RawData) -eq $pageThumbprint } | Select-Object -First 1
        if ($pageMatch) {
            Write-Info ('mscep_admin CA thumbprint: {0} - {1} in the GetCACert chain' -f (Format-Thumbprint $pageThumbprint), $pageMatch.Subject) 'Ok'
        }
        else {
            Write-Info ('mscep_admin CA thumbprint: {0} - not in the GetCACert chain' -f (Format-Thumbprint $pageThumbprint)) 'Warn'
            Write-CaCertificateLookup -Hash $pageThumbprint -Published $caInfo.Certificates
        }
    }

    # ----------------------------------------------------------- enrol ---
    $enrollmentSubject = if ($subjectBase) { $subjectBase } else {
        New-TestSubjectName -StoreLocation $(if ($MachineContext) { 'LocalMachine' } else { 'CurrentUser' })
    }

    $session = $null

    try {
        $session = New-ScepEnrollment -ServerCertificatesBase64 $caInfo.ServerCertificatesBase64 `
            -RootCertificate $rootCertificate -SubjectName $enrollmentSubject `
            -KeyLength $KeyLength -ProviderName $KeyStorageProvider `
            -MachineContext:$MachineContext -ChallengePassword $password `
            -ServerCapabilities $caps.Text

        Write-Info ('Request ready: {0} ({1}, {2} bit)' -f $enrollmentSubject, $session.ContextName, $KeyLength)
        Write-Info ('           key container {0}' -f $session.KeyContainer)

        $message = $session.Enrollment.CreateRequestMessage($script:Base64)
        $messageBytes = [Convert]::FromBase64String($message)
        Write-Info ('PKIOperation request: {0} bytes' -f $messageBytes.Length)

        $submission = Send-ScepPkiOperation -BaseUri $baseUri -MessageBase64 $message `
            -Capabilities $caps.Capabilities -TimeoutSec $TimeoutSec

        if ($submission.Response.StatusCode -ne 200 -or -not $submission.Response.Bytes -or
            $submission.Response.Bytes.Length -eq 0) {
            $summary = Get-HttpSummary -Response $submission.Response
            Write-Info ('PKIOperation ({0}): {1}' -f $submission.Method, $summary) 'Fail'
            if ($submission.Response.Error) { Write-Info ("           {0}" -f $submission.Response.Error) 'Warn' }
            $snippet = Get-ResponseSnippet -Response $submission.Response
            if ($snippet) { Write-Info ('           {0}' -f $snippet) 'Warn' }
            if ($submission.Response.StatusCode -in 404, 413) {
                Write-Info 'A 404/413 here usually means http.sys limits: check MaxFieldLength and MaxRequestBytes under HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters.' 'Warn'
            }
            $result.Problem = 'PKIOperation failed'
            $results += $result
            continue
        }

        Write-Info ('PKIOperation ({0}): {1}, {2} bytes' -f $submission.Method, (Get-HttpSummary -Response $submission.Response), $submission.Response.Bytes.Length) 'Ok'

        $dispositionCode = $session.Enrollment.ProcessResponseMessage(
            [Convert]::ToBase64String($submission.Response.Bytes), $script:Base64)
        $disposition = if ($script:ScepDisposition.ContainsKey([int]$dispositionCode)) {
            $script:ScepDisposition[[int]$dispositionCode]
        }
        else { 'Unknown({0})' -f $dispositionCode }
        $result.Disposition = $disposition

        if ($disposition -eq 'Success') {
            $certificateBase64 = $session.Enrollment.Certificate($script:Base64)
            if ($certificateBase64) {
                $issued = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    [Convert]::FromBase64String($certificateBase64))
                $result.Issued = $issued
                $result.IssuedThumbprint = $issued.Thumbprint
                Write-Info ('Enrolment succeeded: {0}' -f $issued.Subject) 'Ok'
                Write-Info ('           thumbprint {0}' -f $issued.Thumbprint)
                Write-Info ('           issuer     {0}' -f $issued.Issuer)
                Write-Info ('           serial     {0}' -f $issued.SerialNumber)
                Write-Info ('           expires    {0}' -f $issued.NotAfter)

                # The object above is built from the response bytes, so it can never
                # report a private key. What matters is the store entry the SCEP
                # client installed: that is the certificate anyone would actually
                # use, and whether it carries its key decides if it is usable.
                $storePath = if ($MachineContext) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }
                $installed = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue |
                    Where-Object { $_.Thumbprint -eq $issued.Thumbprint } | Select-Object -First 1
                if ($installed) {
                    Write-Info ('           installed in {0}, key present: {1}' -f $storePath, $installed.HasPrivateKey)
                    if (-not $installed.HasPrivateKey) {
                        Write-Info 'The certificate is in the store but no private key is associated with it, so it cannot be used for client authentication.' 'Warn'
                    }
                }
                else {
                    Write-Info ('           not installed in {0} (the client returned it but did not store it)' -f $storePath) 'Warn'
                }

                foreach ($extension in $issued.Extensions) {
                    if ($extension.Oid.Value -eq $script:OidCertificateRequestAgent) {
                        Write-Info '           This certificate is itself an enrolment agent certificate (Certificate Request Agent EKU).' 'Warn'
                    }
                }

                if ($OutFile) {
                    [System.IO.File]::WriteAllBytes($OutFile, $issued.RawData)
                    Write-Info ('           written to {0}' -f $OutFile) 'Ok'
                }
            }
            else {
                Write-Info 'Disposition was Success but no certificate was returned' 'Warn'
            }
        }
        elseif ($disposition -eq 'Failure') {
            $failInfoCode = [int]$session.Enrollment.FailInfo()
            $failInfo = if ($script:ScepFailInfo.ContainsKey($failInfoCode)) { $script:ScepFailInfo[$failInfoCode] } else { 'unknown' }
            Write-Info ('Enrolment rejected: {0} ({1})' -f $failInfo, $failInfoCode) 'Fail'
            try {
                $status = $session.Enrollment.Status()
                if ($status -and $status.Text) { Write-Info ('           {0}' -f $status.Text) 'Warn' }
            }
            catch { Write-Verbose "No status text: $($_.Exception.Message)" }
            Write-Info 'The CA or NDES policy rejected the request. The usual causes are an expired or already-used challenge password, a template the device cannot enrol, or the CA refusing the RA signature.' 'Warn'
            $result.Problem = 'enrolment rejected'
        }
        elseif ($disposition -eq 'Pending') {
            Write-Info 'Enrolment is pending: the request needs approval on the CA, then poll with a retrieve-pending message.' 'Warn'
            $result.Problem = 'pending approval'
        }
        elseif ($disposition -eq 'PendingChallenge') {
            Write-Info 'The server wants another challenge exchange (PendingChallenge); this client only does the one-shot flow.' 'Warn'
            $result.Problem = 'pending challenge'
        }
        else {
            Write-Info ('Unhandled disposition: {0}' -f $disposition) 'Warn'
            $result.Problem = 'unhandled disposition'
        }
    }
    catch {
        $errorText = $_.Exception.Message
        $firstLine = ($errorText -split "`r?`n")[0]
        Write-Info ('Enrolment error: {0}' -f $firstLine) 'Fail'

        # A rejected request arrives as an exception, not as a disposition, so the
        # PKI status reported inside the message is the only reason available.
        if ($errorText -match '(?i)PkiStatus\((\d+)\)') {
            Write-Info ('           PKI status {0} (2 = failure)' -f $Matches[1]) 'Warn'
        }
        if ($errorText -match '(?i)EnrollStatus\((\d+)\)') {
            Write-Info ('           enrol status {0}' -f $Matches[1]) 'Warn'
        }
        try {
            $failInfoCode = [int]$session.Enrollment.FailInfo()
            $failInfo = if ($script:ScepFailInfo.ContainsKey($failInfoCode)) { $script:ScepFailInfo[$failInfoCode] } else { "unknown ($failInfoCode)" }
            Write-Info ('           fail info: {0}' -f $failInfo) 'Warn'
        }
        catch { Write-Verbose "FailInfo not available: $($_.Exception.Message)" }
        try {
            $status = $session.Enrollment.Status()
            if ($status -and $status.Text) { Write-Info ('           {0}' -f $status.Text) 'Warn' }
        }
        catch { Write-Verbose "Status not available: $($_.Exception.Message)" }

        if ($errorText -match '(?i)PkiStatus\(2\)|SCEPDispositionFailure') {
            if ($errorText -notmatch 'CRYPT_E_ASN1') {
                Write-Info 'The CA or NDES policy rejected the request. Usual causes: challenge password wrong or already used, a template the device cannot enrol, or the CA refusing the RA signature.' 'Warn'
            }
        }
        if ($errorText -match 'CRYPT_E_EXISTS|0x80092005') {
            Write-Info 'CRYPT_E_EXISTS means the server certificate set is ambiguous: NDES must publish exactly one RA signing (Certificate Request Agent) and one RA encryption certificate.' 'Warn'
        }
        if ($errorText -match 'CRYPT_E_NO_MATCH|0x80092009|SCARD_E_NO_SUCH_CERTIFICATE|0x8010002c') {
            Write-Info 'The SCEP client could not find the CA or the RA signing certificate in what GetCACert returned.' 'Warn'
        }
        if ($errorText -match 'CRYPT_E_ASN1_BADTAG|0x8009310b|CRYPT_E_ASN1') {
            Write-Info 'The response was not a valid SCEP CertRep. Check what the endpoint actually returns for PKIOperation - a proxy or a custom error page in front of mscep.dll produces exactly this.' 'Warn'
        }
        $result.Problem = 'enrolment error'
    }
    finally {
        if ($session) {
            if ($Cleanup) {
                $deleted = $false
                try {
                    $session.Enrollment.DeleteRequest()
                    $deleted = $true
                }
                catch { Write-Verbose "DeleteRequest failed: $($_.Exception.Message)" }

                $removed = Remove-TestRequestArtifacts -StoreLocation $session.StoreLocation `
                    -SubjectName $enrollmentSubject -ProviderName $KeyStorageProvider -ContainerName $session.KeyContainer

                if ($deleted) {
                    $result.Issued = $null
                    Write-Info 'Cleanup: test request, key and certificate removed' 'Ok'
                }
                elseif ($removed -gt 0) {
                    $result.Issued = $null
                    Write-Info ('Cleanup: removed {0} test certificate(s) and the key container' -f $removed) 'Ok'
                }
                else {
                    Write-Info 'Cleanup: nothing was left in the certificate store' 'Ok'
                }
            }
            else {
                $storeLocation = if ($MachineContext) { 'LocalMachine' } else { 'CurrentUser' }
                Write-Info 'Keeping the test certificate and key (-Cleanup removes them)'
                Write-Info ('           {0}\{1}' -f $storeLocation, $enrollmentSubject)
                if ($result.IssuedThumbprint) {
                    Write-Info ('           thumbprint {0}' -f $result.IssuedThumbprint)
                    Write-Info ('           remove with: Remove-Item Cert:\{0}\My\{1} -Force' -f $storeLocation, $result.IssuedThumbprint)
                    $userSwitch = if ($MachineContext) { '' } else { '-user ' }
                    Write-Info ('                        certutil {0}-csp "{1}" -delkey {2}' -f $userSwitch, $KeyStorageProvider, $session.KeyContainer)
                }
            }

            foreach ($comObject in @($session.Enrollment, $session.Request, $session.PrivateKey)) {
                if ($comObject) {
                    try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($comObject) } catch { }
                }
            }
        }
    }

    $results += $result
}

# --------------------------------------------------------------- summary ---

Write-Step 'Summary'

foreach ($result in $results) {
    $level = if ($result.Problem) { 'Fail' } else { 'Ok' }
    $detail = if ($result.Problem) {
        $result.Problem
    }
    elseif ($SkipEnroll) {
        'read-only checks passed'
    }
    else {
        'enrolment succeeded'
    }
    Write-Info ('{0,-5} {1} - {2}' -f $result.Protocol.ToUpperInvariant(), $detail, $result.BaseUri) $level
    if ($result.Capabilities.Count -gt 0) {
        Write-Info ('        {0}' -f ($result.Capabilities -join ', '))
    }
    if ($result.CaThumbprint) {
        Write-Info ('        CA thumbprint {0}' -f (Format-Thumbprint $result.CaThumbprint))
    }
    if ($result.Challenge) {
        Write-Info ('        challenge password {0}' -f $result.Challenge)
    }
    if ($result.IssuedThumbprint) {
        $kept = if ($Cleanup) { 'removed' } else { 'kept' }
        Write-Info ('        certificate {0} ({1})' -f $result.IssuedThumbprint, $kept)
    }
}

$failures = @($results | Where-Object { $_.Problem })
if ($failures.Count -eq 0) {
    Write-Info 'All endpoint tests passed.'
}
else {
    Write-Info ('{0} of {1} endpoint test(s) failed.' -f $failures.Count, $results.Count) 'Warn'
}
