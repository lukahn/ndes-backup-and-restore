<#
    Dumps the certificate-template attributes that decide whether a template can be
    enrolled by a COMPUTER. Run on any domain-joined machine (subCA is ideal).

    Positive controls: CEPEncryption and NDESServer both enrolled as NDES$ here.
    Negative controls: EnrollmentAgent, EnrollmentAgentOffline, NDESUser all refuse.

    The flag that decides whether a computer can enrol the template at all is
    'flags' bit 0x40 (machine type). Everything else is secondary: without it the
    enrolment API rejects a LocalMachine\My request before any ACL is consulted.

    Also shown: msPKI-Certificate-Name-Flag
      0x1        ENROLLEE_SUPPLIES_SUBJECT  - subject comes from the request
      0x1000000  SUBJECT_REQUIRE_DIRECTORY_PATH - subject must be built from AD
    #>
param([string[]]$Templates = @('CEPEncryption', 'EnrollmentAgent', 'EnrollmentAgentOffline', 'NDESUser', 'NDESServer', 'User'))

$rootDse = [ADSI]'LDAP://RootDSE'
$base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
$searchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$base")
$searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
$searcher.Filter = '(objectClass=pKICertificateTemplate)'
$searcher.PageSize = 200
$wanted = @('cn', 'displayName', 'flags', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
    'msPKI-RA-Signature', 'msPKI-Certificate-Application-Policy', 'pKIExtendedKeyUsage', 'msPKI-Cert-Template-OID')
foreach ($p in $wanted) { [void]$searcher.PropertiesToLoad.Add($p) }

function Get-FirstProp {
    param($Result, [string]$Name)
    $p = $Result.Properties[$Name]
    if ($null -eq $p -or $p.Count -eq 0) { return $null }
    return $p[0]
}

$rows = foreach ($result in $searcher.FindAll()) {
    $cn = [string](Get-FirstProp -Result $result -Name 'cn')
    if ($Templates -notcontains $cn) { continue }

    $nameFlag = Get-FirstProp -Result $result -Name 'msPKI-Certificate-Name-Flag'
    $enrollFlag = Get-FirstProp -Result $result -Name 'msPKI-Enrollment-Flag'
    $nameInt = if ($null -ne $nameFlag) { [int64]$nameFlag } else { $null }
    $enrollInt = if ($null -ne $enrollFlag) { [int64]$enrollFlag } else { $null }
    $flagsInt = Get-FirstProp -Result $result -Name 'flags'
    if ($null -ne $flagsInt) { $flagsInt = [int64]$flagsInt }

    # bit 0x40 is what actually decides whether a computer can enrol this template;
    # it outranks every other attribute when diagnosing a machine-store request.
    $type = if ($null -eq $flagsInt) { 'unknown' }
    elseif (($flagsInt -band 0x40) -ne 0) { 'computer can enrol' }
    else { 'user only - refuses LocalMachine\My' }

    $subject = if ($null -eq $nameInt) { 'unknown' }
    elseif (($nameInt -band 0x1) -ne 0) { 'supplied in request (machine OK)' }
    elseif (($nameInt -band 0x1000000) -ne 0) { 'built from AD (user only)' }
    else { 'other' }

    [pscustomobject]@{
        Template       = $cn
        FlagsHex       = if ($null -ne $flagsInt) { '0x{0:X}' -f $flagsInt } else { '' }
        Type           = $type
        NameFlagHex    = if ($null -ne $nameInt) { '0x{0:X}' -f $nameInt } else { '' }
        EnrollFlagHex  = if ($null -ne $enrollInt) { '0x{0:X}' -f $enrollInt } else { '' }
        SubjectSource  = $subject
        RA_Signatures  = [string](Get-FirstProp -Result $result -Name 'msPKI-RA-Signature')
        EKU            = ((@((Get-FirstProp -Result $result -Name 'pKIExtendedKeyUsage')) -join ','))
        OID            = [string](Get-FirstProp -Result $result -Name 'msPKI-Cert-Template-OID')
    }
}

$rows | Sort-Object Template | Format-Table -AutoSize | Out-String -Width 220
