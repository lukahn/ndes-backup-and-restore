<#
.SYNOPSIS
    Collects what is needed to explain a 503 on the SCEP endpoints.

.DESCRIPTION
    Run elevated on the NDES server. Read-only: it inspects IIS, the worker
    process, WAS and the Application log, then proves the service account can
    actually log on.

.PARAMETER ServiceAccount
    The SCEP application pool account, in DOMAIN\User form. Omit it and the
    credential prompt asks for both.
#>
param([string]$ServiceAccount)

# Collects what is needed to explain the 503 on the SCEP endpoints.
# Run elevated on the NDES server.

$appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"

"=== site ==="
& $appcmd list site

"`n=== app pool ==="
& $appcmd list apppool SCEP
& $appcmd list apppool SCEP /text:*

"`n=== is the worker running? ==="
Get-Process w3wp -ErrorAction SilentlyContinue | Select-Object Id, StartTime, Path | Format-Table -AutoSize

"`n=== last 30 minutes: WAS / worker / mscep ==="
$since = (Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'WAS|Application Error|Windows Error Reporting|IIS|mscep|Certificate' -or $_.Message -match 'mscep|w3wp|SCEP' } |
    Select-Object -First 15 TimeCreated, ProviderName, Id, @{n = 'Msg'; e = { (($_.Message -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 3) -join ' | ' } } |
    Format-List

"`n=== WAS operational log ==="
Get-WinEvent -LogName 'Microsoft-Windows-WAS/Operational' -MaxEvents 15 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, @{n = 'Msg'; e = { (($_.Message -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' | ' } } |
    Format-List

"`n=== can the identity actually log on? ==="
$cred = Get-Credential -UserName $ServiceAccount -Message 'Enter the service account password'
try {
    $p = Start-Process -FilePath "$env:SystemRoot\System32\whoami.exe" -Credential $cred -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\whoami.txt"
    "logon exit=$($p.ExitCode);  identity: " + (Get-Content "$env:TEMP\whoami.txt" -ErrorAction SilentlyContinue)
    Remove-Item "$env:TEMP\whoami.txt" -Force -ErrorAction SilentlyContinue
}
catch { "logon FAILED: " + $_.Exception.Message }

"`n=== http.sys request queues for the site ==="
& netsh http show servicestate view=requestq 2>&1 | Select-String -Pattern 'SCEP|Default Web Site|Request queue name' | Select-Object -First 12
