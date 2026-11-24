#Requires -Version 5.1
# NdesCapture - instrumentation + diff engine for lab capture of an NDES install.
# Written for Windows Server 2019 / Windows PowerShell 5.1.

$script:LogPath = $null

# ---------------------------------------------------------------- helpers ---

function Set-CaptureLogPath {
    param([Parameter(Mandatory)][string]$Path, [switch]$Truncate)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ($Truncate -and (Test-Path -LiteralPath $Path)) { Remove-Item -LiteralPath $Path -Force }
    $script:LogPath = $Path
}

function Write-CaptureLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'STEP')][string]$Level = 'INFO'
    )
    $line = '{0} [{1,-5}] {2}' -f (Get-Date).ToString('HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN' { Write-Host $line -ForegroundColor Yellow }
        'STEP' { Write-Host $line -ForegroundColor Cyan }
        default { Write-Host $line }
    }
    if ($script:LogPath) { Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 }
}

function Invoke-CaptureStep {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [switch]$Optional
    )
    Write-CaptureLog "collect $Name" -Level STEP
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        $sw.Stop()
        Write-CaptureLog ('  ok ({0:N1}s)' -f $sw.Elapsed.TotalSeconds)
        return [pscustomobject]@{ Collector = $Name; Status = 'Ok'; Detail = '' }
    }
    catch {
        $sw.Stop()
        $level = 'WARN'
        if (-not $Optional) { $level = 'ERROR' }
        Write-CaptureLog ('  {0}: {1}' -f $(if ($Optional) { 'skipped' } else { 'FAILED' }), $_.Exception.Message) -Level $level
        $status = 'Failed'
        if ($Optional) { $status = 'Skipped' }
        return [pscustomobject]@{ Collector = $Name; Status = $status; Detail = $_.Exception.Message }
    }
}

function New-CaptureSubdir {
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Name)
    $path = Join-Path $Base $Name
    if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
    return $path
}

function Write-JsonFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$InputObject, [int]$Depth = 10)
    $json = $InputObject | ConvertTo-Json -Depth $Depth
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function Get-DefaultSettings {
    return [ordered]@{
        Registry = @{
            DefaultHives = @(
                'HKEY_LOCAL_MACHINE\SOFTWARE'
                'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services'
                'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control'
            )
        }
        Files    = @{
            Mode      = 'Auto'
            Volume    = 'C:'
            Roots     = @(
                'C:\Windows\System32\certsrv'
                'C:\Windows\System32\inetsrv'
                'C:\ProgramData\Microsoft\Crypto'
            )
            HashRoots = @(
                'C:\Windows\System32\certsrv'
                'C:\Windows\System32\inetsrv\config'
            )
        }
        Ad       = @{
            ExportDomainNc        = $true
            ExportConfigurationNc = $true
            MaxAuditEvents        = 50000
            OmitAttributes        = @(
                'whenCreated'
                'whenChanged'
                'uSNCreated'
                'uSNChanged'
                'replPropertyMetaData'
                'dSCorePropagationData'
                'msDS-GenerationId'
                'objectGUID'
                'objectSid'
            )
        }
        Iis      = @{ Enabled = $true }
        FileAudit = @{
            Enabled        = $false
            Paths          = @('C:\Windows\System32\CertLog')
            MaxEvents      = 50000
            AuditPrincipal = 'Everyone'
        }
        Scenarios = @{}
        Signal   = @{
            HighPatterns  = @(
                'registry\|.*\\Microsoft\\Cryptography\\MSCEP'
                'registry\|.*\\Services\\SCEP'
                'registry\|.*\\Services\\CertSvc'
                'registry\|.*\\Microsoft\\ADCS'
                'iis\|'
                'ad\|'
                'certs\|'
            )
            NoisePatterns = @(
                'files\|.*\\Prefetch\\'
                'files\|.*\\Temp\\'
                'files\|.*\\WinSxS\\'
            )
        }
    }
}

function Get-ScenarioProfile {
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$Name
    )
    if (-not $Settings.Contains('Scenarios') -or -not $Settings.Scenarios.ContainsKey($Name)) {
        $available = 'none defined - is config\capture-settings.psd1 present beside the scripts?'
        if ($Settings.Contains('Scenarios') -and $Settings.Scenarios.Count -gt 0) {
            $available = (@($Settings.Scenarios.Keys) | Sort-Object) -join ', '
        }
        throw ("Unknown scenario '{0}'. Available scenarios: {1}" -f $Name, $available)
    }
    return $Settings.Scenarios[$Name]
}

function Import-CaptureSettings {
    param([string]$Path, [string]$Scenario)
    $settings = Get-DefaultSettings
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $user = Import-PowerShellDataFile -LiteralPath $Path
        foreach ($key in $user.Keys) {
            if ($settings.Contains($key) -and $settings[$key] -is [hashtable] -and $user[$key] -is [hashtable]) {
                foreach ($subKey in $user[$key].Keys) { $settings[$key][$subKey] = $user[$key][$subKey] }
            }
            else {
                $settings[$key] = $user[$key]
            }
        }
    }

    if ($Scenario) {
        # NB: named scenarioConfig, not the built-in automatic variable for
        # the PowerShell profile path.
        $scenarioConfig = Get-ScenarioProfile -Settings $settings -Name $Scenario
        $settings['Scenario'] = @{
            Name                   = $Scenario
            Description            = [string]$scenarioConfig.Description
            IncludeConfigurationNc = [bool]$scenarioConfig.IncludeConfigurationNc
            AdFocusPatterns        = @($scenarioConfig.AdFocusPatterns)
            NoisePatterns          = @($scenarioConfig.NoisePatterns)
        }
        if (@($scenarioConfig.HighPatterns).Count -gt 0) { $settings.Signal.HighPatterns = @($scenarioConfig.HighPatterns) }
    }

    return $settings
}

function Save-CaptureState {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$State)
    Write-JsonFile -Path $Path -InputObject $State
}

function Get-CaptureState {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Capture state not found: $Path" }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

# ------------------------------------------------------------ environment ---

function Test-IsDomainController {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        return ([int]$cs.DomainRole -ge 4)
    }
    catch { return $false }
}

function Test-HasIis {
    $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
    return (Test-Path -LiteralPath $appcmd)
}

function Test-HasCertificationAuthority {
    return (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc')
}

# ------------------------------------------------------------- USN journal ---

function ConvertTo-UsnNumber {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.Trim()
    if ($t -match '^0[xX]([0-9a-fA-F]+)$') {
        return [int64][System.Convert]::ToUInt64($Matches[1], 16)
    }
    return [int64]$t
}

function Get-UsnJournalState {
    param([string]$Volume = 'C:')
    $out = & fsutil.exe usn queryjournal $Volume 2>&1
    if ($LASTEXITCODE -ne 0) { throw (($out | Out-String).Trim()) }

    $map = @{}
    foreach ($line in $out) {
        if ($line -match '^\s*([^:]+?)\s*:\s*(.+?)\s*$') { $map[$Matches[1].Trim()] = $Matches[2].Trim() }
    }
    if (-not $map.ContainsKey('Next Usn')) { throw "Unexpected fsutil output for $Volume" }

    return [pscustomobject]@{
        Volume    = $Volume
        JournalId = $map['Usn Journal ID']
        FirstUsn  = ConvertTo-UsnNumber $map['First Usn']
        NextUsn   = ConvertTo-UsnNumber $map['Next Usn']
    }
}

function Get-UsnReasonFlags {
    # NB: numeric hashtable keys are unreliable here (ordered dictionaries
    # mis-associate values, and 0x80000000 wraps to a negative Int32), so this
    # uses an explicit mask/name table.
    param([int64]$Reason)
    $table = @(
        [pscustomobject]@{ Mask = 0x00000001L; Name = 'DataOverwrite' }
        [pscustomobject]@{ Mask = 0x00000002L; Name = 'DataExtend' }
        [pscustomobject]@{ Mask = 0x00000004L; Name = 'DataTruncation' }
        [pscustomobject]@{ Mask = 0x00000100L; Name = 'Create' }
        [pscustomobject]@{ Mask = 0x00000200L; Name = 'Delete' }
        [pscustomobject]@{ Mask = 0x00000400L; Name = 'EaChange' }
        [pscustomobject]@{ Mask = 0x00000800L; Name = 'SecurityChange' }
        [pscustomobject]@{ Mask = 0x00001000L; Name = 'RenameOldName' }
        [pscustomobject]@{ Mask = 0x00002000L; Name = 'RenameNewName' }
        [pscustomobject]@{ Mask = 0x00004000L; Name = 'IndexableChange' }
        [pscustomobject]@{ Mask = 0x00008000L; Name = 'BasicInfoChange' }
        [pscustomobject]@{ Mask = 0x00010000L; Name = 'HardLinkChange' }
        [pscustomobject]@{ Mask = 0x00020000L; Name = 'CompressionChange' }
        [pscustomobject]@{ Mask = 0x00040000L; Name = 'EncryptionChange' }
        [pscustomobject]@{ Mask = 0x00080000L; Name = 'ObjectIdChange' }
        [pscustomobject]@{ Mask = 0x00100000L; Name = 'ReparsePointChange' }
        [pscustomobject]@{ Mask = 0x00200000L; Name = 'StreamChange' }
        [pscustomobject]@{ Mask = 0x00400000L; Name = 'TransactedChange' }
        [pscustomobject]@{ Mask = 0x00800000L; Name = 'IntegrityChange' }
        [pscustomobject]@{ Mask = 0x80000000L; Name = 'Close' }
    )
    $names = foreach ($entry in $table) {
        if (($Reason -band $entry.Mask) -ne 0) { $entry.Name }
    }
    return (@($names) -join ',')
}

function ConvertTo-FullPath {
    <#
        fsutil reports USN paths volume-relative (\Windows\System32\...) or, in
        some builds, as \??\C:\... . Normalise both to a full path so reports
        and filters work on a real location.
    #>
    param(
        [AllowEmptyString()][AllowNull()][string]$Path,
        [string]$Volume = 'C:'
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = $Path.Trim()

    if ($p -match '^\\\?\?\\') { $p = $p.Substring(4) }
    elseif ($p -match '^\\\?\\') { $p = $p.Substring(3) }

    if ($p -match '^[A-Za-z]:') { return $p }

    $root = $Volume.TrimEnd('\', ':') + ':'
    if ($p.StartsWith('\')) { return $root + $p }
    return $root + '\' + $p
}

function ConvertFrom-UsnCsv {
    <#
        Parses `fsutil usn readjournal <vol> csv` output. The csv variant is
        undocumented, so columns are resolved by name with fallbacks.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Volume = 'C:'
    )

    $lines = [System.IO.File]::ReadAllLines($Path)
    $headerIndex = -1
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match '^\s*"?Usn"?\s*,') { $headerIndex = $i; break }
    }
    if ($headerIndex -lt 0) { throw 'No USN CSV header found in fsutil output.' }

    $text = ($lines[$headerIndex..($lines.Length - 1)]) -join "`r`n"
    $rows = @($text | ConvertFrom-Csv)
    if ($rows.Count -eq 0) { return @() }

    $columns = @($rows[0].PSObject.Properties.Name)
    $pathColumn = @('FileName', 'File name', 'FilePath', 'Name') | Where-Object { $columns -contains $_ } | Select-Object -First 1
    if (-not $pathColumn) { throw ('Unrecognised USN CSV columns: {0}' -f ($columns -join ',')) }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($row in $rows) {
        $usn = $null
        try { $usn = ConvertTo-UsnNumber $row.Usn } catch { continue }
        if ($null -eq $usn) { continue }

        $reasonText = ''
        if ($columns -contains 'Reason') { $reasonText = [string]$row.Reason }
        $reasonValue = 0L
        if ($reasonText -match '^0[xX]([0-9a-fA-F]+)') {
            $reasonValue = [int64][System.Convert]::ToUInt64($Matches[1], 16)
        }

        $timestamp = ''
        foreach ($candidate in @('Timestamp', 'Time')) {
            if ($columns -contains $candidate) { $timestamp = [string]$row.$candidate; break }
        }

        $results.Add([pscustomobject]@{
                Usn       = $usn
                Path      = (ConvertTo-FullPath -Path ([string]$row.$pathColumn) -Volume $Volume)
                Reason    = (Get-UsnReasonFlags -Reason $reasonValue)
                RawReason = $reasonText
                Timestamp = $timestamp
            })
    }
    return $results
}

function Get-UsnApiSource {
    return @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public class NdesUsnRecord
{
    public long Usn;
    public long FileTimeUtc;
    public uint Reason;
    public uint FileAttributes;
    public string Path;
}

public static class NdesUsn
{
    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 0x00000001;
    const uint FILE_SHARE_WRITE = 0x00000002;
    const uint FILE_SHARE_DELETE = 0x00000004;
    const uint OPEN_EXISTING = 3;
    const uint FSCTL_READ_USN_JOURNAL = 0x000900BB;
    const uint ERROR_HANDLE_EOF = 38;
    const uint ERROR_JOURNAL_DELETE_IN_PROGRESS = 1178;
    const uint ERROR_JOURNAL_NOT_ACTIVE = 1179;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
    static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode,
        byte[] lpInBuffer, uint nInBufferSize, byte[] lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    // READ_USN_JOURNAL_DATA_V1. Min/MaxMajorVersion pinned to 2 so only
    // USN_RECORD_V2 structures come back, which have a fixed, known layout.
    // Requesting V2 avoids having to guess the V3 header layout.
    static byte[] BuildRequest(long startUsn, long journalId)
    {
        byte[] req = new byte[48];
        Buffer.BlockCopy(BitConverter.GetBytes(startUsn), 0, req, 0, 8);
        Buffer.BlockCopy(BitConverter.GetBytes((uint)0xFFFFFFFF), 0, req, 8, 4);   // ReasonMask: all
        Buffer.BlockCopy(BitConverter.GetBytes((uint)0), 0, req, 12, 4);           // ReturnOnlyOnClose: no
        Buffer.BlockCopy(BitConverter.GetBytes((long)0), 0, req, 16, 8);           // Timeout
        Buffer.BlockCopy(BitConverter.GetBytes((long)0), 0, req, 24, 8);           // BytesToWaitFor
        Buffer.BlockCopy(BitConverter.GetBytes(journalId), 0, req, 32, 8);
        Buffer.BlockCopy(BitConverter.GetBytes((short)2), 0, req, 40, 2);          // MinMajorVersion
        Buffer.BlockCopy(BitConverter.GetBytes((short)2), 0, req, 42, 2);          // MaxMajorVersion
        return req;
    }

    /// Parses a raw FSCTL_READ_USN_JOURNAL result buffer. Split out so the
    /// record layout can be tested without a live journal.
    public static List<NdesUsnRecord> ParseBuffer(byte[] buffer, int length, long startUsn)
    {
        List<NdesUsnRecord> results = new List<NdesUsnRecord>();
        if (buffer == null || length < 8) { return results; }

        int offset = 8; // first 8 bytes are the next USN to resume from
        while (offset + 8 <= length)
        {
            int recordLength = BitConverter.ToInt32(buffer, offset);
            if (recordLength < 60 || offset + recordLength > length) { break; }

            short majorVersion = BitConverter.ToInt16(buffer, offset + 4);
            if (majorVersion != 2) { break; }

            long usn = BitConverter.ToInt64(buffer, offset + 24);
            long fileTime = BitConverter.ToInt64(buffer, offset + 32);
            uint reason = BitConverter.ToUInt32(buffer, offset + 40);
            uint attributes = BitConverter.ToUInt32(buffer, offset + 52);
            int nameLength = BitConverter.ToInt16(buffer, offset + 56);
            int nameOffset = BitConverter.ToInt16(buffer, offset + 58);

            if (usn > startUsn && nameLength > 0 && offset + nameOffset + nameLength <= length)
            {
                NdesUsnRecord rec = new NdesUsnRecord();
                rec.Usn = usn;
                rec.FileTimeUtc = fileTime;
                rec.Reason = reason;
                rec.FileAttributes = attributes;
                rec.Path = Encoding.Unicode.GetString(buffer, offset + nameOffset, nameLength);
                results.Add(rec);
            }

            offset += recordLength;
        }
        return results;
    }

    /// Reads journal records newer than startUsn, up to stopUsn (or the end).
    public static List<NdesUsnRecord> Read(string volume, long startUsn, long stopUsn, long journalId, out string error)
    {
        error = null;
        List<NdesUsnRecord> results = new List<NdesUsnRecord>();
        string device = @"\\.\" + volume.TrimEnd('\\');

        using (SafeFileHandle handle = CreateFileW(device, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                error = "Cannot open " + device + " for reading (Win32 error " + Marshal.GetLastWin32Error() + "). Administrator rights are required.";
                return results;
            }

            byte[] request = BuildRequest(startUsn, journalId);
            byte[] output = new byte[1024 * 1024];
            long cursor = startUsn;

            while (true)
            {
                // Advance the request's StartUsn field without rebuilding the array.
                Buffer.BlockCopy(BitConverter.GetBytes(cursor), 0, request, 0, 8);

                uint returned;
                bool ok = DeviceIoControl(handle, FSCTL_READ_USN_JOURNAL, request, (uint)request.Length,
                    output, (uint)output.Length, out returned, IntPtr.Zero);

                if (!ok)
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == (int)ERROR_HANDLE_EOF) { break; }
                    if (err == (int)ERROR_JOURNAL_DELETE_IN_PROGRESS)
                    {
                        error = "The USN journal is being deleted; file evidence is unavailable.";
                        break;
                    }
                    if (err == (int)ERROR_JOURNAL_NOT_ACTIVE)
                    {
                        error = "No active USN journal on " + volume + ".";
                        break;
                    }
                    error = "FSCTL_READ_USN_JOURNAL failed (Win32 error " + err + ").";
                    break;
                }

                if (returned <= 8) { break; }

                long next = BitConverter.ToInt64(output, 0);
                List<NdesUsnRecord> batch = ParseBuffer(output, (int)returned, cursor - 1);
                results.AddRange(batch);

                if (next <= cursor) { break; }
                cursor = next;
                if (cursor > stopUsn) { break; }
            }
        }

        return results;
    }
}
'@
}

function Initialize-UsnApi {
    if (-not ('NdesUsn' -as [type])) {
        Add-Type -TypeDefinition (Get-UsnApiSource) -Language CSharp -ErrorAction Stop
    }
}

function Read-UsnJournalApi {
    <#
        Reads changed paths straight from the NTFS change journal via
        FSCTL_READ_USN_JOURNAL. Preferred over parsing fsutil output: the text
        format is undocumented and varies between builds, and silently yields
        bare file names with no path, reason or timestamp when it does not match.
    #>
    param(
        [string]$Volume = 'C:',
        [Parameter(Mandatory)][int64]$StartUsn,
        [int64]$StopUsn = [int64]::MaxValue,
        [Parameter(Mandatory)][string]$JournalId
    )

    Initialize-UsnApi

    $journalIdValue = [int64]0
    if ($JournalId -match '^0[xX]([0-9a-fA-F]+)$') {
        $journalIdValue = [int64][System.Convert]::ToUInt64($Matches[1], 16)
    }
    else {
        $journalIdValue = [int64]$JournalId
    }

    $errorText = ''
    $records = [NdesUsn]::Read($Volume, $StartUsn, $StopUsn, $journalIdValue, [ref]$errorText)
    if ($errorText) { throw $errorText }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($rec in $records) {
        $when = ''
        try { $when = [System.DateTime]::FromFileTimeUtc($rec.FileTimeUtc).ToString('o') } catch { }
        $results.Add([pscustomobject]@{
                Usn       = [int64]$rec.Usn
                Path      = (ConvertTo-FullPath -Path ([string]$rec.Path) -Volume $Volume)
                Reason    = (Get-UsnReasonFlags -Reason ([int64]$rec.Reason))
                RawReason = ('0x{0:X8}' -f $rec.Reason)
                Timestamp = $when
            })
    }
    return $results
}

function Test-UsnPathsLookValid {
    <#
        Guards against a silently mis-parsed journal: if the "paths" are bare
        file names, the evidence is worthless and the caller must not trust it.
    #>
    param($Records)
    $rows = @($Records | ForEach-Object { $_ })
    if ($rows.Count -eq 0) { return $true }
    $withPath = @($rows | Where-Object { $_.Path -match '[\\/]' }).Count
    return (($withPath / $rows.Count) -ge 0.5)
}

function Read-UsnJournal {
    param([string]$Volume = 'C:', [int64]$StartUsn = 0, [int64]$StopUsn = [int64]::MaxValue, [string]$JournalId)

    # Preferred: direct API read.
    try {
        $apiRecords = Read-UsnJournalApi -Volume $Volume -StartUsn $StartUsn -StopUsn $StopUsn -JournalId $JournalId
        if (Test-UsnPathsLookValid -Records $apiRecords) {
            Write-CaptureLog ('  journal read via API: {0} record(s)' -f @($apiRecords).Count)
            return $apiRecords
        }
        Write-CaptureLog '  API journal read returned paths without directories - falling back to fsutil' -Level WARN
    }
    catch {
        Write-CaptureLog ('  API journal read unavailable ({0}) - falling back to fsutil' -f $_.Exception.Message) -Level WARN
    }

    # Fallback: parse fsutil output, then validate it.
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        Write-CaptureLog "  reading USN journal on $Volume from USN $StartUsn via fsutil"

        $withStart = "fsutil usn readjournal $Volume csv startusn=$('0x{0:X}' -f $StartUsn)"
        & cmd.exe /c "$withStart > `"$tmp`" 2>nul" | Out-Null
        $ok = ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $tmp) -and (Get-Item -LiteralPath $tmp).Length -gt 0)

        if (-not $ok) {
            & cmd.exe /c "fsutil usn readjournal $Volume csv > `"$tmp`" 2>nul" | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "fsutil usn readjournal $Volume failed - run elevated (administrator rights required)."
            }
        }

        $records = ConvertFrom-UsnCsv -Path $tmp -Volume $Volume
        if (-not (Test-UsnPathsLookValid -Records $records)) {
            throw ('fsutil output contained {0} entries but none carried a directory path; the format was not understood.' -f @($records).Count)
        }
        return $records
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- registry ---

function ConvertFrom-RegFile {
    <#
        Parses a `reg export` file into Key/Name/Data rows.
        Continuation lines (trailing backslash) are joined so byte-identical
        exports compare equal regardless of wrapping.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Registry export not found: $Path" }

    $lines = [System.IO.File]::ReadAllLines($Path)
    $currentKey = $null
    $pending = $null
    $pendingName = $null
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($rawLine in $lines) {
        $line = $rawLine.TrimEnd()

        if ($null -ne $pending) {
            if ($line.EndsWith('\')) {
                [void]$pending.Append($line.Substring(0, $line.Length - 1))
            }
            else {
                [void]$pending.Append($line)
                $results.Add([pscustomobject]@{ Key = $currentKey; Name = $pendingName; Data = $pending.ToString() })
                $pending = $null
                $pendingName = $null
            }
            continue
        }

        $trim = $line.Trim()
        if ($trim.Length -eq 0) { continue }
        if ($trim.StartsWith(';')) { continue }
        if ($trim.StartsWith('Windows Registry Editor')) { continue }

        if ($trim.StartsWith('[')) {
            $end = $trim.IndexOf(']')
            if ($end -gt 1) {
                $currentKey = $trim.Substring(1, $end - 1)
                if ($currentKey.StartsWith('-')) { $currentKey = $currentKey.Substring(1) }
            }
            continue
        }

        if ($null -eq $currentKey) { continue }

        $name = $null
        $data = $null
        if ($trim.StartsWith('@=')) {
            $name = ''
            $data = $trim.Substring(2)
        }
        elseif ($trim.StartsWith('"')) {
            $m = [regex]::Match($trim, '^"((?:[^"\\]|\\.)*)"=(.*)$')
            if (-not $m.Success) { continue }
            $name = $m.Groups[1].Value
            $data = $m.Groups[2].Value
        }
        else { continue }

        if ($data.EndsWith('\')) {
            $pending = New-Object System.Text.StringBuilder
            [void]$pending.Append($data.Substring(0, $data.Length - 1))
            $pendingName = $name
        }
        else {
            $results.Add([pscustomobject]@{ Key = $currentKey; Name = $name; Data = $data })
        }
    }

    return $results
}

function Export-RegistrySnapshot {
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$OutDir,
        [ValidateSet('Default', 'Full')][string]$Scope = 'Default',
        [switch]$IncludeUserHives
    )

    $regDir = New-CaptureSubdir -Base $OutDir -Name 'registry'
    $targets = New-Object System.Collections.Generic.List[string]

    if ($Scope -eq 'Full') {
        $targets.Add('HKEY_LOCAL_MACHINE')
    }
    else {
        foreach ($t in $Settings.Registry.DefaultHives) { $targets.Add($t) }
    }

    if ($IncludeUserHives) {
        $userRoot = Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue
        foreach ($u in $userRoot) {
            if ($u.PSChildName -like '*_Classes' -or $u.PSChildName -eq '.DEFAULT') { continue }
            $targets.Add(('HKEY_USERS\{0}' -f $u.PSChildName))
        }
    }

    $summary = @()
    foreach ($target in $targets) {
        $safe = ($target -replace '[\\:]', '_')
        $regFile = Join-Path $regDir "$safe.reg"

        & reg.exe export $target $regFile /y 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $regFile)) {
            Write-CaptureLog "  reg export failed: $target" -Level WARN
            continue
        }

        $entries = ConvertFrom-RegFile -Path $regFile
        $entries | Select-Object Key, Name, Data |
            Export-Csv -LiteralPath (Join-Path $regDir "$safe.values.csv") -NoTypeInformation -Encoding UTF8

        ($entries | ForEach-Object { $_.Key } | Sort-Object -Unique) |
            Set-Content -LiteralPath (Join-Path $regDir "$safe.keys.txt") -Encoding UTF8

        $summary += [pscustomobject]@{ Target = $target; Values = $entries.Count; Export = $regFile }
        Write-CaptureLog ('  {0}: {1} values' -f $target, $entries.Count)
    }

    Write-JsonFile -Path (Join-Path $regDir 'summary.json') -InputObject $summary
}

# ------------------------------------------------------------------- files ---

function Export-FileSnapshot {
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$OutDir,
        [ValidateSet('Auto', 'Usn', 'Inventory')][string]$Mode = 'Auto',
        [int64]$SinceUsn,
        [string]$SinceJournalId,
        [string]$Volume = 'C:'
    )

    $fileDir = New-CaptureSubdir -Base $OutDir -Name 'files'

    # Exact-content hashing for the small, high-value roots - always both sides.
    $hashRoots = @(@($Settings.Files.HashRoots) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($hashRoots.Count -gt 0) {
        $hashes = New-Object System.Collections.Generic.List[object]
        foreach ($root in $hashRoots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            $files = Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $h = $null
                try { $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
                $hashes.Add([pscustomobject]@{ Path = $f.FullName; Length = $f.Length; Hash = $h })
            }
        }
        $hashes | Export-Csv -LiteralPath (Join-Path $fileDir 'hashes.csv') -NoTypeInformation -Encoding UTF8
        Write-CaptureLog ('  hashed {0} files under {1} root(s)' -f $hashes.Count, $hashRoots.Count)
    }

    $effectiveMode = $Mode
    if ($Mode -eq 'Auto') {
        if ($null -ne $SinceUsn -and $SinceJournalId) { $effectiveMode = 'Usn' }
        else { $effectiveMode = 'Inventory' }
    }

    if ($effectiveMode -eq 'Usn') {
        if ($null -eq $SinceUsn) {
            # No cursor yet - record an inventory anyway so a failed journal read
            # at T1 still has something to compare against.
            Export-FileInventory -Settings $Settings -OutDir $OutDir
            return
        }
        $journal = Get-UsnJournalState -Volume $Volume
        # Bound the read at the journal's current position so a long-running
        # capture cannot chase records written after this snapshot began.
        $stopUsn = [int64]$journal.NextUsn
        if ($journal.JournalId -ne $SinceJournalId) {
            Write-CaptureLog '  USN journal was recreated between captures - falling back to inventory' -Level WARN
            $effectiveMode = 'Inventory'
        }
        else {
            try {
                $records = Read-UsnJournal -Volume $Volume -StartUsn $SinceUsn -StopUsn $stopUsn -JournalId $SinceJournalId
            }
            catch {
                Write-CaptureLog ('  {0} - falling back to inventory' -f $_.Exception.Message) -Level WARN
                Export-FileInventory -Settings $Settings -OutDir $OutDir
                return
            }

            $changes = $records | Where-Object { $_.Usn -gt $SinceUsn }

            $captureRootPattern = [regex]::Escape((Split-Path -Parent $OutDir))
            # -match $null returns TRUE, so nulls must never reach the filter list.
            $noise = @(
                @($Settings.Files.NoisePatterns) +
                @($Settings.Signal.NoisePatterns) +
                @($captureRootPattern) |
                    Where-Object { -not [string]::IsNullOrEmpty($_) }
            )

            $grouped = @{}
            foreach ($rec in $changes) {
                $path = $rec.Path
                if ([string]::IsNullOrWhiteSpace($path)) { continue }
                $skip = $false
                foreach ($pattern in $noise) {
                    if ($path -match $pattern) { $skip = $true; break }
                }
                if ($skip) { continue }

                if (-not $grouped.ContainsKey($path)) {
                    $grouped[$path] = [pscustomobject]@{
                        Path   = $path
                        Usn    = $rec.Usn
                        Reason = $rec.Reason
                        When   = $rec.Timestamp
                        Events = 1
                    }
                }
                else {
                    $g = $grouped[$path]
                    $g.Usn = $rec.Usn
                    $g.Events = $g.Events + 1
                    $reasons = @(($g.Reason + ',' + $rec.Reason) -split ',' | Sort-Object -Unique)
                    $g.Reason = ($reasons -join ',')
                }
            }

            $grouped.Values | Sort-Object Path |
                Export-Csv -LiteralPath (Join-Path $fileDir 'changed-usn.csv') -NoTypeInformation -Encoding UTF8

            Write-CaptureLog ('  {0} USN records scanned, {1} candidate paths' -f $changes.Count, $grouped.Count)
            return
        }
    }

    Export-FileInventory -Settings $Settings -OutDir $OutDir
}

function Export-FileInventory {
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$OutDir
    )

    $fileDir = New-CaptureSubdir -Base $OutDir -Name 'files'
    $inv = New-Object System.Collections.Generic.List[object]
    $roots = @(@($Settings.Files.Roots) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $stack = New-Object System.Collections.Stack
        $stack.Push($root)
        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            try {
                foreach ($f in [System.IO.Directory]::EnumerateFiles($dir)) {
                    try {
                        $info = New-Object System.IO.FileInfo($f)
                        $inv.Add([pscustomobject]@{
                                Path      = $info.FullName
                                Length    = $info.Length
                                LastWrite = $info.LastWriteTimeUtc.ToString('o')
                            })
                    }
                    catch { }
                }
            }
            catch { }
            try {
                foreach ($d in [System.IO.Directory]::EnumerateDirectories($dir)) {
                    $attrs = [System.IO.File]::GetAttributes($d)
                    if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $stack.Push($d)
                }
            }
            catch { }
        }
    }
    $inv | Export-Csv -LiteralPath (Join-Path $fileDir 'inventory.csv') -NoTypeInformation -Encoding UTF8
    Write-CaptureLog ('  inventory: {0} files' -f $inv.Count)
}

# --------------------------------------------------------------------- IIS ---

function Export-IisSnapshot {
    param([Parameter(Mandatory)][string]$OutDir)

    $inetsrv = Join-Path $env:SystemRoot 'System32\inetsrv'
    $appcmd = Join-Path $inetsrv 'appcmd.exe'
    if (-not (Test-Path -LiteralPath $appcmd)) { throw 'IIS is not installed on this host.' }

    $iisDir = New-CaptureSubdir -Base $OutDir -Name 'iis'

    foreach ($name in @('applicationHost.config', 'administration.config', 'redirection.config')) {
        $src = Join-Path $inetsrv "config\$name"
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination (Join-Path $iisDir $name) -Force }
    }

    $lists = [ordered]@{
        'apppools.xml' = @('list', 'apppool', '/xml')
        'sites.xml'    = @('list', 'site', '/xml')
        'vdirs.xml'    = @('list', 'vdir', '/xml')
        'config.xml'   = @('list', 'config', '/xml')
        'apps.xml'     = @('list', 'app', '/xml')
    }
    foreach ($key in $lists.Keys) {
        & $appcmd @($lists[$key]) 2>&1 | Out-File -LiteralPath (Join-Path $iisDir $key) -Encoding utf8
    }

    & $appcmd list backup 2>&1 | Out-File -LiteralPath (Join-Path $iisDir 'backups.txt') -Encoding utf8

    # IIS feature state (part of the picture, cheap to record).
    & dism.exe /online /get-features /format:table 2>&1 |
        Select-String -Pattern 'IIS-' |
        Out-File -LiteralPath (Join-Path $iisDir 'dism-iis-features.txt') -Encoding utf8

    Write-CaptureLog '  captured IIS configuration + appcmd object lists'
}

# ---------------------------------------------------------------- features ---

function Export-FeatureSnapshot {
    param([Parameter(Mandatory)][string]$OutDir)
    if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        throw 'Get-WindowsFeature is not available (not a Windows Server host or ServerManager module missing).'
    }
    $dir = New-CaptureSubdir -Base $OutDir -Name 'features'

    $features = @(Get-WindowsFeature)
    $features | Select-Object Name, DisplayName, InstallState, FeatureType |
        Export-Csv -LiteralPath (Join-Path $dir 'windowsfeatures.csv') -NoTypeInformation -Encoding UTF8

    # Paste-ready install list for the rebuild script: roles and role services
    # only - plain features are added by the roles that depend on them.
    $installed = @($features |
        Where-Object { $_.InstallState -eq 'Installed' -and "$($_.FeatureType)" -match '^Role(Service| Service)?$' } |
        ForEach-Object { $_.Name } |
        Sort-Object)
    $installLines = @(
        "# Installed roles/role services on $env:COMPUTERNAME at $((Get-Date).ToUniversalTime().ToString('o'))"
        '# Paste-ready for a rebuild of this host:'
        ('Install-WindowsFeature -Name {0}' -f ($installed -join ','))
    )
    Set-Content -LiteralPath (Join-Path $dir 'installed-roles.txt') -Value $installLines -Encoding UTF8
    Write-CaptureLog ('  {0} role(s)/role service(s) installed' -f $installed.Count)

    # DISM adds component-level detail and catches features ServerManager hides.
    & dism.exe /online /get-features /format:table 2>&1 |
        Out-File -LiteralPath (Join-Path $dir 'dism-features.txt') -Encoding utf8
    & dism.exe /online /get-packages /format:table 2>&1 |
        Out-File -LiteralPath (Join-Path $dir 'dism-packages.txt') -Encoding utf8
}

function ConvertFrom-DismTable {
    <#
        Parses `dism /get-features` and `dism /get-packages` output. Tolerates
        both shapes DISM emits: pipe tables ("Name | State") and key/value
        blocks ("Feature Name : X" / "State : Y").
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Feature', 'Package')][string]$Kind = 'Feature'
    )

    $results = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Path)) { return $results }

    $nameKey = if ($Kind -eq 'Feature') { 'Feature Name' } else { 'Package Identity' }
    $pendingName = $null

    foreach ($raw in (Get-Content -LiteralPath $Path)) {
        $line = $raw.Trim()
        if ($line.Length -eq 0) { continue }
        if ($line -match '^-+$') { continue }

        if ($line -match '^(.+?)\s*\|\s*(\S+)$') {
            $name = $Matches[1].Trim()
            $state = $Matches[2].Trim()
            if ($name -eq 'Feature Name' -or $name -eq 'Package Identity') { continue }
            if ($name -match '^-+$') { continue }
            $results.Add([pscustomobject]@{ Kind = 'Table'; Name = $name; State = $state })
            continue
        }

        if ($line -match ('^{0}\s*:\s*(.+)$' -f [regex]::Escape($nameKey))) {
            $pendingName = $Matches[1].Trim()
            continue
        }
        if ($line -match '^State\s*:\s*(.+)$') {
            if ($pendingName) {
                $results.Add([pscustomobject]@{ Kind = 'Pair'; Name = $pendingName; State = $Matches[1].Trim() })
                $pendingName = $null
            }
        }
    }
    return $results
}

function Export-ServiceSnapshot {
    param([Parameter(Mandatory)][string]$OutDir)
    $dir = New-CaptureSubdir -Base $OutDir -Name 'services'
    Get-CimInstance -ClassName Win32_Service |
        Select-Object Name, DisplayName, StartMode, State, StartName, PathName |
        Export-Csv -LiteralPath (Join-Path $dir 'services.csv') -NoTypeInformation -Encoding UTF8
}

function Export-CertificateSnapshot {
    param([Parameter(Mandatory)][string]$OutDir, [switch]$IncludeCurrentUser)
    $dir = New-CaptureSubdir -Base $OutDir -Name 'certs'

    $stores = @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\TrustedPublisher')
    if ($IncludeCurrentUser) { $stores += 'Cert:\CurrentUser\My' }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($store in $stores) {
        if (-not (Test-Path -LiteralPath $store)) { continue }
        foreach ($cert in Get-ChildItem -LiteralPath $store) {
            $rows.Add([pscustomobject]@{
                    Store          = $store
                    Thumbprint     = $cert.Thumbprint
                    Subject        = $cert.Subject
                    Issuer         = $cert.Issuer
                    NotBefore      = $cert.NotBefore.ToUniversalTime().ToString('o')
                    NotAfter       = $cert.NotAfter.ToUniversalTime().ToString('o')
                    HasPrivateKey  = $cert.HasPrivateKey
                    FriendlyName   = $cert.FriendlyName
                })
        }
    }
    $rows | Export-Csv -LiteralPath (Join-Path $dir 'certificates.csv') -NoTypeInformation -Encoding UTF8
    Write-CaptureLog ('  {0} certificates recorded' -f $rows.Count)
}

function Export-FirewallSnapshot {
    param([Parameter(Mandatory)][string]$OutDir)
    $dir = New-CaptureSubdir -Base $OutDir -Name 'firewall'
    if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
        Get-NetFirewallRule | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile |
            Export-Csv -LiteralPath (Join-Path $dir 'rules.csv') -NoTypeInformation -Encoding UTF8
    }
    $policy = Join-Path $dir 'policy.wfw'
    & netsh.exe advfirewall export $policy 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-CaptureLog '  netsh advfirewall export needs elevation - rules.csv only' -Level WARN }
}

function Export-ScheduledTaskSnapshot {
    param([Parameter(Mandatory)][string]$OutDir)
    $dir = New-CaptureSubdir -Base $OutDir -Name 'tasks'
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Select-Object TaskPath, TaskName, State |
        Export-Csv -LiteralPath (Join-Path $dir 'scheduledtasks.csv') -NoTypeInformation -Encoding UTF8
}

function Export-SystemInfo {
    param([Parameter(Mandatory)][string]$OutDir)
    $dir = New-CaptureSubdir -Base $OutDir -Name 'system'
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem

    $info = [ordered]@{
        Hostname            = $env:COMPUTERNAME
        Domain              = $cs.Domain
        DomainRole          = $cs.DomainRole
        IsDomainController  = Test-IsDomainController
        HasIis              = Test-HasIis
        HasCertificationAuthority = Test-HasCertificationAuthority
        OS                  = $os.Caption
        Version             = $os.Version
        BuildNumber         = $os.BuildNumber
        InstallDate         = $os.InstallDate.ToString('o')
        PowerShellVersion   = $PSVersionTable.PSVersion.ToString()
        CapturedUtc         = (Get-Date).ToUniversalTime().ToString('o')
        TimeZone            = (Get-TimeZone).Id
    }
    Write-JsonFile -Path (Join-Path $dir 'systeminfo.json') -InputObject $info
    Write-CaptureLog ('  {0} / DC={1} / IIS={2} / CA={3}' -f $info.Hostname, $info.IsDomainController, $info.HasIis, $info.HasCertificationAuthority)
    return $info
}

# ------------------------------------------------------------ active dir ---

function Export-AdSnapshot {
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$OutDir,
        [datetime]$SinceUtc
    )

    if (-not (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
        throw 'ActiveDirectory module not available - run this on a domain controller.'
    }
    $domain = Get-ADDomain
    $rootDse = Get-ADRootDSE
    $adDir = New-CaptureSubdir -Base $OutDir -Name 'ad'

    $ldifde = Join-Path $env:SystemRoot 'System32\ldifde.exe'
    if (-not (Test-Path -LiteralPath $ldifde)) { throw 'ldifde.exe not found.' }

    $omit = @($Settings.Ad.OmitAttributes) -join ','

    $exports = [ordered]@{}
    if ($Settings.Ad.ExportDomainNc) { $exports['domain.ldf'] = $domain.DistinguishedName }
    if ($Settings.Ad.ExportConfigurationNc) { $exports['configuration.ldf'] = $rootDse.configurationNamingContext }

    foreach ($file in $exports.Keys) {
        $target = Join-Path $adDir $file
        & $ldifde -f $target -d $exports[$file] -o $omit 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target)) {
            throw "ldifde export failed for $($exports[$file])"
        }
        $size = (Get-Item -LiteralPath $target).Length
        Write-CaptureLog ('  {0}: {1:N1} MB' -f $file, ($size / 1MB))
    }

    # Authoritative "which objects were touched" list.
    if ($null -ne $SinceUtc -and $SinceUtc -ne [datetime]::MinValue) {
        $filter = 'whenChanged -gt {0}' -f $SinceUtc.ToUniversalTime().ToString('yyyyMMddHHmmss')
        $ncs = @($domain.DistinguishedName, $rootDse.configurationNamingContext)
        $touched = New-Object System.Collections.Generic.List[object]
        foreach ($nc in $ncs) {
            $objects = Get-ADObject -Filter $filter -SearchBase $nc -Properties whenChanged, whenCreated, objectClass -ErrorAction SilentlyContinue
            foreach ($o in $objects) {
                $touched.Add([pscustomobject]@{
                        DistinguishedName = $o.DistinguishedName
                        ObjectClass       = ($o.objectClass -join '/')
                        WhenCreated       = $o.whenCreated
                        WhenChanged       = $o.whenChanged
                        Partition         = $nc
                    })
            }
        }
        $touched | Sort-Object WhenChanged |
            Export-Csv -LiteralPath (Join-Path $adDir 'changed-objects.csv') -NoTypeInformation -Encoding UTF8
        Write-CaptureLog ('  {0} objects touched since {1:u}' -f $touched.Count, $SinceUtc)
    }
}

function Export-AdAuditEvents {
    <#
        Extracts 5136 (Directory Service Change) events in the capture window.
        Requires Enable-AdDirectoryAuditing.ps1 to have been applied, and
        generates nothing when no SACL is present.
    #>
    param(
        [Parameter(Mandatory)][string]$OutDir,
        [datetime]$SinceUtc,
        [string]$SubjectUserName,
        [int]$MaxEvents = 50000
    )

    if ($null -eq $SinceUtc -or $SinceUtc -eq [datetime]::MinValue) { return }

    $adDir = New-CaptureSubdir -Base $OutDir -Name 'ad'
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 5136
            StartTime = $SinceUtc.ToLocalTime()
        } -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch {
        Write-CaptureLog '  no 5136 events available (SACL/auditing not enabled, or no matching activity)' -Level WARN
        return
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($evt in $events) {
        try { [xml]$xml = $evt.ToXml() } catch { continue }
        $data = @{}
        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name) { $data[$node.Name] = $node.'#text' }
        }
        if ($SubjectUserName -and $data['SubjectUserName'] -ne $SubjectUserName) { continue }

        $rows.Add([pscustomobject]@{
                Time                      = $evt.TimeCreated.ToUniversalTime().ToString('o')
                SubjectUserName           = $data['SubjectUserName']
                SubjectDomainName         = $data['SubjectDomainName']
                ObjectDN                  = $data['ObjectDN']
                ObjectClass               = $data['ObjectClass']
                AttributeLDAPDisplayName  = $data['AttributeLDAPDisplayName']
                OperationType             = $data['OperationType']
                AttributeValue            = $data['AttributeValue']
                DSName                    = $data['DSName']
            })
    }

    $rows | Sort-Object Time |
        Export-Csv -LiteralPath (Join-Path $adDir 'ds-change-events-5136.csv') -NoTypeInformation -Encoding UTF8
    Write-CaptureLog ('  {0} directory-change events attributed' -f $rows.Count)
}

# ---------------------------------------------------------------- diffing ---

function Compare-Set {
    param($Before, $After)
    $b = @($Before)
    $a = @($After)
    $added = @($a | Where-Object { $b -notcontains $_ })
    $removed = @($b | Where-Object { $a -notcontains $_ })
    return [pscustomobject]@{ Added = $added; Removed = $removed }
}

function Get-RegistryValueMap {
    param([Parameter(Mandatory)][string]$Dir)
    $values = @{}
    $keys = New-Object System.Collections.Generic.HashSet[string]
    $sep = [char]31

    foreach ($csv in Get-ChildItem -LiteralPath $Dir -Filter '*.values.csv' -ErrorAction SilentlyContinue) {
        foreach ($row in (Import-Csv -LiteralPath $csv.FullName)) {
            $values[('{0}{1}{2}' -f $row.Key, $sep, $row.Name)] = $row.Data
        }
    }
    foreach ($file in Get-ChildItem -LiteralPath $Dir -Filter '*.keys.txt' -ErrorAction SilentlyContinue) {
        foreach ($line in (Get-Content -LiteralPath $file.FullName)) { [void]$keys.Add($line) }
    }
    return [pscustomobject]@{ Values = $values; Keys = $keys }
}

function Compare-RegistrySnapshot {
    param(
        [Parameter(Mandatory)][string]$BeforeDir,
        [Parameter(Mandatory)][string]$AfterDir
    )
    $before = Get-RegistryValueMap -Dir $BeforeDir
    $after = Get-RegistryValueMap -Dir $AfterDir
    $sep = [char]31
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($key in $after.Values.Keys) {
        if (-not $before.Values.ContainsKey($key)) {
            $parts = $key.Split($sep)
            $results.Add([pscustomobject]@{
                    Area = 'Registry'; Change = 'Added'; Target = $parts[0]; Name = $parts[1]; Before = ''; After = $after.Values[$key]
                })
        }
        elseif ($before.Values[$key] -ne $after.Values[$key]) {
            $parts = $key.Split($sep)
            $results.Add([pscustomobject]@{
                    Area = 'Registry'; Change = 'Modified'; Target = $parts[0]; Name = $parts[1]; Before = $before.Values[$key]; After = $after.Values[$key]
                })
        }
    }
    foreach ($key in $before.Values.Keys) {
        if (-not $after.Values.ContainsKey($key)) {
            $parts = $key.Split($sep)
            $results.Add([pscustomobject]@{
                    Area = 'Registry'; Change = 'Removed'; Target = $parts[0]; Name = $parts[1]; Before = $before.Values[$key]; After = ''
                })
        }
    }

    foreach ($key in $after.Keys) {
        if (-not $before.Keys.Contains($key)) {
            $results.Add([pscustomobject]@{ Area = 'Registry'; Change = 'KeyAdded'; Target = $key; Name = ''; Before = ''; After = '' })
        }
    }
    foreach ($key in $before.Keys) {
        if (-not $after.Keys.Contains($key)) {
            $results.Add([pscustomobject]@{ Area = 'Registry'; Change = 'KeyRemoved'; Target = $key; Name = ''; Before = ''; After = '' })
        }
    }

    return $results
}

function Compare-FeatureSnapshot {
    param([string]$BeforeDir, [string]$AfterDir)
    $beforeFile = Join-Path $BeforeDir 'windowsfeatures.csv'
    $afterFile = Join-Path $AfterDir 'windowsfeatures.csv'
    $results = New-Object System.Collections.Generic.List[object]

    if ((Test-Path -LiteralPath $beforeFile) -and (Test-Path -LiteralPath $afterFile)) {
        $before = @{}
        foreach ($row in Import-Csv -LiteralPath $beforeFile) { $before[$row.Name] = $row.InstallState }
        foreach ($row in Import-Csv -LiteralPath $afterFile) {
            $was = $before[$row.Name]
            if ($null -eq $was) { $was = '(absent)' }
            if ($was -ne $row.InstallState) {
                $results.Add([pscustomobject]@{
                        Area = 'Features'; Change = 'Modified'; Target = $row.Name; Name = 'InstallState'; Before = $was; After = $row.InstallState
                    })
            }
        }
    }

    # DISM is the second opinion: it lists state changes for features
    # ServerManager hides, and package-level payloads that Get-WindowsFeature
    # never mentions (this is where the NDES package itself shows up).
    $dismTargets = @(
        @{ Kind = 'Feature'; File = 'dism-features.txt'; Area = 'DismFeature'; ReportAdded = $false }
        @{ Kind = 'Package'; File = 'dism-packages.txt'; Area = 'DismPackage'; ReportAdded = $true }
    )
    foreach ($target in $dismTargets) {
        $beforePath = Join-Path $BeforeDir $target.File
        $afterPath = Join-Path $AfterDir $target.File
        if (-not (Test-Path -LiteralPath $beforePath)) { continue }
        if (-not (Test-Path -LiteralPath $afterPath)) { continue }

        $beforeMap = @{}
        foreach ($row in (ConvertFrom-DismTable -Path $beforePath -Kind $target.Kind)) { $beforeMap[$row.Name] = $row.State }

        $afterNames = New-Object System.Collections.Generic.HashSet[string]
        foreach ($row in (ConvertFrom-DismTable -Path $afterPath -Kind $target.Kind)) {
            [void]$afterNames.Add($row.Name)
            if (-not $beforeMap.ContainsKey($row.Name)) {
                if ($target.ReportAdded) {
                    $results.Add([pscustomobject]@{
                            Area = $target.Area; Change = 'Added'; Target = $row.Name; Name = 'State'; Before = '(absent)'; After = $row.State
                        })
                }
                continue
            }
            if ($beforeMap[$row.Name] -ne $row.State) {
                $results.Add([pscustomobject]@{
                        Area = $target.Area; Change = 'Modified'; Target = $row.Name; Name = 'State'; Before = $beforeMap[$row.Name]; After = $row.State
                    })
            }
        }

        if ($target.ReportAdded) {
            foreach ($name in $beforeMap.Keys) {
                if (-not $afterNames.Contains($name)) {
                    $results.Add([pscustomobject]@{
                            Area = $target.Area; Change = 'Removed'; Target = $name; Name = 'State'; Before = $beforeMap[$name]; After = '(absent)'
                        })
                }
            }
        }
    }

    return $results
}

function ConvertFrom-LdifCertificateValue {
    <#
        Decodes an LDIF base64 value (the 'attr:: <base64>' form) into readable
        certificate fields. Returns $null when the value is not a certificate.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $b64 = ($Value -replace '\s', '')
    if ($b64.Length -lt 64) { return $null }

    try { $bytes = [System.Convert]::FromBase64String($b64) } catch { return $null }
    if ($bytes.Length -lt 100) { return $null }

    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $bytes)
        return [pscustomobject]@{
            Subject    = $cert.Subject
            Issuer     = $cert.Issuer
            Thumbprint = $cert.Thumbprint
            NotBefore  = $cert.NotBefore.ToUniversalTime().ToString('o')
            NotAfter   = $cert.NotAfter.ToUniversalTime().ToString('o')
        }
    }
    catch { return $null }
}

function Test-AdFocus {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Target,
        [string[]]$Patterns
    )
    foreach ($pattern in @($Patterns)) {
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
        if ($Target -match [regex]::Escape($pattern)) { return $true }
    }
    return $false
}

function Compare-ServiceSnapshot {
    param([string]$BeforeDir, [string]$AfterDir)
    $beforeFile = Join-Path $BeforeDir 'services.csv'
    $afterFile = Join-Path $AfterDir 'services.csv'
    $results = New-Object System.Collections.Generic.List[object]

    if (-not (Test-Path -LiteralPath $beforeFile)) { return $results }
    if (-not (Test-Path -LiteralPath $afterFile)) { return $results }

    $before = @{}
    foreach ($row in Import-Csv -LiteralPath $beforeFile) { $before[$row.Name] = $row }
    $after = @{}
    foreach ($row in Import-Csv -LiteralPath $afterFile) {
        $after[$row.Name] = $row
        if (-not $before.ContainsKey($row.Name)) {
            $results.Add([pscustomobject]@{ Area = 'Service'; Change = 'Added'; Target = $row.Name; Name = 'Service'; Before = ''; After = ('{0} ({1}/{2})' -f $row.DisplayName, $row.StartMode, $row.State) })
            continue
        }
        $was = $before[$row.Name]
        foreach ($prop in @('StartMode', 'StartName', 'PathName')) {
            if ($was.$prop -ne $row.$prop) {
                $results.Add([pscustomobject]@{ Area = 'Service'; Change = 'Modified'; Target = $row.Name; Name = $prop; Before = $was.$prop; After = $row.$prop })
            }
        }
    }
    foreach ($name in $before.Keys) {
        if (-not $after.ContainsKey($name)) {
            $results.Add([pscustomobject]@{ Area = 'Service'; Change = 'Removed'; Target = $name; Name = 'Service'; Before = $before[$name].DisplayName; After = '' })
        }
    }
    return $results
}

function Compare-CertificateSnapshot {
    param([string]$BeforeDir, [string]$AfterDir)
    $beforeFile = Join-Path $BeforeDir 'certificates.csv'
    $afterFile = Join-Path $AfterDir 'certificates.csv'
    $results = New-Object System.Collections.Generic.List[object]

    if (-not (Test-Path -LiteralPath $beforeFile)) { return $results }
    if (-not (Test-Path -LiteralPath $afterFile)) { return $results }

    $before = @{}
    foreach ($row in Import-Csv -LiteralPath $beforeFile) { $before[$row.Thumbprint] = $row }
    $afterThumbs = New-Object System.Collections.Generic.HashSet[string]
    foreach ($row in Import-Csv -LiteralPath $afterFile) {
        [void]$afterThumbs.Add($row.Thumbprint)
        if (-not $before.ContainsKey($row.Thumbprint)) {
            $results.Add([pscustomobject]@{
                    Area = 'Certificates'; Change = 'Added'; Target = $row.Thumbprint
                    Name = $row.Store; Before = ''
                    After = ('{0} (issuer {1}, expires {2}, privatekey={3})' -f $row.Subject, $row.Issuer, $row.NotAfter, $row.HasPrivateKey)
                })
        }
    }
    foreach ($thumb in $before.Keys) {
        if (-not $afterThumbs.Contains($thumb)) {
            $results.Add([pscustomobject]@{
                    Area = 'Certificates'; Change = 'Removed'; Target = $thumb
                    Name = $before[$thumb].Store; Before = $before[$thumb].Subject; After = ''
                })
        }
    }
    return $results
}

function Compare-FileHashes {
    param([string]$BeforeDir, [string]$AfterDir)
    $results = New-Object System.Collections.Generic.List[object]
    $beforeFile = Join-Path $BeforeDir 'hashes.csv'
    $afterFile = Join-Path $AfterDir 'hashes.csv'
    if (-not (Test-Path -LiteralPath $beforeFile)) { return $results }
    if (-not (Test-Path -LiteralPath $afterFile)) { return $results }

    $before = @{}
    foreach ($row in Import-Csv -LiteralPath $beforeFile) { $before[$row.Path] = $row.Hash }
    foreach ($row in Import-Csv -LiteralPath $afterFile) {
        if (-not $before.ContainsKey($row.Path)) {
            $results.Add([pscustomobject]@{ Area = 'Files'; Change = 'Added'; Target = $row.Path; Name = 'Content'; Before = ''; After = $row.Hash })
        }
        elseif ($before[$row.Path] -ne $row.Hash) {
            $results.Add([pscustomobject]@{ Area = 'Files'; Change = 'Modified'; Target = $row.Path; Name = 'Content'; Before = $before[$row.Path]; After = $row.Hash })
        }
    }
    return $results
}

function Compare-FileInventory {
    param([string]$BeforeDir, [string]$AfterDir)
    $results = New-Object System.Collections.Generic.List[object]
    $beforeFile = Join-Path $BeforeDir 'inventory.csv'
    $afterFile = Join-Path $AfterDir 'inventory.csv'
    if (-not (Test-Path -LiteralPath $beforeFile)) { return $results }
    if (-not (Test-Path -LiteralPath $afterFile)) { return $results }

    $before = @{}
    foreach ($row in Import-Csv -LiteralPath $beforeFile) { $before[$row.Path] = $row }

    $after = @{}
    foreach ($row in Import-Csv -LiteralPath $afterFile) {
        $after[$row.Path] = $row
        if (-not $before.ContainsKey($row.Path)) {
            $results.Add([pscustomobject]@{ Area = 'Files'; Change = 'Added'; Target = $row.Path; Name = 'File'; Before = ''; After = ('{0} bytes' -f $row.Length) })
        }
        else {
            $was = $before[$row.Path]
            if ($was.Length -ne $row.Length -or $was.LastWrite -ne $row.LastWrite) {
                $results.Add([pscustomobject]@{
                        Area = 'Files'; Change = 'Modified'; Target = $row.Path; Name = 'File'
                        Before = ('{0} bytes @ {1}' -f $was.Length, $was.LastWrite)
                        After  = ('{0} bytes @ {1}' -f $row.Length, $row.LastWrite)
                    })
            }
        }
    }
    foreach ($path in $before.Keys) {
        if (-not $after.ContainsKey($path)) {
            $results.Add([pscustomobject]@{ Area = 'Files'; Change = 'Removed'; Target = $path; Name = 'File'; Before = ('{0} bytes' -f $before[$path].Length); After = '' })
        }
    }
    return $results
}

function Compare-UsnJournal {
    param([string]$BeforeDir, [string]$AfterDir)
    $results = New-Object System.Collections.Generic.List[object]
    $file = Join-Path $AfterDir 'changed-usn.csv'
    if (-not (Test-Path -LiteralPath $file)) { return $results }

    $rows = @(Import-Csv -LiteralPath $file)
    if ($rows.Count -eq 0) { return $results }

    # A capture taken with an older build (or a mis-parsed fsutil format) can
    # contain bare file names instead of paths. Refuse to emit those as changes -
    # 246 meaningless rows are worse than an honest gap.
    $pathsWithDir = @($rows | Where-Object { $_.Path -match '[\\/]' }).Count
    if (($pathsWithDir / $rows.Count) -lt 0.5) {
        $results.Add([pscustomobject]@{
                Area   = 'Files'
                Change = 'CaptureUnusable'
                Target = $file
                Name   = 'USN journal'
                Before = ''
                After  = ('{0} journal entries with no directory path - captured by an older build; file evidence for this window cannot be diffed. Re-capture to get paths.' -f $rows.Count)
            })
        return $results
    }

    foreach ($row in $rows) {
        $change = 'Modified'
        if ($row.Reason -match 'Create') { $change = 'Added' }
        if ($row.Reason -match 'Delete') { $change = 'Removed' }
        $results.Add([pscustomobject]@{
                Area = 'Files'; Change = $change; Target = $row.Path; Name = $row.Reason
                Before = ''; After = ('{0} event(s) @ {1}' -f $row.Events, $row.When)
            })
    }
    return $results
}

function Get-XmlSignatureSet {
    param([Parameter(Mandatory)][string]$Path)
    $set = New-Object System.Collections.Generic.HashSet[string]
    if (-not (Test-Path -LiteralPath $Path)) { return $set }

    $doc = New-Object System.Xml.XmlDocument
    try { $doc.Load($Path) } catch { return $set }
    if ($null -eq $doc.DocumentElement) { return $set }

    $stack = New-Object System.Collections.Stack
    $stack.Push($doc.DocumentElement)
    while ($stack.Count -gt 0) {
        $node = $stack.Pop()
        if ($null -eq $node) { continue }

        $parts = New-Object System.Collections.Generic.List[string]
        $cursor = $node
        while ($null -ne $cursor -and $cursor.NodeType -eq 'Element') {
            $parts.Insert(0, $cursor.Name)
            $cursor = $cursor.ParentNode
        }
        $path = ($parts -join '/')

        $attrs = @()
        if ($node.Attributes) {
            foreach ($a in $node.Attributes) { $attrs += ('{0}={1}' -f $a.Name, $a.Value) }
        }
        [void]$set.Add(('{0}|{1}' -f $path, (($attrs | Sort-Object) -join ';')))

        foreach ($child in $node.ChildNodes) {
            if ($child -is [System.Xml.XmlElement]) { $stack.Push($child) }
        }
    }
    return $set
}

function Compare-IisSnapshot {
    param([string]$BeforeDir, [string]$AfterDir)
    $results = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $BeforeDir)) { return $results }

    foreach ($list in @('apppools.xml', 'sites.xml', 'vdirs.xml', 'apps.xml', 'config.xml')) {
        $b = Get-XmlSignatureSet -Path (Join-Path $BeforeDir $list)
        $a = Get-XmlSignatureSet -Path (Join-Path $AfterDir $list)
        if ($a.Count -eq 0 -and $b.Count -eq 0) { continue }

        foreach ($sig in $a) {
            if (-not $b.Contains($sig)) {
                $results.Add([pscustomobject]@{ Area = 'IIS'; Change = 'Added'; Target = $list; Name = ''; Before = ''; After = $sig })
            }
        }
        foreach ($sig in $b) {
            if (-not $a.Contains($sig)) {
                $results.Add([pscustomobject]@{ Area = 'IIS'; Change = 'Removed'; Target = $list; Name = ''; Before = $sig; After = '' })
            }
        }
    }

    foreach ($config in @('applicationHost.config', 'administration.config')) {
        $bf = Join-Path $BeforeDir $config
        $af = Join-Path $AfterDir $config
        if ((Test-Path -LiteralPath $bf) -and (Test-Path -LiteralPath $af)) {
            $bh = (Get-FileHash -LiteralPath $bf -Algorithm SHA256).Hash
            $ah = (Get-FileHash -LiteralPath $af -Algorithm SHA256).Hash
            if ($bh -ne $ah) {
                $results.Add([pscustomobject]@{
                        Area = 'IIS'; Change = 'Modified'; Target = $config; Name = 'FileHash'; Before = $bh; After = $ah
                    })
            }
        }
    }
    return $results
}

function ConvertFrom-LdifFile {
    param([Parameter(Mandatory)][string]$Path)
    $objects = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $objects }

    $lines = [System.IO.File]::ReadAllLines($Path)
    $current = $null
    $lastAttribute = $null

    foreach ($raw in $lines) {
        if ($raw.Length -eq 0) {
            if ($null -ne $current -and $current.Dn) { $objects[$current.Dn] = $current }
            $current = $null
            $lastAttribute = $null
            continue
        }
        if ($raw.StartsWith('#')) { continue }

        if ($raw.StartsWith(' ')) {
            # continuation of the previous value
            if ($null -ne $current -and $lastAttribute) {
                $list = $current.Attributes[$lastAttribute]
                if ($list -and $list.Count -gt 0) {
                    $list[$list.Count - 1] = $list[$list.Count - 1] + $raw.TrimStart()
                }
            }
            continue
        }

        $idx = $raw.IndexOf(':')
        if ($idx -lt 1) { continue }
        $name = $raw.Substring(0, $idx).Trim()
        $rest = $raw.Substring($idx + 1)
        if ($rest.StartsWith(':')) { $rest = $rest.Substring(1) }
        $value = $rest.Trim()

        if ($name -eq 'dn') {
            $current = [pscustomobject]@{ Dn = $value; Attributes = @{} }
            $lastAttribute = $null
            continue
        }
        if ($null -eq $current) { continue }

        if (-not $current.Attributes.ContainsKey($name)) {
            $current.Attributes[$name] = New-Object System.Collections.Generic.List[string]
        }
        $current.Attributes[$name].Add($value)
        $lastAttribute = $name
    }
    if ($null -ne $current -and $current.Dn) { $objects[$current.Dn] = $current }

    return $objects
}

function Compare-LdifSnapshot {
    param(
        [Parameter(Mandatory)][string]$BeforeFile,
        [Parameter(Mandatory)][string]$AfterFile
    )
    $results = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $BeforeFile)) { return $results }
    if (-not (Test-Path -LiteralPath $AfterFile)) { return $results }

    $before = ConvertFrom-LdifFile -Path $BeforeFile
    $after = ConvertFrom-LdifFile -Path $AfterFile

    foreach ($dn in $after.Keys) {
        if (-not $before.ContainsKey($dn)) {
            $classes = ''
            if ($after[$dn].Attributes.ContainsKey('objectClass')) { $classes = ($after[$dn].Attributes['objectClass'] -join '/') }
            $results.Add([pscustomobject]@{ Area = 'AD'; Change = 'ObjectAdded'; Target = $dn; Name = $classes; Before = ''; After = '' })
            continue
        }

        $b = $before[$dn].Attributes
        $a = $after[$dn].Attributes
        $names = New-Object System.Collections.Generic.HashSet[string]
        foreach ($n in $a.Keys) { [void]$names.Add($n) }
        foreach ($n in $b.Keys) { [void]$names.Add($n) }

        foreach ($attr in $names) {
            $bList = @()
            if ($b.ContainsKey($attr)) { $bList = @($b[$attr]) }
            $aList = @()
            if ($a.ContainsKey($attr)) { $aList = @($a[$attr]) }

            $diff = Compare-Set -Before $bList -After $aList
            if ($diff.Added.Count -gt 0 -or $diff.Removed.Count -gt 0) {
                $change = 'AttrModified'
                if ($bList.Count -eq 0) { $change = 'AttrAdded' }
                elseif ($aList.Count -eq 0) { $change = 'AttrRemoved' }
                $results.Add([pscustomobject]@{
                        Area = 'AD'; Change = $change; Target = $dn; Name = $attr
                        Before = ($diff.Removed -join ' | ')
                        After  = ($diff.Added -join ' | ')
                    })
            }
        }
    }

    foreach ($dn in $before.Keys) {
        if (-not $after.ContainsKey($dn)) {
            $results.Add([pscustomobject]@{ Area = 'AD'; Change = 'ObjectRemoved'; Target = $dn; Name = ''; Before = ''; After = '' })
        }
    }
    return $results
}

function Get-ChangeSignal {
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Target,
        [AllowEmptyString()][string]$Name = '',
        [Parameter(Mandatory)]$Settings
    )
    $probe = ('{0}|{1}' -f $Area.ToLowerInvariant(), $Target)
    # Scenario noise may reference the value/attribute name, so it is matched
    # against a three-part probe. Base patterns keep the two-part form so
    # end-anchored rules such as '\.etl$' keep working.
    $probeWithName = $probe
    if (-not [string]::IsNullOrEmpty($Name)) { $probeWithName = '{0}|{1}' -f $probe, $Name }

    if ($Settings.Contains('Scenario')) {
        foreach ($pattern in @($Settings.Scenario.NoisePatterns)) {
            if ([string]::IsNullOrEmpty($pattern)) { continue }
            if ($probeWithName -match $pattern) { return 'Noise' }
        }
    }
    foreach ($pattern in $Settings.Signal.NoisePatterns) {
        if ([string]::IsNullOrEmpty($pattern)) { continue }
        if ($probe -match $pattern) { return 'Noise' }
    }
    foreach ($pattern in $Settings.Signal.HighPatterns) {
        if ([string]::IsNullOrEmpty($pattern)) { continue }
        if ($probe -match $pattern) { return 'High' }
    }
    return 'Review'
}

function Get-DirectorySecurityWithSacl {
    <#
        Returns a modifiable ActiveDirectorySecurity for a directory object,
        with the SACL included. DirectoryEntry does not request the SACL and its
        Options.SecurityMasks is not reachable from PowerShell, so the
        search-result path is used.
    #>
    param([Parameter(Mandatory)][string]$DistinguishedName)

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
            throw 'Security descriptor could not be read (SeSecurityPrivilege required).'
        }
    }
    finally {
        $searcher.Dispose()
        try { $rootEntry.Close() } catch { }
    }

    $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $security.SetSecurityDescriptorBinaryForm($bytes)
    return $security
}

function New-DirectoryAuditRule {
    param([string]$Principal = 'Authenticated Users')

    $identity = New-Object System.Security.Principal.NTAccount($Principal)
    $rights = [System.DirectoryServices.ActiveDirectoryRights]'WriteProperty, CreateChild, DeleteChild, Delete, WriteDacl, WriteOwner'
    $flags = [System.Security.AccessControl.AuditFlags]'Success, Failure'
    # ActiveDirectoryAuditRule takes (identity, rights, auditFlags, inheritanceType).
    $inherit = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    return New-Object System.DirectoryServices.ActiveDirectoryAuditRule($identity, $rights, $flags, $inherit)
}

function Set-DirectoryAuditPolicy {
    param([Parameter(Mandatory)][bool]$Enabled)
    $flag = if ($Enabled) { 'enable' } else { 'disable' }
    & auditpol.exe /set /subcategory:'{0CCE923F-69AE-11D9-BED3-505054503030}' /success:$flag /failure:$flag | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol failed to change the Directory Service Changes subcategory.' }
}

function Enable-DirectoryAuditSacl {
    <#
        Applies the directory-change audit ACE to a naming context, if absent.
        Returns $true when a change was made.
    #>
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string]$Principal = 'Authenticated Users'
    )

    $sid = (New-Object System.Security.Principal.NTAccount($Principal)).Translate([System.Security.Principal.SecurityIdentifier])
    $existing = @((Get-DirectorySecurityWithSacl -DistinguishedName $DistinguishedName).GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -eq $sid.Value })
    if ($existing.Count -gt 0) { return $false }

    $security = Get-DirectorySecurityWithSacl -DistinguishedName $DistinguishedName
    $security.AddAuditRule((New-DirectoryAuditRule -Principal $Principal))

    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DistinguishedName")
    try {
        $entry.ObjectSecurity = $security
        $entry.CommitChanges()
    }
    finally { try { $entry.Close() } catch { } }
    return $true
}

function Disable-DirectoryAuditSacl {
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string]$Principal = 'Authenticated Users'
    )

    $sid = (New-Object System.Security.Principal.NTAccount($Principal)).Translate([System.Security.Principal.SecurityIdentifier])
    $security = Get-DirectorySecurityWithSacl -DistinguishedName $DistinguishedName
    $rules = @($security.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -eq $sid.Value })
    foreach ($rule in $rules) { [void]$security.RemoveAuditRule($rule) }

    if ($rules.Count -gt 0) {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DistinguishedName")
        try {
            $entry.ObjectSecurity = $security
            $entry.CommitChanges()
        }
        finally { try { $entry.Close() } catch { } }
    }
    return $rules.Count
}

function Enable-FileSystemAudit {
    param(
        [string[]]$Paths,
        [string]$Principal = 'Everyone'
    )
    Enable-CapturePrivilege
    Set-FileSystemAuditPolicy -Enabled $true
    foreach ($p in @($Paths)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if (-not (Test-Path -LiteralPath $p)) { continue }
        Add-FileAuditRule -Path $p -Principal $Principal
    }
}

function Disable-FileSystemAudit {
    param(
        [string[]]$Paths,
        [string]$Principal = 'Everyone'
    )
    Enable-CapturePrivilege
    foreach ($p in @($Paths)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if (-not (Test-Path -LiteralPath $p)) { continue }
        [void](Remove-FileAuditRule -Path $p -Principal $Principal)
    }
    Set-FileSystemAuditPolicy -Enabled $false
}

function Test-DirectoryAuditSacl {
    <#
        Reports whether a directory-change audit ACE exists on a naming
        context. Used as a preflight check: the absence of this ACE is a silent
        failure mode - the capture runs, the diff is correct, but the report can
        never say WHICH ACCOUNT made a change.

        Requires SeSecurityPrivilege to read the SACL.  Throws if it cannot.
    #>
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string]$Principal = 'Authenticated Users'
    )

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
            throw 'Security descriptor could not be read (SeSecurityPrivilege required).'
        }
    }
    finally {
        $searcher.Dispose()
        try { $rootEntry.Close() } catch { }
    }

    $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $security.SetSecurityDescriptorBinaryForm($bytes)

    $sid = (New-Object System.Security.Principal.NTAccount($Principal)).Translate([System.Security.Principal.SecurityIdentifier])
    $rules = @($security.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -eq $sid.Value })
    return $rules.Count
}

function Get-DirectoryNamingContexts {
    <#
        Returns the default and configuration naming contexts, or $null values
        when this host is not a domain controller / cannot reach its domain.
    #>
    $entry = $null
    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        return [pscustomobject]@{
            Domain        = [string]$entry.Properties['defaultNamingContext'].Value
            Configuration = [string]$entry.Properties['configurationNamingContext'].Value
        }
    }
    catch {
        return [pscustomobject]@{ Domain = $null; Configuration = $null }
    }
    finally {
        if ($null -ne $entry) { try { $entry.Close() } catch { } }
    }
}

function Test-DirectoryAuditSubcategory {
    $output = & auditpol.exe /get /subcategory:'{0CCE923F-69AE-11D9-BED3-505054503030}' 2>&1
    $text = ($output | Out-String)
    return ($text -match 'Success and Failure|Success')
}

# ------------------------------------------------- file system auditing (4663) ---

$script:FileSystemSubcategory = '{0CCE921D-69AE-11D9-BED3-505054503030}'  # Audit File System

function Enable-CapturePrivilege {
    <#
        Enables a token privilege (default SeSecurityPrivilege) for this process.
        Needed to read or write SACLs. Requires elevation.
    #>
    param([string]$Privilege = 'SeSecurityPrivilege')

    $source = @'
using System;
using System.Runtime.InteropServices;

public static class NdesCapturePrivilege
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

    if (-not ('NdesCapturePrivilege' -as [type])) {
        Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
    }
    if (-not [NdesCapturePrivilege]::Enable($Privilege)) {
        throw ('Could not enable {0}. Run elevated as an administrator.' -f $Privilege)
    }
}

function Set-FileSystemAuditPolicy {
    <#
        Turns the "Audit File System" audit subcategory on or off. Only the
        success path is audited: failures on a busy volume are mostly noise.
    #>
    param([Parameter(Mandatory)][bool]$Enabled)

    $flag = if ($Enabled) { 'enable' } else { 'disable' }
    & auditpol.exe /set /subcategory:$script:FileSystemSubcategory /success:$flag /failure:disable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol failed to change the Audit File System subcategory.' }
}

function Get-FileSystemAuditPolicy {
    return (& auditpol.exe /get /subcategory:$script:FileSystemSubcategory 2>&1)
}

function New-FileAuditRule {
    <#
        Audit rule covering the access types that indicate a modification.
        Reads are deliberately excluded - auditing them multiplies the event
        volume without answering "who changed this".

        NB: FileSystemAuditRule takes (identity, rights, inheritance,
        propagation, auditFlags) - auditFlags is LAST, unlike
        ActiveDirectoryAuditRule where it comes third. Passing them in the AD
        order silently binds Success=1 as InheritanceFlags and fails with
        "Must set at least one flag".
    #>
    param([Parameter(Mandatory)][string]$Principal)

    $identity = New-Object System.Security.Principal.NTAccount($Principal)
    $rights = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    $flags = [System.Security.AccessControl.AuditFlags]::Success

    return New-Object System.Security.AccessControl.FileSystemAuditRule($identity, $rights, $inherit, $propagate, $flags)
}

function Get-FileAuditRules {
    param(
        [Parameter(Mandatory)][string]$Path,
        [System.Security.Principal.SecurityIdentifier]$Identity
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $sections = [System.Security.AccessControl.AccessControlSections]::Audit
    $security = if ($item.PSIsContainer) {
        (New-Object System.IO.DirectoryInfo($item.FullName)).GetAccessControl($sections)
    }
    else {
        (New-Object System.IO.FileInfo($item.FullName)).GetAccessControl($sections)
    }
    if ($null -eq $Identity) {
        return @($security.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    }
    return @($security.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -eq $Identity.Value })
}

function Add-FileAuditRule {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Principal
    )

    $rule = New-FileAuditRule -Principal $Principal
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $sections = [System.Security.AccessControl.AccessControlSections]::Audit

    if ($item.PSIsContainer) {
        $info = New-Object System.IO.DirectoryInfo($item.FullName)
        $security = $info.GetAccessControl($sections)
        $security.AddAuditRule($rule)
        $info.SetAccessControl($security)
    }
    else {
        $info = New-Object System.IO.FileInfo($item.FullName)
        $security = $info.GetAccessControl($sections)
        $security.AddAuditRule($rule)
        $info.SetAccessControl($security)
    }
}

function Remove-FileAuditRule {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Principal
    )

    $sid = (New-Object System.Security.Principal.NTAccount($Principal)).Translate([System.Security.Principal.SecurityIdentifier])
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $sections = [System.Security.AccessControl.AccessControlSections]::Audit

    $info = if ($item.PSIsContainer) { New-Object System.IO.DirectoryInfo($item.FullName) } else { New-Object System.IO.FileInfo($item.FullName) }
    $security = $info.GetAccessControl($sections)
    $matching = @($security.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -eq $sid.Value })
    foreach ($rule in $matching) { [void]$security.RemoveAuditRule($rule) }
    if ($matching.Count -gt 0) { $info.SetAccessControl($security) }
    return $matching.Count
}

function ConvertFrom-FileAceAccessList {
    <#
        4663 reports access types as %%NNNN resource strings. Translate the ones
        that matter for "was this a modification?".
    #>
    param([AllowEmptyString()][string]$AccessList)

    if ([string]::IsNullOrWhiteSpace($AccessList)) { return '' }
    $map = @{
        '%%4416' = 'ReadData'
        '%%4417' = 'WriteData'
        '%%4418' = 'AppendData'
        '%%4419' = 'ReadExtendedAttributes'
        '%%4420' = 'WriteExtendedAttributes'
        '%%4421' = 'ExecuteTraverse'
        '%%4422' = 'DeleteChild'
        '%%4423' = 'ReadAttributes'
        '%%4424' = 'WriteAttributes'
        '%%1537' = 'Delete'
        '%%1538' = 'ReadPermissions'
        '%%1539' = 'ChangePermissions'
        '%%1540' = 'TakeOwnership'
        '%%1541' = 'Synchronize'
    }
    $names = foreach ($token in ($AccessList -split '\s+')) {
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        if ($map.ContainsKey($token)) { $map[$token] } else { $token }
    }
    return (@($names) -join ',')
}

function Test-FileAceIsModification {
    param([AllowEmptyString()][string]$AccessList)
    $text = [string]$AccessList
    foreach ($marker in @('%%4417', '%%4418', '%%4420', '%%4424', '%%1537', '%%1539', '%%1540')) {
        if ($text -match [regex]::Escape($marker)) { return $true }
    }
    return $false
}

function Export-FileAuditEvents {
    <#
        Extracts 4663 (object access) events for the audited paths within the
        capture window. Requires Enable-FileAuditing.ps1 -Apply before T0.
    #>
    param(
        [Parameter(Mandatory)][string]$OutDir,
        [datetime]$SinceUtc,
        [string[]]$Paths,
        [int]$MaxEvents = 50000
    )

    if ($null -eq $SinceUtc -or $SinceUtc -eq [datetime]::MinValue) { return }

    $fileDir = New-CaptureSubdir -Base $OutDir -Name 'files'
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4663
            StartTime = $SinceUtc.ToLocalTime()
        } -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch {
        Write-CaptureLog '  no 4663 events available (file system auditing not applied, or no activity)' -Level WARN
        return
    }

    $prefixes = @(@($Paths) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($evt in $events) {
        try { [xml]$xml = $evt.ToXml() } catch { continue }
        $data = @{}
        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name) { $data[$node.Name] = $node.'#text' }
        }

        $objectName = [string]$data['ObjectName']
        if ($prefixes.Count -gt 0) {
            $inScope = $false
            foreach ($p in $prefixes) {
                if ($objectName -like ('{0}*' -f $p.TrimEnd('\'))) { $inScope = $true; break }
            }
            if (-not $inScope) { continue }
        }
        if (-not (Test-FileAceIsModification -AccessList ([string]$data['AccessList']))) { continue }

        $rows.Add([pscustomobject]@{
                Time         = $evt.TimeCreated.ToUniversalTime().ToString('o')
                Account      = ('{0}\{1}' -f $data['SubjectDomainName'], $data['SubjectUserName'])
                Path         = $objectName
                Access       = (ConvertFrom-FileAceAccessList -AccessList ([string]$data['AccessList']))
                ProcessName  = [string]$data['ProcessName']
                ObjectType   = [string]$data['ObjectType']
            })
    }

    $rows | Sort-Object Time |
        Export-Csv -LiteralPath (Join-Path $fileDir 'file-access-4663.csv') -NoTypeInformation -Encoding UTF8
    Write-CaptureLog ('  {0} file modification event(s) attributed' -f $rows.Count)
}

function Compare-FileAuditEvents {
    param([string]$BeforeDir, [string]$AfterDir)
    $results = New-Object System.Collections.Generic.List[object]
    $file = Join-Path $AfterDir 'file-access-4663.csv'
    if (-not (Test-Path -LiteralPath $file)) { return $results }

    $rows = @(Import-Csv -LiteralPath $file)
    foreach ($row in $rows) {
        $results.Add([pscustomobject]@{
                Area   = 'FileAudit'
                Change = 'Modified'
                Target = $row.Path
                Name   = $row.Account
                Before = ''
                After  = ('{0} by {1} [{2}]' -f $row.Access, $row.ProcessName, $row.Time)
            })
    }
    return $results
}

Export-ModuleMember -Function *
