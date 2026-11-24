@{
    # ---------------------------------------------------------------------
    # Registry evidence.
    # 'Default' exports only the hives below. Use -RegistryScope Full to
    # export all of HKEY_LOCAL_MACHINE when you suspect the narrow list
    # misses something.
    # ---------------------------------------------------------------------
    Registry = @{
        DefaultHives = @(
            'HKEY_LOCAL_MACHINE\SOFTWARE'
            'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services'
            'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control'
        )
    }

    # ---------------------------------------------------------------------
    # File evidence.
    # Mode Auto  = USN journal when readable, otherwise metadata inventory.
    # Mode Usn   = force USN journal (fails loudly if unavailable).
    # Mode Inventory = force inventory of Roots (slower, but only needs
    #                  read access).
    # Roots      = used by Inventory mode.
    # HashRoots  = always hashed at both capture points (keep this list
    #              small - these are the paths whose exact bytes matter).
    # ---------------------------------------------------------------------
    Files = @{
        Mode   = 'Auto'
        Volume = 'C:'
        Roots  = @(
            'C:\Windows\System32\certsrv'
            'C:\Windows\System32\inetsrv'
            'C:\ProgramData\Microsoft\Crypto'
            'C:\Windows\System32\Microsoft\Protect'
            'C:\ProgramData'
        )
        HashRoots = @(
            'C:\Windows\System32\certsrv'
            'C:\Windows\System32\inetsrv\config'
        )
    }

    # ---------------------------------------------------------------------
    # Active Directory evidence (only runs on a domain controller).
    # OmitAttributes keeps replication/volatile noise out of the LDIF so the
    # diff shows real attribute writes. The whenChanged sweep separately
    # identifies every touched object.
    # ---------------------------------------------------------------------
    Ad = @{
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
            'mS-DS-ConsistencyGuid'
        )
    }

    Iis = @{
        Enabled = $true
    }

    # ---------------------------------------------------------------------
    # File system auditing (event 4663) - the only way to attribute file
    # changes to an account. Off by default: it is only worth the event
    # volume when you specifically need "who touched this file".
    # Enable with Enable-FileAuditing.ps1 -Apply, then capture with
    # -FileAuditing. Keep Paths narrow.
    # ---------------------------------------------------------------------
    FileAudit = @{
        Enabled        = $false
        Paths          = @(
            'C:\Windows\System32\CertLog'
        )
        MaxEvents      = 50000
        AuditPrincipal = 'Everyone'
    }

    # ---------------------------------------------------------------------
    # Named scenarios. Selecting one with -Scenario replaces the HighPatterns
    # list (so unrelated changes drop to 'Review' instead of crowding the
    # report) and adds AdFocusPatterns, which drives a dedicated report
    # section. Add your own profiles here.
    # ---------------------------------------------------------------------
    Scenarios = @{
        EnterpriseCA = @{
            Description            = 'Focus on the AD writes performed when an enterprise CA is installed and registered.'
            IncludeConfigurationNc = $true
            HighPatterns           = @(
                # Nearly all PKI state lives under CN=Public Key Services in the
                # Configuration partition.
                'ad\|.*CN=Public Key Services'
                'ad\|.*CN=NTAuthCertificates'
                'ad\|.*CN=Cert Publishers'
                'registry\|.*\\Services\\CertSvc'
                'registry\|.*\\Microsoft\\Cryptography'
                'registry\|.*\\Microsoft\\ADCS'
                'service\|.*CertSvc'
                'certs\|'
                'features\|.*(ADCS|Certificate)'
                'dismfeature\|.*(ADCS|Certificate|PKI)'
                'dismpackage\|.*(ADCS|Certificate|PKI)'
                'files\|.*[\\/]CertLog'
                'files\|.*CAPolicy\.inf'
            )
            NoisePatterns          = @(
                # Routine machine-account churn on a DC during a long window.
                'ad\|.*CN=Computers,.*\|(pwdLastSet|unicodePwd|lastLogonTimestamp|logonCount|badPwdCount)$'
            )
            AdFocusPatterns        = @(
                'CN=Public Key Services'
                'CN=NTAuthCertificates'
                'CN=Cert Publishers'
                'CN=Certification Authorities'
                'CN=Enrollment Services'
                'CN=Certificate Templates'
                'CN=AIA'
                'CN=CDP'
                'CN=KRA'
                'CN=OID'
            )
        }
    }

    # ---------------------------------------------------------------------
    # Classification patterns. Applied (case-insensitive regex) to
    # "<area>|<target>". High = look here first. Noise = expected churn.
    # ---------------------------------------------------------------------
    Signal = @{
        HighPatterns = @(
            'registry\|.*\\Microsoft\\Cryptography\\MSCEP'
            'registry\|.*\\Services\\SCEP'
            'registry\|.*\\Services\\CertSvc'
            'registry\|.*\\Microsoft\\ADCS'
            'registry\|.*\\Microsoft\\ServerManager'
            'registry\|.*\\Services\\W3SVC'
            'registry\|.*\\Services\\WAS'
            'registry\|.*\\InetStp'
            'iis\|'
            'ad\|'
            'certs\|'
        )
        NoisePatterns = @(
            'registry\|.*\\CurrentControlSet\\Enum'
            'registry\|.*\\NetworkList'
            'registry\|.*\\Windows\\CurrentVersion\\Diagnostics'
            'registry\|.*\\EventLog'
            'registry\|.*\\Tracing'
            'registry\|.*\\Performance'
            'files\|.*\\Prefetch\\'
            'files\|.*\\Temp\\'
            'files\|.*\\LogFiles\\'
            'files\|.*\\SoftwareDistribution\\'
            'files\|.*\\WinSxS\\'
            'files\|.*\\\$Recycle\.Bin'
            'files\|.*\.etl$'
            'files\|.*\.evtx$'
        )
    }
}
