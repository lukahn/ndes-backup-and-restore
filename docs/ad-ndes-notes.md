# AD and NDES notes

Working notes from the lab where this kit was developed. Hostnames, addresses and
account names have been replaced with placeholders; the topology and the reasoning
are unchanged.

---
===============================================================================
 AD SERVER  -  NDES EXERCISE
 Label: ndes     Scenario: (none)
 Account: log in as da or ea, and run PowerShell "as administrator"
===============================================================================

 The label must be the same as on the NDES server (ndes).

 Kit location assumed below:  C:\Tools\ndes-backup-and-restore

 This run answers: what did the NDES install change IN THE DIRECTORY, and as
 which account?  That is the evidence for the "does it need Enterprise Admin
 every time, or only once?" question.

-------------------------------------------------------------------------------
 BEFORE  -  before you install NDES on the NDES server
-------------------------------------------------------------------------------

cd C:\Tools\ndes-backup-and-restore
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 1. Take the baseline (T0). This also switches on directory-change auditing
#    for the domain and Configuration partitions, and Stop switches it off
#    again - no separate step needed.
.\Start-NdesCapture.ps1 -Label ndes

# 2. Verify attribution is live (optional). Both partitions must show an ACE.
.\Enable-AdDirectoryAuditing.ps1 -Status -IncludeConfigurationNc

   Expected last lines:
     baseline complete - 0 collector(s) failed
     state: C:\NdesCapture\AD\state-ndes.json

   Now go and install / configure NDES on the NDES server.

-------------------------------------------------------------------------------
 AFTER  -  once NDES is installed and configured end to end
-------------------------------------------------------------------------------

cd C:\Tools\ndes-backup-and-restore
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 4. Close the capture window (T1).
.\Stop-NdesCapture.ps1 -Label ndes

# 5. Build the report.
.\Compare-NdesCapture.ps1 -Label ndes

# 6. Read it.
notepad C:\NdesCapture\AD\report-ndes\report.md

   Stop has already turned the auditing back off. If you passed -KeepAuditing:
   .\Enable-AdDirectoryAuditing.ps1 -Revert -IncludeConfigurationNc

-------------------------------------------------------------------------------
 WHAT YOU SHOULD SEE
-------------------------------------------------------------------------------

 In C:\NdesCapture\AD\report-ndes\report.md:

   ## High-signal changes  (AD)
     Attribute writes on the SCEP service account, most likely:
       userCertificate        (the RA certificates get published on the account)
       possibly msPKI-* / altSecurityIdentities style attributes

     Group membership changes, if setup granted rights - for example:
       CN=Cert Publishers,CN=Users,...   (member added)
       any custom group you used for the SCEP account

   ## AD objects touched
     The SCEP account, plus anything NDES wrote to

   ## AD writes attributed by account
     Subject names and the attributes they wrote.
     This is the direct evidence for whether ea/da was needed at setup time,
     and what it actually wrote.

 Handy extracts:

   # what objects were touched, and when
   Import-Csv C:\NdesCapture\AD\T1-ndes\ad\changed-objects.csv |
     Sort-Object WhenChanged | Format-Table WhenChanged,ObjectClass,DistinguishedName -AutoSize

   # who wrote what
   Import-Csv C:\NdesCapture\AD\T1-ndes\ad\ds-change-events-5136.csv |
     Format-Table SubjectUserName,OperationType,ObjectDN,AttributeLDAPDisplayName -AutoSize

   # just the attribute deltas
   Import-Csv C:\NdesCapture\AD\report-ndes\changes.csv |
     Where-Object { $_.Area -eq 'AD' } |
     Format-Table Partition,Change,Target,Name,Before,After -AutoSize

 If the 5136 CSV does not exist, the SACL did not land - re-run step 1 and 2
 before trusting the report. The LDIF diff still works without it, but you
 lose the "which account" half.

-------------------------------------------------------------------------------
 OPTIONAL  -  which ACCOUNT changed which FILE
-------------------------------------------------------------------------------

 5136 attributes DIRECTORY writes. File changes on disk carry no user identity
 in the USN journal - that needs event 4663. Start applies the SACLs for you:

   .\Start-NdesCapture.ps1 -Label ndes -FileAuditing
   ...
   .\Stop-NdesCapture.ps1 -Label ndes -FileAuditing

 Paths come from FileAudit.Paths in config\capture-settings.psd1
 (default: C:\Windows\System32\CertLog). Stop reverts the SACLs it applied.

-------------------------------------------------------------------------------
 WHY THIS RUN IS THE INTERESTING ONE
-------------------------------------------------------------------------------

 If the only account that appears in the 5136 events is the one you were logged
 in as (ea or da), and the objects touched are limited to the SCEP service
 account plus group membership, then the conclusion is:

   - Enterprise Admin / Domain Admin was needed to ALLOW the one-time writes,
     not because NDES needs standing elevated rights
   - the resulting state (published certificates, group membership) is
     persistent in AD, so a NEW NDES server must still be able to READ them,
     but does not need to re-create them

 That is what to take to the "do we need EA on rebuild?" decision.

-------------------------------------------------------------------------------
 TROUBLESHOOTING
-------------------------------------------------------------------------------

 "cannot be loaded ... is not digitally signed"
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

 "Module not found ... \lib\NdesCapture.psm1"
     Copy the whole kit folder, not just the .ps1 files.

 "Access is denied" writing the SACL
     Not Domain Admin / Enterprise Admin in that session.

 "Capture state not found"
     Start was not run on this host with -Label ndes.

 DON'T: interrupt Start; run Stop before NDES is configured; revert the
        auditing before Stop (the SACL change would appear in your window).
===============================================================================

