# AD and CA notes

Working notes from the lab where this kit was developed. Hostnames, addresses and
account names have been replaced with placeholders; the topology and the reasoning
are unchanged.

---
===============================================================================
 AD SERVER  -  CA EXERCISE
 Label: ca     Scenario: EnterpriseCA
 Account: log in as da or ea, and run PowerShell "as administrator"
===============================================================================

 The label must be the same on the AD server and the CA server (ca), so the
 two reports line up. Evidence lands in C:\NdesCapture\<HOSTNAME>\.

 Kit location assumed below:  C:\Tools\ndes-backup-and-restore
 If you keep the kit somewhere else, cd to that instead.

-------------------------------------------------------------------------------
 BEFORE  -  do this first, before you touch the CA server
-------------------------------------------------------------------------------

cd C:\Tools\ndes-backup-and-restore
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 1. Confirm the CA is NOT registered yet.  Expect NO output.
Get-ADObject -Filter 'objectClass -eq "pKIEnrollmentService"' `
  -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
  -Properties dNSHostName | Select-Object Name, dNSHostName

# 2. Take the baseline (T0). This also switches on directory-change auditing
#    for the domain and Configuration partitions, and Stop switches it off
#    again afterwards - no separate step needed.
.\Start-NdesCapture.ps1 -Label ca -Scenario EnterpriseCA

# 3. Verify attribution is live (optional). Both partitions must show an ACE.
.\Enable-AdDirectoryAuditing.ps1 -Status -Scenario EnterpriseCA

   Expected last lines:
     baseline complete - 0 collector(s) failed
     state: C:\NdesCapture\AD\state-ca.json

   Now go and build the CA. Do not run "checkpoint" / Stop until the CA is
   installed and registered as an enterprise CA.

-------------------------------------------------------------------------------
 AFTER  -  once the enterprise CA is installed and registered
-------------------------------------------------------------------------------

cd C:\Tools\ndes-backup-and-restore
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 5. Close the capture window (T1).
.\Stop-NdesCapture.ps1 -Label ca

# 6. Build the report.
.\Compare-NdesCapture.ps1 -Label ca

# 7. Read it.
notepad C:\NdesCapture\AD\report-ca\report.md

   Stop has already turned the auditing back off. If you passed -KeepAuditing
   and want to undo it manually:
   .\Enable-AdDirectoryAuditing.ps1 -Revert -Scenario EnterpriseCA

-------------------------------------------------------------------------------
 WHAT YOU SHOULD SEE
-------------------------------------------------------------------------------

 C:\NdesCapture\AD\report-ca\report.md contains:

   ## EnterpriseCA focus - AD objects
     ### Enrollment Services (n)          -> new pKIEnrollmentService object
     ### Certification Authorities (n)    -> new certificationAuthority object
     ### NTAuthCertificates (n)           -> cACertificate added
     ### Certificates published to AD (decoded)
                                          -> subject, issuer, thumbprint
     ### Accounts that performed the focus writes
                                          -> THIS answers the Enterprise Admin
                                             question: which account did it

 Quick look without opening the file:

   Select-String -Path C:\NdesCapture\AD\report-ca\report.md -Pattern 'EnterpriseCA focus' -Context 0,45

 Which account made the writes:

   Import-Csv C:\NdesCapture\AD\T1-ca\ad\ds-change-events-5136.csv |
     Group-Object SubjectUserName | Select-Object Name, Count

 If the 5136 CSV does not exist, the SACL did not land - re-run step 2 and step 3
 before trusting the report.

-------------------------------------------------------------------------------
 OPTIONAL  -  which ACCOUNT changed which FILE
-------------------------------------------------------------------------------

 The report shows WHAT changed in the directory and (with 5136) WHICH ACCOUNT
 did it. File changes on disk are different: the USN journal has no user
 information at all. To attribute file changes you need event 4663.

 Only do this if you specifically need it. Scope it to one or two folders.
 Start applies the SACLs for you - no separate step.

   # capture with the opt-in
   .\Start-NdesCapture.ps1 -Label ca -Scenario EnterpriseCA -FileAuditing
   ...
   .\Stop-NdesCapture.ps1 -Label ca -FileAuditing

 Paths come from FileAudit.Paths in config\capture-settings.psd1
 (default: C:\Windows\System32\CertLog). Stop reverts the SACLs it applied.

 The report then gains "File modifications by account" listing account, file,
 access type and process.

-------------------------------------------------------------------------------
 TROUBLESHOOTING
-------------------------------------------------------------------------------

 "cannot be loaded ... is not digitally signed"
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
     (run it in the same window, or use: powershell.exe -ExecutionPolicy Bypass -File .\script.ps1)

 "Module not found ... \lib\NdesCapture.psm1"
     The kit folder is incomplete. Copy the whole folder, including lib\ and config\.

 "Unknown scenario 'EnterpriseCA' ... none defined"
     config\capture-settings.psd1 is missing from the kit folder.

 "Capture state not found"
     You are running Stop on a host where Start was not run, or with a
     different -Label.

 "Access is denied" writing the SACL
     You are not Domain Admin / Enterprise Admin in that session.

 Report is empty / ad-configuration shows 0 changes
     The baseline was taken after the CA was already registered. Revert the
     DC and CA VM snapshots and start again.

 DON'T: interrupt Start (the state file is written at the end);
        run Stop before the CA is registered;
        copy files into C:\Users\... while the window is open (they show up
        in your own file diff).
===============================================================================

