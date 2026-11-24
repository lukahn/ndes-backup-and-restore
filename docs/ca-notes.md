# CA notes

Working notes from the lab where this kit was developed. Hostnames, addresses and
account names have been replaced with placeholders; the topology and the reasoning
are unchanged.

---
===============================================================================
 CA SERVER  -  CA EXERCISE
 Label: ca     Scenario: EnterpriseCA
 Account: administrator, PowerShell "as administrator"
===============================================================================

 The label must be the same as on the AD server (ca).

 Kit location assumed below:  C:\Tools\ndes-backup-and-restore

 This host captures its OWN local state, not the directory:
   - CertSvc registry configuration
   - installed roles / features / DISM packages
   - certificates, services, firewall, scheduled tasks
   - IIS configuration (only if IIS is installed; an enterprise CA does not
     need it - web enrollment does)

 The directory writes are captured on the AD server (see AD-CA.txt).

-------------------------------------------------------------------------------
 BEFORE  -  before you install / configure the CA role
-------------------------------------------------------------------------------

cd C:\Tools\ndes-backup-and-restore
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 1. Take the baseline (T0).
.\Start-NdesCapture.ps1 -Label ca -Scenario EnterpriseCA

   Expected last lines:
     baseline complete - 0 collector(s) failed
     state: C:\NdesCapture\CA\state-ca.json

   Expect a pause at "collect registry" - the HKLM exports are large. That is
   normal; do not press Ctrl+C (the state file is written at the very end).

   Now install and configure the CA (install the AD CS role, then run the
   AD CS Configuration wizard and register it as an enterprise CA).

-------------------------------------------------------------------------------
 AFTER  -  once the CA is installed and registered
-------------------------------------------------------------------------------

cd C:\Tools\ndes-backup-and-restore
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 2. Close the capture window (T1).
.\Stop-NdesCapture.ps1 -Label ca

# 3. Build the report.
.\Compare-NdesCapture.ps1 -Label ca

# 4. Read it.
notepad C:\NdesCapture\CA\report-ca\report.md

-------------------------------------------------------------------------------
 WHAT YOU SHOULD SEE
-------------------------------------------------------------------------------

 In C:\NdesCapture\CA\report-ca\report.md:

   ## Roles and features
     ADCS-Cert-Authority and friends: Available -> Installed
     plus the DISM package for AD CS

   ## High-signal changes  (Registry)
     HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\... 
     (CA name, CA type, CSP, key length, validity, CDP/AIA paths)

   ## MSCEP configuration as installed
     (empty on a CA-only host - that appears on the NDES server)

 The "EnterpriseCA focus" section will be empty here. That is correct: this is
 a member server, so the ad-domain / ad-configuration collectors are skipped
 (the log says "ad: not a domain controller, skipped"). The directory evidence
 is in the AD server's report.

 Handy extracts:

   Import-Csv C:\NdesCapture\CA\report-ca\changes.csv |
     Where-Object { $_.Area -eq 'Registry' } |
     Format-Table Change,Target,Name,Before,After -AutoSize

   Get-Content C:\NdesCapture\CA\T1-ca\features\installed-roles.txt

-------------------------------------------------------------------------------
 TROUBLESHOOTING
-------------------------------------------------------------------------------

 "cannot be loaded ... is not digitally signed"
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

 "Module not found ... \lib\NdesCapture.psm1"
     Copy the whole kit folder, not just the .ps1 files.

 "Capture state not found"
     Start was not run on this host, or with a different -Label.

 The "ad" collector being skipped is expected and harmless on this host.

 DON'T: interrupt Start; run Stop before the CA is configured.
===============================================================================

