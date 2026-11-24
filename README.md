# NDES lab capture kit

Instrumentation for measuring **exactly what an NDES install changes** across an
AD / CA / NDES lab, and for rebuilding that install on another server from a
bundle — with the evidence for every decision recorded in this repository.

| Folder | What is in it |
| --- | --- |
| `capture/` | Measures what an NDES install changes: `Start-NdesCapture.ps1`, `Stop-NdesCapture.ps1`, `Compare-NdesCapture.ps1`, plus the optional file- and directory-auditing helpers, `lib/` and `config/` |
| `migration/` | `NDESMigration.ps1` (`-Backup` / `-Restore` / `-Verify`), `Get-TemplateFlags.ps1`, `Diagnose-Ndes503.ps1` |
| `test/` | `Test-NdesEnrollment.ps1` — a real SCEP enrolment over HTTP and HTTPS, using only inbox Windows code |
| `docs/` | Working notes from the lab that produced this, with hostnames and accounts replaced by placeholders |

Capture output, bundles and logs are deliberately not published — see
[`.gitignore`](./.gitignore). They contain registry exports, account names and
certificate thumbprints, and they are large.

Target platform: **Windows Server 2019**, Windows PowerShell 5.1. No modules to
install beyond what ships with the role.

```powershell
# on each VM: measure the baseline, install NDES, measure again, compare
.\capture\Start-NdesCapture.ps1 -Label ndes
.\capture\Stop-NdesCapture.ps1  -Label ndes
.\capture\Compare-NdesCapture.ps1 -Label ndes

# on the working server, then on the new one
.\migration\NDESMigration.ps1 -Backup
.\migration\NDESMigration.ps1 -Restore -Path C:\NDESMigration\NDES-<stamp> `
    -RAEncryptionTemplate CEPEncryption -RASigningTemplate MachineEnrollmentAgent

# prove it actually enrols
.\test\Test-NdesEnrollment.ps1 -Server ndes.contoso.com
```

---

## What it captures

| Area | Method | Proves |
| --- | --- | --- |
| AD | LDIF export of the domain + Configuration NC, diffed attribute by attribute | what changed, with old and new values |
| AD | `whenChanged` sweep | every object touched in the window, including ones with no visible attribute delta |
| AD | 5136 events (optional, needs a SACL) | **which account** made each write - this is what answers the Enterprise Admin question |
| Registry | `reg export` of HKLM\SOFTWARE, CurrentControlSet\Services, CurrentControlSet\Control | every value written, with before/after |
| Files | USN journal from the T0 cursor (`startusn=`) | every path touched on the volume, with reason flags |
| Files | metadata inventory + SHA256 of `inetsrv\config` and `certsrv` | fallback when the journal is unavailable; exact bytes where they matter |
| IIS | `applicationHost.config` + `appcmd list` object dumps | app pool, vdir, site and handler changes |
| Features | `Get-WindowsFeature` + `dism /get-features` | the exact feature set a rebuilt server needs |
| Services, certs, firewall, tasks | WMI / cert stores / netsh / scheduler | supporting state a rebuild must reproduce |

Everything is auto-detected per host: the AD collector only runs on a domain
controller, the IIS collector only when IIS is installed.

---

## Prerequisites

- Run PowerShell **elevated** on each VM. USN journal reads and `netsh
  advfirewall export` require it; without elevation the file collector degrades
  to metadata inventory and says so in the log.
- On the DC: the `ActiveDirectory` PowerShell module (present by default) and
  `ldifde.exe` (present by default).
- To capture 5136 attribution, run
  [Enable-AdDirectoryAuditing.ps1](./capture/Enable-AdDirectoryAuditing.ps1) `-Apply`
  on the DC first. This needs `SeSecurityPrivilege`, which the script enables
  for itself - just run it elevated as a Domain Admin.
- Expect the Security log to grow while auditing is on. `-Revert` when done.

---

## Scenarios

`-Scenario <name>` re-tunes what counts as high-signal and adds a dedicated
report section. Profiles live in `Scenarios` in
[config/capture-settings.psd1](./capture/config/capture-settings.psd1).

| Scenario | Use for | Focus |
| --- | --- | --- |
| *(none)* | NDES install | everything is triaged as before |
| `EnterpriseCA` | installing/registering an enterprise CA | `CN=Public Key Services`, `NTAuthCertificates`, `Cert Publishers`, `CertSvc` |

`EnterpriseCA` differs from the default in three ways:

1. **`ad\|` (blanket "all AD is important") is replaced** by rules that target
   the PKI containers, so unrelated directory churn drops to `Review` instead of
   crowding the report.
2. **Machine-account noise** (`pwdLastSet`, `logonCount`, …) is filtered out.
3. **A focus section** groups changes by AD container, decodes published
   certificates to subject/issuer/thumbprint, and reports which account
   performed each write.

The scenario also implies the Configuration partition for auditing, because
nearly all PKI state lives there. `Start` handles that automatically on a DC:

```powershell
# on the DC
.\capture\Start-NdesCapture.ps1 -Label ca -Scenario EnterpriseCA
# ... install and register the enterprise CA ...
.\capture\Stop-NdesCapture.ps1  -Label ca -Scenario EnterpriseCA
.\capture\Compare-NdesCapture.ps1 -Label ca -Scenario EnterpriseCA

# on the CA server (local state: CertSvc registry, IIS, features)
.\capture\Start-NdesCapture.ps1 -Label ca -Scenario EnterpriseCA
# ... same operation ...
.\capture\Stop-NdesCapture.ps1  -Label ca -Scenario EnterpriseCA
.\capture\Compare-NdesCapture.ps1 -Label ca -Scenario EnterpriseCA
```

The scenario is recorded in the capture state, so `Stop` and `Compare` pick it up
automatically if you omit `-Scenario`.

---

## Procedure

Do this once per VM, using the **same `-Label`** on each.

### 0. Attribution is automatic

On a domain controller, `Start` switches directory-change auditing on by
default (audit subcategory + inheritable SACL on the domain and Configuration
naming contexts), and `Stop` switches it back off. Nothing extra to run.

```powershell
.\capture\Start-NdesCapture.ps1 -Label ndes     # enables 5136 attribution on a DC
.\capture\Stop-NdesCapture.ps1  -Label ndes     # reverts it
```

Control it with `-NoDirectoryAuditing` (skip) or `-KeepAuditing` (leave the
SACL in place after `Stop`). It only acts when a SACL is missing, so a second
capture does not stack duplicate entries, and it only reverts what *it*
enabled.

Requires an elevated Domain Admin / Enterprise Admin session; if that is not
available the capture still runs and logs a warning, but the report will not be
able to say which account changed anything. `Enable-AdDirectoryAuditing.ps1`
remains available for turning attribution on outside a capture.

### 1. Baseline, on all three VMs, before touching anything

```powershell
.\capture\Start-NdesCapture.ps1 -Label ndes
```

Useful switches:

- `-RegistryScope Full` - export all of `HKLM` instead of the narrow hive list.
  Slower and larger; use it if you suspect the default list misses something.
- `-IncludeUserHives` - also snapshot loaded `HKEY_USERS` hives.
- `-IncludeUserStore` - also snapshot the current user's personal certificate store.
- `-Root D:\capture` - where captures live (default `C:\NdesCapture`).

### 2. Install NDES end to end

Run the wizard or `Install-AdcsNetworkDeviceEnrollmentService` exactly as you
would in production. Do not clean up afterwards - the mess is the evidence.

### 3. Post-install, on all three VMs

```powershell
.\capture\Stop-NdesCapture.ps1 -Label ndes
```

### 4. Diff, on each VM

```powershell
.\capture\Compare-NdesCapture.ps1 -Label ndes
```

Then read `<Root>\<Host>\report-ndes\report.md`.

You can also copy all three `C:\NdesCapture\<Host>` folders to one analyst box
and run:

```powershell
.\capture\Compare-NdesCapture.ps1 -Root D:\bundles -HostName NDES01 -Label ndes
```

Attribution is reverted automatically by `Stop`; there is no separate cleanup
step. Use `-KeepAuditing` on `Stop` if you want the audit SACL to stay.

---

## Outputs and re-running the report

Nothing is summarised at capture time — `Start` and `Stop` only record evidence.
All analysis happens in `Compare-NdesCapture.ps1`, which is **read-only with
respect to the evidence**, so you can re-run it as often as you like.

Everything lives under `-Root` (default `C:\NdesCapture`), one folder per host:

```
C:\NdesCapture\<HOSTNAME>\
├── T0-<label>\                 baseline evidence
│   ├── capture-settings.psd1   copy of the settings used (see below)
│   ├── system\  registry\  files\  iis\  features\  services\  certs\  ad\
├── T1-<label>\                 post-change evidence (same layout)
├── state-<label>.json          window, USN cursor, scenario, collector results
├── capture-<label>.log         timestamped log of both runs
└── report-<label>\             written by Compare, overwritten on each run
    ├── report.md               triaged report - start here
    ├── changes.csv             every change, machine readable
    ├── high-signal.csv         just the high-signal subset
    └── compare.log
```

To regenerate the report later, on the same machine:

```powershell
.\capture\Compare-NdesCapture.ps1 -Label ca
```

Or from a bundle copied to an analyst box:

```powershell
.\capture\Compare-NdesCapture.ps1 -Root D:\bundles -HostName AD -Label ca
```

Useful switches when re-running:

| Switch | Effect |
| --- | --- |
| `-IncludeNoise` | include the filtered noise rows in the report |
| `-OutDir <path>` | write to a different folder, leaving the previous report intact |
| `-SettingsPath <path>` | diff against a different classification profile |
| `-Scenario <name>` | re-triage under a named scenario |

**Reproducibility:** the settings file in effect at capture time is copied into
`T0-<label>\capture-settings.psd1` (and `T1`). `Compare` prefers the recorded
path, and falls back to that snapshot if the original has moved or been edited —
so an archived bundle re-diffs exactly as it did originally. The report header
records which settings file was used.

`Stop-NdesCapture.ps1 -Zip` additionally bundles `T0`, `T1`, the state file and
the log into `<Root>\<HOSTNAME>-<label>.zip` for copying off the machine.

---

## File auditing - which account changed which file (optional)

The USN journal records *what* changed on a volume, never *who*. It is worth
being explicit about this: no amount of parsing yields an account for a file
change. Attribution needs a different mechanism:

| | AD objects | Files on disk |
| --- | --- | --- |
| Event | 5136 | **4663** |
| Enabled by | `Start` on a DC, automatically | `Start -FileAuditing` |
| Requires | SACL on the naming context | SACL on each folder + `Audit File System` |
| Volume | tens of events | thousands per minute on a busy DC |

Use it only when you need "who touched this file". Scope it to one or two
folders - never a whole system volume.

```powershell
# configure the paths once (or pass -FileAuditingPaths nowhere: the default
# list lives in FileAudit.Paths in config\capture-settings.psd1)
# C:\Windows\System32\CertLog is the default

# capture, opting in to 4663 collection - Start applies the SACLs for you
.\capture\Start-NdesCapture.ps1 -Label ca -FileAuditing
# ... do the thing ...
.\capture\Stop-NdesCapture.ps1  -Label ca -FileAuditing
.\capture\Compare-NdesCapture.ps1 -Label ca
```

`Stop` reverts the file SACLs it applied, unless `-KeepAuditing` is passed.
`Enable-FileAuditing.ps1` remains available for setting this up outside a
capture, or for inspecting current state with `-Status`.

Paths may also come from `-PathFile <file>` (one path per line, `#` comments)
or from `FileAudit.Paths` in
[config/capture-settings.psd1](./capture/config/capture-settings.psd1).

The report gains a **"File modifications by account"** section:

```
**contoso\ea** - 2 event(s) across 2 file(s)

Processes: certsrv.exe

- `C:\Windows\System32\CertLog\Lab-CA.edb` - WriteData,WriteAttributes
- `C:\Windows\System32\CertLog\edb00001.log` - WriteData

**contoso\CA$** - 1 event(s) across 1 file(s)
```

Only modification rights are audited (`WriteData`, `AppendData`,
`WriteAttributes`, `Delete`, `ChangePermissions`, `TakeOwnership`, ...), success
only. Auditing reads multiplies the event count for no benefit.

---

## Migrating NDES to another server (no Enterprise Admin)

[NDESMigration.ps1](./migration/NDESMigration.ps1) rebuilds an NDES configuration on a new
server **without the NDES setup wizard**, and therefore without Enterprise Admin.

The wizard needs EA because it publishes RA certificates to the service account
in AD. This script reproduces the configuration directly instead:

| Step | Done by |
| --- | --- |
| Roles and features | `Install-WindowsFeature` |
| `SCEP` app pool + `Certsrv/mscep*` applications | `appcmd` |
| App pool identity (account + password) | `appcmd` — **the step IIS Manager cannot do here** |
| Authentication, ISAPI registration, default document | `appcmd` |
| NDES registry (three keys — see below) | written from the bundle |
| RA certificates | re-enrolled into `LocalMachine\My` |
| Server certificate | re-requested for the target host, then bound with `netsh` |

### Roles and features: parity with a hand-built server

`-Restore` installs the bundle's feature list **plus the delta between a fresh
server and the hand-built reference server** - the difference between
`softwareCheck/installed-base.txt` and `softwareCheck/installed-manually.txt`.
The result has to be *the same 57 features*, not a superset, so two rules apply:

1. **Defaults are never requested.** A fresh server already has 12 of them
   (`FileAndStorage-Services`, `NET-Framework-45-Features`/`-Core`,
   `NET-WCF-Services45`, `NET-WCF-TCP-PortSharing45`, `Windows-Defender`,
   `PowerShellRoot`/`PowerShell`/`PowerShell-ISE`, `Storage-Services`,
   `WoW64-Support`, `XPS-Viewer`).
2. **Leaves are requested, never intermediate parents.** `Install-WindowsFeature`
   installs a feature *and its default children*, so asking for a parent pulls in
   siblings the reference build never had. Parents still arrive - they are
   dependencies of the leaves - they are just never asked for.

| Requested (39) | Group |
| --- | --- |
| `ADCS-Device-Enrollment` | the NDES role service; `AD-Certificate` arrives as its parent |
| `WAS`, `WAS-Process-Model`, `WAS-NET-Environment`, `WAS-Config-APIs` | WAS, fully selected |
| `NET-Framework-Features`, `NET-Framework-Core`, `NET-HTTP-Activation`, `NET-Framework-45-ASPNET`, `NET-WCF-HTTP-Activation45` | .NET 3.5 stack and the 4.x **HTTP activation** |
| 24 IIS role services | `Web-Server`, `Web-WebServer`, HTTP/health/performance/security/app-dev, ISAPI Extensions and Filters |
| `Web-Mgmt-Console`, `Web-Metabase`, `Web-WMI` | IIS Manager, IIS 6 metabase and WMI (not the IIS 6 console) |
| `RSAT-ADCS-Mgmt` | the CA console MMC add-on |
| `PowerShell-V2` | in the reference build, not on a fresh server |

What is deliberately **never requested**, because each one drags a subtree the
reference build does not have:

| Not requested | What it would install |
| --- | --- |
| `AD-Certificate` | `ADCS-Cert-Authority` - the CA role service |
| `ADCS-Cert-Authority` | the CA role service; the documented procedure clears its check box |
| `RSAT`, `RSAT-Role-Tools` | every RSAT tool: AD DS tools, Hyper-V, RDS, WSUS, SMTP |
| `RSAT-ADCS` | `RSAT-Online-Responder` |
| `NET-WCF-Services45` | MSMQ + the MSMQ/Pipe/TCP activations |
| `Web-Mgmt-Tools`, `Web-Mgmt-Compat` | the IIS 6 management console |
| the 12 fresh-server defaults | nothing - they are already installed |

Installing that way is what keeps the build identical. Requesting those parents
plus `-IncludeManagementTools` is how an earlier revision reached 81 features
instead of 57; `softwareCheck/installed-automated-2.txt` is that run.

HTTP Activation is in the list because the documented NDES installation selects
it - under **.NET Framework 3.5 Features** and under **.NET Framework 4.5 Features
> WCF Services** - on the Features page
([Microsoft Learn](https://learn.microsoft.com/windows/security/identity-protection/hello-for-business/hello-hybrid-aadj-sso-cert)).

Features that this build does not have are skipped with a warning (newer Server
releases drop `PowerShell-V2`, for example), and the .NET 3.5 group needs the
payload, which newer builds remove by default - the same caveat the documentation
gives, where an offline server needs `\Sources\SxS\`:

```
  [warn] Feature installation failed: The source files could not be found (0x800F0954).
  [warn] Retrying without the .NET 3.5 payload features (NET-Framework-Features, NET-Framework-Core,
         NET-HTTP-Activation, Web-Net-Ext, WAS-NET-Environment); add them by hand with an alternate
         source (Sources\SxS) if they are required.
  [warn] Requested but not installed: NET-Framework-Core, NET-Framework-Features, NET-HTTP-Activation,
         WAS-NET-Environment, Web-Net-Ext
```

`-Restore` finishes by checking parity in both directions:

```
[ok]   Feature parity: all 57 expected feature(s) installed
[warn] Features the reference build does not have: ADCS-Cert-Authority, Web-Lgcy-Mgmt-Console
[warn] Each of these is a default child of a parent feature (AD-Certificate, RSAT, RSAT-ADCS,
       NET-WCF-Services45, Web-Mgmt-Tools/Compat). Requesting the parent installs the whole
       group; requesting the leaves installs only what is needed.
```

Missing features are counted as failures. So are extra AD CS role services,
because they change what the host is: a precise install never creates
`ADCS-Cert-Authority`, and installed-but-unconfigured it is also what keeps the
Server Manager post-deployment tile showing. The other over-install indicators
(RSAT tools, the IIS 6 console, MSMQ and the extra WCF activations) are reported
without failing the run - they may pre-date the restore, and only the operator
can say whether to uninstall them. On a clean rebuild the list is empty.

This works because the source is configured with `CertsInMYStore = 1`: RA
certificates are located by template in the machine store, so nothing
machine-specific (no thumbprint hashes, no private-key copies) has to move.

### Backup

```powershell
# on the working NDES server: default destination
.\migration\NDESMigration.ps1 -Backup

# choose where the bundle goes
.\migration\NDESMigration.ps1 -Backup -Path D:\Backups\ndes-2026-11

# or build a bundle from an existing NdesCapture folder
.\migration\NDESMigration.ps1 -Backup -FromCapture C:\Uploads\NdesCapture-NDES -Path C:\Staging\ndes
```

`-Path` is the bundle **folder** — the script writes `ndes-config.json` into it.
The default is `C:\NDESMigration\<host>-<timestamp>`, so repeated backups never
collide. An existing folder is a valid destination; only an existing
`ndes-config.json` is a conflict, and that needs `-Force` to overwrite. Relative
paths and UNC paths (`\\server\share\...)` both work.

Writes `ndes-config.json` (typically ~12 KB) plus a log. It contains **no
passwords and no private keys** — the app pool password is encrypted with the
source machine's WAS key and cannot leave it.

### Restore

```powershell
# on the new server: domain-joined, elevated
.\migration\NDESMigration.ps1 -Restore -Path C:\Staging\ndes

# -Path also accepts the file itself, which is what people copy across
.\migration\NDESMigration.ps1 -Restore -Path C:\Staging\ndes\ndes-config.json

# see every change first, without making any
.\migration\NDESMigration.ps1 -Restore -Path C:\Staging\ndes -WhatIf
```

`-WhatIf` covers the app pool, applications, registry values, certificate
requests and certificate binding, and reports "would write" instead of "wrote".

You are prompted to confirm, each defaulting to the backed-up value:

| Prompt | Default |
| --- | --- |
| Service account | `CONTOSO\svc_ndes` |
| CA configuration | `ca.contoso.com\CONTOSO-SUBCA` |
| Server certificate template | `NDESServer` |
| RA encryption template | MSCEP `EncryptionTemplate` (`NDESUser`) |
| RA signing template | MSCEP `SignatureTemplate` (`NDESUser`) |
| Server FQDN | `hostname.dnsdomain` |

then for the service account password, which is used only to set the app pool
identity and is never written to disk.

### RA templates must match the MSCEP values

With `CertsInMYStore = 1`, NDES finds its RA certificates **by template name**.
The restore therefore enrols from whatever MSCEP `EncryptionTemplate` and
`SignatureTemplate` say, and if you override either prompt it writes the new name
back into MSCEP in the same run — the certificate and the value can't drift
apart.

The direction matters, and the two are easy to swap:

| MSCEP value | Certificate | Default template |
| --- | --- | --- |
| `EncryptionTemplate` | encrypts the SCEP challenge | `CEPEncryption` (CEP Encryption) |
| `SignatureTemplate` | signs requests to the CA | `EnrollmentAgent` (**Enrollment Agent**, computer) |

The signing role needs the **computer** enrollment agent template.
`EnrollmentAgentOffline` — "Exchange Enrollment Agent (Offline request)" — is the
*user* variant and refuses machine requests with `CONTEXT_E_ROLENOTFOUND`, no matter
what its ACL says. That distinction cost several rounds here; the giveaway is the
template's `Intended Purpose` in the CA console.

A request made as the **computer account** against a template ACL that only lists
user principals fails with:

```
CERTSRV_E_TEMPLATE_DENIED 0x80094012
The permissions on the certificate template do not allow the current user to enroll
```

so the request is made as the **service account**, into `LocalMachine\My`.

### What the two RA certificates actually do

NDES is the middleman between a device that has no Kerberos identity and a CA that
only speaks AD-authenticated enrolment. The device proves itself with a one-time
password from `mscep_admin`; the two RA certificates are what let NDES act on its
behalf:

| Certificate | Template | Role |
| --- | --- | --- |
| Encryption (`EncryptionTemplate`) | `CEP Encryption` / `NDESUser` | NDES decrypts the device's encrypted SCEP message with it, and protects the challenge-password exchange |
| Signing (`SignatureTemplate`) | `Exchange Enrollment Agent (Offline request)` / `NDESUser` | NDES signs the device's PKCS#10 as an **enrollment agent**, so the CA will issue to a subject that never authenticated itself |

The signing one is the interesting case: without an enrollment-agent signature the
CA has no reason to trust a request naming some router's subject, so it refuses.
That is the entire reason NDES needs a Certificate Request Agent certificate.

They are **per-server, not per-service**. A new NDES server needs its own pair from
the same templates; nothing about the old server's certificates is carried over.

The original Enterprise Admin requirement came from the setup wizard enrolling them
**as an admin user** (CA database rows 3 and 4, requester `CONTOSO\ea`). It was never
about the RA certificates being special — it was about which identity held Enroll
on the templates at that moment.


Worth proving rather than assuming. The CA database records the requester of every
request, issued or failed. On the CA:

```powershell
certutil -config "ca.contoso.com\CONTOSO-SUBCA" -view `
         -out "RequestID,RequesterName,SubmittedWhen,Subject,Disposition" csv |
  Out-File C:\ca-requests.csv -Encoding utf8
```

On the lab build of this project that produced:

| Request | Requester | Template | Reading |
| --- | --- | --- | --- |
| 3 | `CONTOSO\ea` | Exchange Enrollment Agent (Offline request) | EA enrolled the RA certs |
| 4 | `CONTOSO\ea` | CEP Encryption | — that is the Enterprise Admin requirement |
| 5 | `CONTOSO\NDES$` | NDESServer | server cert, machine account |
| 6 | `CONTOSO\svc_ndes` | NDESUser | RA cert, service account |

Two conclusions, both useful:

- The **Enterprise Admin** step exists because setup ran as EA to enrol the RA
  templates. It is not needed once a template grants `svc_ndes` Enroll — which is
  the point of this script.
- RA certificates are always requested by a **user** identity, never the computer
  account. The server certificate is the opposite: it is requested by the machine.

### Two ways to authenticate the request

`Get-Certificate` derives the enrolment **context** from `-CertStoreLocation`:
`LocalMachine\My` always means machine context, whatever credential is supplied. A
user-only RA template therefore refuses the request at build time with
`0x8004e00c CONTEXT_E_ROLENOTFOUND` — no ACL or impersonation changes that.

So the default path does not use `Get-Certificate` at all:

| Step | Runs as | Store |
| --- | --- | --- |
| `certreq -new` builds the key + CSR | you (elevated) | machine |
| `certreq -submit` sends the CSR | **the service account** | — (writes the issued cert to a file) |
| `certreq -machine -accept` installs it | you (elevated) | machine |

That separation is the whole trick: the *key* is machine-scope, so it stays in
`LocalMachine\My` and never needs exporting, while the *request* is authenticated
as `svc_ndes`, so the template's user-only rule and its ACLs both apply to the
right identity. Submitting to a file rather than installing means the service
account needs no local administrator rights.

The alternative is a CEP policy endpoint, which requires the Certificate
Enrollment Policy role service on the CA:

```powershell
.\migration\NDESMigration.ps1 -Restore -Path C:\Staging\ndes `
    -EnrollmentPolicyUrl https://ca.contoso.com/ADPolicyProvider_CEP_UsernamePassword/service.svc
```

Either way the script prints the identity it will use:

```
Requesting as      : CONTOSO\svc_ndes (service account)
```

Work files go to `%ProgramData%\ndes-ra` and are removed afterwards. The service
account is granted **Modify** on that folder only so it can write the issued
certificate; the ACE is not removed by the script, so delete the folder if you
want it gone.

`http://<CA>/certsrv/` is **not** a CEP endpoint, despite looking like the obvious
URL — it is the Web Enrollment directory, and passing it fails with
`CX509EnrollmentPolicyWebService::Initialize: ERROR_INVALID_PARAMETER (0x80070057)`.

A template duplicated from the built-in **User** template behaves as user-only; the
CA's `Intended Purpose` column reveals it (`Secure Email, Encrypting File System,
Client Authentication`). Note that such a template also lacks the **Certificate
Request Agent** EKU, which NDES needs for the signing role — check
`Certificate Templates` → template → `Extensions` → `Application Policies`.

### Private key access

Whichever identity enrols, the key file carries an ACE only for that identity plus
Administrators and SYSTEM. The SCEP app pool runs as the service account, so the
restore grants it **Read** on each RA private key afterwards
(`Grant-CertificateKeyRead`). Without that, NDES starts but cannot use its RA
certificates.

### The recipe that works (verified)

A full rebuild was performed from a pre-NDES snapshot with no Enterprise Admin,
no template edits during the run, and no certificate export. What it took:

| Role | MSCEP value | Template | Why |
| --- | --- | --- | --- |
| Encryption | `EncryptionTemplate` | `CEPEncryption` | machine-capable (flags bit `0x40`) |
| Signing | `SignatureTemplate` | `MachineEnrollmentAgent` | machine-capable **and** Certificate Request Agent EKU |

One durable AD change: `NDES-Servers` holding **Read + Enroll** on both templates.
It already contains the NDES computer objects, so every future rebuild inherits it.

`-Backup` now checks this up front: it reads the `flags` attribute of whatever
`EncryptionTemplate` / `SignatureTemplate` the source is using and warns when a
template is not machine-capable, instead of letting a restore discover it after
the roles, the app pool and the site have already been rebuilt.

Verification of the finished server:

```
[ok] Application pool SCEP: Started
[ok] Device endpoint responded HTTP 401
[ok] Admin endpoint: HTTP 200, password page: True
[ok] All checks passed.
```

### Templates that do NOT work for this

All of these are user-only. The enrolment API refuses a `LocalMachine\My` request
before the ACL is consulted, whatever you grant:

- `EnrollmentAgentOffline` — Exchange Enrollment Agent (Offline request)
- `EnrollmentAgent` — Enrollment Agent
- `NDESUser` — a duplicate of the built-in `User` template

Diagnose with `Get-TemplateFlags.ps1`, which prints the `flags` attribute and a
`Type` column. Bit `0x40` means machine type; user-only templates do not have it.
Do not read the type from any other bit — `Machine` and `MachineEnrollmentAgent`
share `0x10260`, while `User` is `0x1023A` and `NDESUser` is `0x2023A`, so several
bits overlap between the two kinds.

`Get-Certificate` derives the enrolment *context* from `-CertStoreLocation`, so
`LocalMachine\My` is always machine context — supplying `-Credential` changes who
authenticates but not which context the request is built in.

A user-only template is a separate failure (`0x8004e00c
CONTEXT_E_ROLENOTFOUND`) and needs the source server's template, not a permission
change.

### Preflight checks

`-WhatIf` answers *what will change*. It does **not** answer *whether it would
work* — a dry run performs no validation, so a permission problem still surfaces
as a hard failure halfway through. The restore therefore begins with a read-only
preflight, and `-Preflight` runs just that and stops:

```powershell
# check the target without touching it
.\migration\NDESMigration.ps1 -Restore -Path C:\Staging\ndes -Preflight
```

It is also run automatically at the start of every restore (skip it with
`-SkipPreflight`). Any `FAIL` stops the restore before the first change.

| Phase | Checks |
| --- | --- |
| Host | elevated, OS version, domain-joined, PKI module, IIS present |
| Directory | LDAP reachable, computer account exists and is enabled, service account exists and is enabled, service account password (LDAP bind), not a local admin |
| CA | CA host resolves, RPC 135 reachable, `certutil -ping` against the config string, each template published on the CA (`certutil -CATemplates`) |
| CA (advisory) | template enrol ACL evaluated for the **computer account** using its flattened group SIDs (`tokenGroups`) |

The ACL check resolves rights by name from AD's own `CN=Extended-Rights`
container rather than assuming GUIDs, honours explicit denies, and treats
`GenericAll` as full control. It is labelled **advisory**: it cannot model S4U,
logon rights, CA policy modules or template supersedence, so a pass is never
proof and a warn is never a certainty.

Everything genuinely unknowable without attempting is listed explicitly instead
of being silently assumed:

```
-- Unverifiable
   n/a  Whether the CA will issue the certificate: manager approval, policy module, template supersedence - only a real request proves it
   n/a  Whether http.sys accepts the certificate binding: needs an actual netsh binding
   n/a  Whether the NDES ISAPI serves requests: needs the configured service running
   n/a  ACL evaluation completeness (advisory checks): S4U and logon rights are not modelled
```

### Re-running a half-finished restore

The restore is safe to re-run: features, the app pool, applications,
authentication, ISAPI registration and group membership are all applied
idempotently, and an existing bundle or certificate is only replaced with
`-Force`. A restore that stopped at the certificate step needs no snapshot
revert — fix the cause and run it again.

### Prerequisites on the target

- Domain-joined, and running elevated.
- The **service account** needs Read + Enroll on the RA templates the restore
  uses, and Request Certificates on the CA — normally already true on a server
  built by the NDES wizard.
- The restoring account needs local Administrator and Request Certificates on
  the CA, since it writes the private keys into the machine store. It does **not**
  need Enterprise Admin, Domain Admin, or any rights on the service account's AD
  object.
- If `Install-WindowsFeature` needs a restart, the script stops and asks you to
  reboot and run `-Restore` again.

### Rotating the service account password

WAS caches the app pool identity credential. Changing `svc_ndes`'s password
without refreshing the identity produces:

```
The identity of application pool SCEP is invalid...
Application pool SCEP has been disabled...
```

and then HTTP **503** on every SCEP URL. It is not an NDES problem — the pool has
no worker process. Re-run `-Restore` (it re-sets the identity and `iisreset`
restarts WAS), or force it directly:

```powershell
Import-Module WebAdministration
$pw = Read-Host 'svc_ndes password' -AsSecureString
Set-ItemProperty IIS:\AppPools\SCEP -Name processModel.password -Value ([System.Net.NetworkCredential]::new('', $pw).Password)
Restart-Service WAS -Force
```

`-Restore` now performs the same batch logon that WAS does (`LogonUser` with
`LOGON32_LOGON_BATCH`) immediately after the password prompt, and stops before
changing anything if it fails — reporting wrong password, missing "Log on as a
batch job", or an expired password. Skipping that with `-SkipPreflight` is how the
503 gets through.

### What it deliberately does not do

- **Copy certificates.** Server-specific and RA certificates are re-enrolled.
- **Grant the service account local Administrator.** Only `IIS_IUSRS` is added;
  the script warns if the account is already an admin, since that is exactly the
  privilege the no-EA method exists to avoid.
- **Store secrets.** No password, no key file, no `[enc:]` blob.
- **Touch AD.** Nothing is written to the directory, which is why EA is not
  required.

### Verification

`-Restore` finishes with checks: every captured registry value read back and
compared by name, path and type (MSCEP values out of the nested key tree, plus
`ADCS\NDES\ConfigurationStatus` and the two `HTTP\Parameters` limits), two RA
certificates, `mscep.dll` present, the anonymous device endpoint responding, the
admin page reachable, and the CA reachable on 135. A non-zero summary points at
the failing layer.

### Verification: does the target match the source?

A restore can report success for every step and still produce a server that is not
the same as the one it came from: `appcmd` accepts settings a locked section
ignores, an application that "already exists" keeps its old values, and a skipped
feature leaves the previous install's files in place. So `-Restore` ends by reading
the server back and comparing it with the bundle, item by item:

```
== Comparing this server with the bundle
  -- IIS
     /CertSrv/mscep :: application                             present
   ~ /CertSrv/mscep :: handlers accessPolicy                   source=Read, Execute ; this server=Read, Script
   ~ /CertSrv/mscep :: anonymous                               source=true ; this server=false
   ! /CertSrv/mscep :: allowDoubleEscaping                     source=true ; this server has nothing
  -- Endpoint
     /CertSrv/mscep anonymous GetCACaps                        HTTP 200 with capabilities
   43 comparison(s): 41 match, 2 differ
```

`!` means the setting is absent, `~` means it is present and different. Areas
compared: registry (every value the bundle recorded, MSCEP nested paths included),
the application pool, each application with its physical path and pool, the
per-application IIS settings that decide whether the ISAPI runs and who may reach
it, the ISAPI restriction entry and its group id, the MSCEP application dependency,
handler order, the bundle's feature set, the HTTPS binding and bound certificate,
the RA certificates, and both endpoints.

The comparison runs as part of `-Restore`, and on its own without changing
anything:

```powershell
# compare this server with a bundle; nothing is written, nothing is prompted
.\migration\NDESMigration.ps1 -Restore -Path C:\NDESMigration\NDES-20261124-221156 -Verify `
    -RAEncryptionTemplate CEPEncryption -RASigningTemplate MachineEnrollmentAgent
```

Each difference carries the repair that owns it, so `-Restore` offers to fix what
it found - one prompt per repair, listing the settings it covers:

```
  -- IIS
   ~ /CertSrv/mscep :: handlers accessPolicy                   source=Read, Execute ; this server=Read, Script
   ~ /CertSrv/mscep :: anonymous                               source=true ; this server=false

== Repairing the differences
  [warn] 2 difference(s): /CertSrv/mscep :: handlers accessPolicy; /CertSrv/mscep :: anonymous
  rewrite the per-application IIS settings? [Y/n]
  [ok]   applied: rewrite the per-application IIS settings

== Re-checking after the repair
   ...
   43 comparison(s): 43 match, 0 differ
```

Answer `n` to leave a setting alone. `-FixDrift` applies every repair without
asking, and the comparison is re-run afterwards so the summary reflects what is
actually on the server. Repairs that exist: the registry values, the application
pool, the applications, the per-application IIS settings, the ISAPI registration
and its dependency, handler order, the feature set, the HTTPS binding (and, as a
catch-all, the whole SCEP IIS configuration followed by an IIS restart).

Certificates and live endpoints have no automatic repair - those differences are
listed by name and left to you, because re-enrolling a certificate or restarting a
service is not something to do on a guess.

The endpoint rows are the ones that matter most. `mscep.dll` being on disk, the IIS
applications existing and even a `200` from the admin page are all true of a broken
server: with `handlers accessPolicy="Read, Script"` IIS skips `ISAPI-dll`
(`requireAccess="Execute"`) and serves the DLL as a file, and a check that decodes
that binary as text finds the word "password" inside the DLL's own string table.
Only a real `GetCACaps` distinguishes the two states, which is what the comparison
does:

| Reported | Meaning |
| --- | --- |
| `HTTP 200 with capabilities` | the ISAPI ran and answered SCEP |
| `mscep.dll served as a file` | IIS executed nothing: feature permissions or handler order |
| `HTTP 401` | `/CertSrv/mscep` needs anonymous authentication |
| `HTTP 404` | the request is not reaching the DLL at all |

### Which copy of the script ran?

Bundles and restores tend to be run from a share, and a stale copy reproduces the
previous release's behaviour, which looks exactly like a configuration bug. Every
run prints its own identity, and the same lines go to the log:

```
   Script      : NDESMigration.ps1 (179,301 bytes)
   Last write  : 2026-11-24 22:41:07
   SHA256      : 2C0A41E8F7B3D590
   Bundle schema this script writes: 3
```

If the behaviour does not match the script you think you are running, compare that
stamp first.

### The role-service list, and why the tile fix broke it

`Get-WindowsFeature` does not ask DISM for role services. It enumerates them from
Server Manager's component cache:

```
HKLM\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\<feature>
```

That cache is also what `Install-WindowsFeature -Name ...` validates against. So a
**missing cache entry makes an installed role service invisible and uninstallable at
the same time**:

```
PS> Get-WindowsFeature | Where-Object InstallState -eq 'Installed'
[X] Active Directory Certificate Services    AD-Certificate    Installed
                      <- ADCS-Device-Enrollment is simply not in the list

PS> Install-WindowsFeature -Name ADCS-Device-Enrollment
ArgumentNotValid: The role, role service, or feature name is not valid:
'ADCS-Device-Enrollment'. The name was not found.
```

DISM cannot help, and that is worth knowing before chasing it: on Server 2019 only
the **Foundation package** is enumerated, so AD CS role services never appear in
`dism /online /get-features` - not even on a server where NDES is installed and
working. Verified against the captured build (`312` features listed, `0` AD CS
rows, identical on the working and the broken server). `0x800f080c` from DISM for
`ADCS-Device-Enrollment` is therefore normal, not evidence of a missing payload.

The restore used to delete that cache entry to clear the Server Manager
post-deployment tile. Within the same process the feature list was already loaded
and looked fine, so the run reported success; every later session saw the role
service gone. The fix is to never delete it:

- `ConfigurationStatus = 2` under `Software\Microsoft\ADCS\NDES` is the only value
  that decides whether the tile shows. The restore writes it and then touches
  `LastModified_UTC` so Server Manager re-evaluates.
- If the entry is absent, the restore **recreates** it with the values the
  reference server held (captured from the T0 side of the diff), which restores the
  enumeration.
- `Install-NdesFeatures` decides from the machine, not the list: if the role
  service's payload is on disk (`mscep.dll`) or its cache entry says
  `InstallState = 1`, it is installed - so the restore repairs the cache entry
  instead of trying to install something that is already there.

```
  [warn] ADCS-Device-Enrollment is installed but not listed by Get-WindowsFeature
         (cache entry: missing, payload: present) - restoring the cache entry rather than reinstalling
  [ok]   Recreated the Server Manager cache entry for ADCS-Device-Enrollment
   Already installed, so not requested: ADCS-Device-Enrollment
```

If a required feature really is absent (`Active Directory Certificate Services` is
not installed at all), the restore installs the role first, then the role service,
and only then falls back to `DISM /Online /Cleanup-Image /RestoreHealth` - offered
as a prompt, because it is slow - before stopping.


### Testing enrolment

The restore's own checks stop at "the endpoints answer". `Test-NdesEnrollment.ps1`
goes further and performs a real SCEP enrolment, over HTTP and HTTPS, using only
code that already exists on the NDES server:

```powershell
# read-only: capabilities, published certificates, admin authentication
.\test\Test-NdesEnrollment.ps1 -Server ndes.contoso.com -SkipEnroll

# full enrolment on both bindings
.\test\Test-NdesEnrollment.ps1 -Server ndes.contoso.com

# HTTPS only, with a password you already have
.\test\Test-NdesEnrollment.ps1 -Server ndes.contoso.com -Protocol Https -ChallengePassword <otp>
```

There is no `sscep.exe`, no `openssl.exe` and nothing to copy across. The SCEP
message itself is built and parsed by `CertEnroll.dll` through
`IX509SCEPEnrollment` — the same client Windows MDM uses — so the protocol
encoding is Microsoft's, not a reimplementation. The script supplies the HTTP
transport, the challenge password and the reporting.

Per endpoint it reports:

| Step | What it proves |
| --- | --- |
| `GetCACaps` | `mscep.dll` answers on that binding, with its capability list |
| `GetCACert` | the CA chain and both RA certificates are published, and the CA is self-issued |
| admin auth | `mscep_admin` refuses anonymous callers |
| `PKIOperation` | a real enrolment: request built, submitted, response parsed |

Points worth knowing:

- A real enrolment **consumes one challenge password per protocol**, because a
  single-password NDES issues a one-time value. Use `-ChallengePassword` to reuse
  a password you already have, and `-SkipEnroll` to avoid consuming any.
- **Authentication.** `/certsrv/mscep` must answer **anonymously** - SCEP devices
  have no domain account - while `/certsrv/mscep_admin` must require Windows
  authentication. Both come from the bundle (schema 3 records them from the
  source's `applicationHost.config`). If an endpoint still answers 401, supply
  `-Credential`, or `-UseDefaultCredentials` when running on the server itself; if
  neither is given, the first 401 triggers a single `Get-Credential` prompt and
  the credential is reused for the rest of the run (both protocols, plus
  `mscep_admin`). `-NoPrompt` suppresses that for unattended runs.
- The CA is identified to the SCEP client by the **MD5 digest of its DER
  encoding**, hex-encoded — not the SHA-1 thumbprint Windows shows in the UI.
  CertEnroll then locates that CA inside the `GetCACert` blob, which is why the
  blob is passed through verbatim.
- `GetCACert` must include the RA signing certificate (Certificate Request Agent
  EKU). The script says so explicitly if it is missing; that is the same
  permission failure `0x80094012` described earlier, caught before any request
  is made.
- The test request, key and certificate are **kept** by default, so the result can
  be inspected: the run reports the store location, the thumbprint and the exact
  `Remove-Item`/`certutil -delkey` commands to undo it. `-Cleanup` removes them at
  the end instead, and `-OutFile` writes the issued certificate to a file.
- Each endpoint gets its own subject (`CN=NDES-EnrollmentTest-<8 hex>`). The name
  is checked against the certificate store and against names already used in the
  run, so HTTP and HTTPS never install certificates that are indistinguishable -
  which would also make cleanup by subject remove both.
- The password page also prints the CA certificate hash. The script identifies
  that certificate and reports its subject, its friendly name (looked up in
  `Cert:\LocalMachine\*` and `Cert:\CurrentUser\*`) and where a local copy lives,
  so the value on the page can be matched to something openable in `certlm.msc`:

  ```
  CA thumbprint: <32 hex digits, grouped in 8s>
             subject      : CN=contoso-Root-CA, DC=contoso, DC=com  (Cert:\LocalMachine\Root)
             friendly name: "contoso Root CA"
             local copy   : Cert:\LocalMachine\Root\<thumbprint of the same certificate>
  ```

  The hash is the MD5 of the CA certificate - the same value the SCEP client sends
  as the CA identifier - so a match also proves that NDES and the chain it
  publishes agree. A hash that appears in neither the published chain nor a local
  store is reported as such rather than guessed at.
- `-AllowUntrustedTls` works on both PowerShell 5.1 and 7. On 7 it is needed
  because .NET Core no longer consults `ServicePointManager`'s certificate
  callback.
- Over HTTP the script warns: the SCEP message is unencrypted, and
  `mscep_admin` credentials cannot be protected by Kerberos on a cleartext
  binding.
- The challenge password comes back **in the page body**: `mscep.dll` renders
  `IDR_HTML_NETWORK.HTML` and the password is a hex token, 16 characters at the
  default `PasswordLength`. There is no form to submit - the authenticated GET
  *is* the password page:

  ```
  The thumbprint (hash value) for the CA certificate is:  <32 hex digits, grouped in 8s>
  The enrollment challenge password is:                  <16 hex digits>
  This password can be used only once and will expire within 60 minutes.
  ```

  So the parser looks in form controls, then next to a "password" label (the gap
  may contain whole words - "password is:" - but never digits), then for a bare
  16-character hex token anywhere in the document, attributes included. It stops
  there deliberately: the 32-character hex run on the same page is the CA
  thumbprint, and returning that as the password would turn "not found" into a
  puzzling rejection. When nothing matches it prints the flattened page text, and
  `-SaveAdminPage <path>` keeps the raw response.

### Server Manager state, IIS handler order and feature permissions

A restore is judged by whether the result looks like a server that was built, not
just whether SCEP answers. Three things are normalised after the configuration is
written:

**The AD CS post-deployment tile.** Server Manager decides whether AD CS still
needs post-deployment configuration by reading the role service's
`ConfigurationKeyPath` from its component cache
(`HKLM\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache`).
For NDES that path is `Software\Microsoft\ADCS\NDES`, and the only value behind
that decision is:

```
HKLM\SOFTWARE\Microsoft\ADCS\NDES\ConfigurationStatus = 2
```

That comes straight out of the T0→T1 capture diff: across the whole
`HKLM\SOFTWARE` hive, the NDES install and its configuration produced exactly one
AD CS value, and the restore writes it. The cache entry is written when the
*feature* is installed - before NDES is configured - so the tile could otherwise
survive a completed configuration. The restore therefore reports the value Server
Manager will read and touches `LastModified_UTC` so Server Manager re-evaluates.

It deliberately does **not** clear the cache entry: `Get-WindowsFeature` enumerates
role services from that cache, so deleting it makes `ADCS-Device-Enrollment`
disappear from the feature list for good - see
[The role-service list](#the-role-service-list-and-why-the-tile-fix-broke-it).

**IIS handler order.** IIS resolves a request with the first handler that matches
it, which makes this order load-bearing in two directions:

```
... ISAPI-dll ...                <- executes *.dll, i.e. mscep.dll
    StaticFile                   <- must be BELOW it
    ExtensionlessUrlHandler-*    <- must be BELOW StaticFile
```

Get it wrong upwards and IIS serves `mscep.dll` as a file instead of running the
ISAPI: every SCEP request returns the DLL, browsers offer to save it as a
download, and nothing answers SCEP at all. Get it wrong downwards and an
extensionless request is routed into ASP.NET before the static handler sees it.
Which of the two the installer happens to produce depends on the order the IIS
features were installed in, so it is normalised rather than left to chance:

```
== Normalising IIS handler order
  [ok]   moved StaticFile immediately above the ExtensionlessUrlHandler- handler(s)
```

The step is idempotent (a second run reports that it is already correct), keeps a
timestamped copy of `applicationHost.config` next to the log, and restores that
copy if IIS rejects the rewritten file. It also treats `ISAPI-dll` as a floor: a
`StaticFile` that a manual edit dragged above it is moved back below, which is
what repairs the "everything downloads mscep.dll" state.

**Per-application feature permissions.** Handler order alone is not enough, and
this is the trap: IIS skips any handler whose required access type the current
`handlers` section does not allow. `ISAPI-dll` has `requireAccess="Execute"` and
the inherited `handlers` section allows only `Read, Script`, so **no ordering
repairs a missing `Execute` permission** - `mscep.dll` is still served as a file.
The built server has a `<location>` block per application that sets it, and the
restore now writes the same settings with `appcmd`:

| Setting | `/CertSrv/mscep` | `/CertSrv/mscep_admin` | Why |
| --- | --- | --- | --- |
| `handlers accessPolicy` | `Read, Execute` | `Read, Execute` | without `Execute` the ISAPI is skipped and the DLL is downloaded |
| `anonymousAuthentication` | **on** | **off** | devices have no domain account; the admin page needs one |
| `windowsAuthentication` | on | on | the admin page authenticates the administrator |
| `requestFiltering allowDoubleEscaping` | on | on | SCEP query strings carry percent-encoded base64 |
| `requestLimits maxQueryString` | 65536 | 65536 | long SCEP messages |
| `defaultDocument` | `mscep.dll` | `mscep.dll` | the ISAPI dispatches on the URL path |

Those values are read back from `applicationHost.config` after being written and
reported, because `appcmd` returns success for a section it did not change:

```
== Configuring SCEP application IIS settings
  [ok]   /CertSrv/mscep: anonymous=true windows=true accessPolicy=Read, Execute allowDoubleEscaping=true
  [ok]   /CertSrv/mscep: accessPolicy=Read, Execute, allowDoubleEscaping=True, default document=mscep.dll
```

The comparison that found this is worth repeating: a T1→T1 diff of
`applicationHost.config` between a hand-built server and a restored one shows the
handler list identical and *only* these per-application values missing. The IIS
comparer cannot see it, because it reports `applicationHost.config` as a single
file hash.

### The registry targets

NDES depends on three registry locations. All three are captured, and the bundle
records each value's relative path and type:

| Key | Captured as | Why |
| --- | --- | --- |
| `HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP` | whole tree | the service configuration, including its nested subkeys |
| `HKLM\SOFTWARE\Microsoft\ADCS\NDES` | whole tree | `ConfigurationStatus = 2` marks setup as complete; without it the ISAPI refuses to run |
| `HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters` | `MaxFieldLength`, `MaxRequestBytes` only | SCEP requests exceed the http.sys defaults |

`HTTP\Parameters` is captured **by value name, not as a tree**. The same key also
holds `SslBindingInfo` (the old certificate's hash, bound to the old host) and
`UrlAclInfo` — machine-specific state that must never be copied to another server.
`SslBindingInfo` is recreated on the target by `netsh http add sslcert`.

These two limits are read by `http.sys` when it starts, and `iisreset` does not
restart `http.sys`. The restore writes them before restarting IIS and then warns
you to **reboot before testing large SCEP requests**.

### The nested MSCEP layout — worth knowing

NDES does not store its configuration as flat values:

```
HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP
    SignatureTemplate              = "NDESUser"        (root value)
\CAInfo\Configuration              = "CA\CAName"
\CAType\CAType                     = 1
\CertsInMYStore\CertsInMYStore     = 1
\EnforcePassword\EnforcePassword   = 1
\PasswordVDir\PasswordVDir         = "CertSrv/mscep_admin"
\UseSinglePassword\UseSinglePassword = 0
```

That is why `Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP` shows
almost nothing — the settings live in subkeys. The bundle records each value's
relative path and the restore recreates the subkeys.

### When mscep_admin says "insufficient permission"

```
You do not have sufficient permission to enroll with SCEP.
Please contact your system administrator.
```

That sentence is nobody's permission check. `mscep.dll` imports `certcli.dll` and
`certca.dll` and **no** token or ACL function at all — no `CheckTokenMembership`, no
`AccessCheck` — so it never evaluates who called it. What it does is call the CA to
register the one-time password, and **any** failure of that call renders this page:

- it appears for a local administrator, and for the service account;
- nothing is written to the Application log (the CA round trip fails before NDES
  logs an event, which is why `Get-WinEvent -ProviderName MSCEP` is empty);
- `GetCACaps` and `GetCACert` keep working, so the SCEP side looks healthy.

The CA call is DCOM, so "port 135 is open" proves nothing — the dynamic port range
matters too. `certutil -ping` makes the same round trip, and the restore now runs it
twice, as the current session and in the service account's own logon session:

```
[ok]   CA endpoint mapper reachable: ca.contoso.com:135
[ok]   CA call as this session: certutil -ping succeeded
[warn] CA call as CONTOSO\svc_ndes FAILED: The RPC server is unavailable. 0x800706ba
```

Read it as a table: both succeed → the failure is inside NDES's own request, so look
at `C:\Windows\System32\CertLog` on the CA. Only one succeeds → that identity cannot
reach or use the CA. Neither succeeds → the NDES server cannot do DCOM to the CA at
all (RPC dynamic ports, or the CA's firewall), and no amount of restoring will fix
it.

Two things that look like this page but are not:

| Symptom | What it is |
| --- | --- |
| `HTTP 200`, body is a Windows executable | IIS served `mscep.dll` instead of running it — handler permissions, not the CA |
| `HTTP 401` for one credential, 200 for another | IIS authentication, decided before the ISAPI runs |

---

## Reading the output

Each run writes to `<Root>\<Host>\`:

| File | Contents |
| --- | --- |
| `report-<label>\report.md` | triaged report - start here |
| `report-<label>\high-signal.csv` | only the changes matching the NDES patterns |
| `report-<label>\changes.csv` | every change, all areas |
| `T1-<label>\registry\*.reg` | raw exports - **these are also the restore source** |
| `T1-<label>\iis\applicationHost.config` | IIS config as installed |
| `T1-<label>\ad\changed-objects.csv` | every AD object touched |
| `T1-<label>\ad\ds-change-events-5136.csv` | attributed AD writes (if auditing was on) |
| `T1-<label>\files\changed-usn.csv` | every path touched on the volume |
| `T1-<label>\files\file-access-4663.csv` | file changes attributed to an account (if `-FileAuditing`) |

Changes are classified `High` / `Review` / `Noise` by the regex lists in
[config/capture-settings.psd1](./capture/config/capture-settings.psd1). Noise is hidden
from the report by default; `-IncludeNoise` brings it back.

The report includes a **"Changed files"** section listing every changed path as
a full, untruncated location (one per line, in a code block, so it is easy to
copy). Paths from the USN journal are normalised to include the drive letter -
`fsutil` reports them volume-relative (`\Windows\...`).

The report also prints an **"MSCEP configuration as installed"** table - the
final values of `HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP`. That table is the
direct input for the restore script.

---

## What to look for

1. **`ad\ds-change-events-5136.csv`, grouped by `SubjectUserName`.** This tells
   you which account performed the AD writes, and therefore which rights the
   install genuinely requires. Cross-check against
   `ad\changed-objects.csv` for the full list of touched objects.
2. **`high-signal.csv` in the Registry area.** `MSCEP`, `Services\SCEP`,
   `Services\CertSvc` and `Microsoft\ADCS` hold the configuration that a rebuild
   must reproduce.
3. **The Features area.** That diff is the literal `Install-WindowsFeature`
   list for the rebuild script.
4. **`files\changed-usn.csv` filtered to `certsrv` and `ProgramData\Microsoft\Crypto`.**
   Distinguishes files NDES *needs* (dlls, templates) from per-machine crypto
   containers that must be re-created rather than copied.

Then prove the minimal-rights hypothesis: rebuild an NDES server with only
local admin plus CA *Issue and Manage Certificates* and enroll rights on the two
RA templates, and see what fails. That failure list is the remaining gap.

---

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `USN journal unavailable` | Not elevated. Re-run elevated, or accept inventory mode. |
| `no 5136 events available` | Auditing not applied, or the SACL ACE was not inherited. Re-run `-Apply`, then `-Status` on the NC root. |
| `ldifde export failed` | Not on a DC, or the account cannot read the whole NC. |
| Report shows no AD section | Host is not a DC - expected on the CA and NDES boxes. |
| `ad-audit` skipped | Same as "no 5136 events" - LDIF diff still works without it. |
| Capture is slow | Inventory mode over `C:\ProgramData` is the cost. Elevate to get USN mode instead. |

## Caveats

- The USN journal read starts from the recorded cursor, but if the journal wraps
  (`maxsize`) mid-window the earliest records are lost. If
  `changed-usn.csv` looks thin, re-run the compare with inventory mode on a
  second pass.
- 5136 does not record the *old* value - only the value written. The LDIF diff
  supplies the old side; the two are meant to be read together.
- `ldifde` exports exclude operational attributes by default, so a bare
  replication-only change may appear in `changed-objects.csv` without a matching
  attribute diff. That is not a miss, it is a timestamp touch.
