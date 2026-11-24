# Lab topology

Working notes from the lab where this kit was developed. Hostnames, addresses and
account names have been replaced with placeholders; the topology and the reasoning
are unchanged.

---
dc.contoso.com - 10.0.0.10
ca.contoso.com - 10.0.0.11
ndes.contoso.com - 10.0.0.12

Accounts
ea - Enterprise Admin
da - Domain Admin
svc_ca - CA service account
svc_ndes - NDES service account
svc_ndes_conn - NDES connector account
user - User account
admin - Administrator account

Password
Same for all

Current state:
-Reconfigure CA to be Enterprise
-Configure subCA
-Run group policy on ndes and ndes2

Group policy
---
$dn = (Get-ADDomain).DistinguishedName

New-ADGroup -Name 'GG-Server-Admins' -GroupScope Global -GroupCategory Security `
            -Path "CN=Users,$dn" `
            -Description 'Local administrators on member servers' -Verbose

Add-ADGroupMember -Identity 'GG-Server-Admins' -Members 'admin'
---

On each server
---
Add-LocalGroupMember -Group 'Administrators' -Member 'CONTOSO\GG-Server-Admins'
---
