# Active Directory Enum

## Basic LDAP Queries with PowerShell

```
systeminfo | findstr Domain
Get-ADUser -Filter * -SearchBase "CN=...,OU=...,DC=...,DC=..."
Get-ADGroup -Filter * | Select-Object Name
Get-ADUser -Identity "username" -Property MemberOf | Select-Object -ExpandProperty MemberOf
Get-ADGroupMember -Identity "GroupName"
Get-ADComputer -Filter * -Property Name, OperatingSystem | Select-Object Name, OperatingSystem
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
```
## SPNs and Kerberoasting

```
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Property ServicePrincipalName | Select-Object Name, ServicePrincipalName
```
## Domain Trusts

```
Get-ADTrust -Filter *
```
## GPO Enumeration

```
Get-GPO -All | Select-Object DisplayName, GpoStatus
Get-GPResultantSetOfPolicy -Computer "ComputerName" -ReportType Html -Path "C:\Path\to\report.html"
```
## Domain Policies

```
Get-ADDefaultDomainPasswordPolicy
```
## DNS Enumeration
```
Resolve-DnsName -Name "domain.local" -Type ALL
```
## Enumerate Admin Privileges
```
Get-ADGroupMember -Identity "Domain Admins"
```
## Credential Delegation / Trust Relationships
```
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Property TrustedForDelegation | Select-Object Name
```
