# Host Security Solutions

## Antivirus, WinDefender and Host-based Firewall

```
Get-Service WinDefend
Get-MpComputerStatus | select RealTimeProtectionEnabled
Get-NetFirewallProfile | Format-Table Name, Enabled
Get-NetFirewallRule | select DisplayName, Enabled, Description
Get-MpThreat
```
## Security Event Logging and Monitoring

```
Get-EventLog -List
Get-Process | Where-Object {$_.ProcessName -eq "Sysmon"}
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*
```
