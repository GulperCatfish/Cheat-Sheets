# Host Security Solutions

```
Get-Service WinDefend
Get-MpComputerStatus | select RealTimeProtectionEnabled
Get-NetFirewallProfile | Format-Table Name, Enabled
Get-NetFirewallRule | select DisplayName, Enabled, Description
```
