---
title: Nmap Cheatsheet
published: 2025-08-16
description: In this Post you'll learn everything you need to know about enumeration using Nmap with a broad cheatsheet
image: 'https://assets.tryhackme.com/img/modules/nmap.png'
tags: [Cheatsheet, Nmap, Commands, Linux, Tools]
category: Cheatsheet
draft: false
---

# Nmap

## Multiple Target

### Host Discovery

```bash
# Initial Host Discovery
nmap -sn <IP>/24 -oG hosts.gnmap

# Export hosts into a hostlist 
grep "Up" hosts.gnmap | awk '{print $2}' > hosts.txt
```

### Port Scan

```bash
# Port scan
nmap -sS -p- --open -Pn -n --min-rate 5000 -iL hosts.txt -oN ports.txt

# Parse ports to a -p<ports> format
grep '^[0-9]' ports.txt | cut -d '/' -f1 | sort -u | xargs | tr '' ','

# Service and Version and NSE Detection Scan
nmap -sCV --open -Pn -p<ports> -iL hosts.txt -oN scan.txt
```

## Single Target scan

### TCP Port Scan

```bash
nmap -p- --open -Pn -n --min-rate 5000 -sS <IP> -oN ports
```

### Parse open ports

```bash
# Add this function to .bashrc or .zshrc (Credits to S4vitar)
extractPorts () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')" 
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)" 
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
	batcat extractPorts.tmp
	rm extractPorts.tmp
}

# Then do
extractPorts <ports file>
```

### Service/Version scan on open ports

```bash
nmap -p<ports> -sCV -Pn <IP>
```

## Firewall Evasion

```bash
sudo nmap -sCV -sS -Pn -n -p- <IP> --disable-arp-ping --source-port 53 -D RND:2
```
