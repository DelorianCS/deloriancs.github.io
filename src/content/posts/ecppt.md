---
title: eCPPT - Review
published: 06-09-2025
description: Here I share my overall opinion on the eCPPTv3 Certification by INE, some Tips & Tricks and some machines & material to actually prepare for the certification 
image: 'https://www.approach-cyber.com/wp-content/uploads/2025/01/30.webp'
tags: [Active Directory, INE, eCPPT,]
category: Certification
draft: false
---

## eCPPTv3 Review

**January 2025 • by DelorianCS**

My hands-on experience with *INE's *Certified Professional Penetration Tester* `eCPPTv3`: what the training covers and misses (yeah, it misses a lot), how the exam feels, and practical tips to pass on your first go.


## My Background
I was pretty much a beginner; my only cert was `eJPTv2`. I prepared mostly with **HTB Academy** and retired labs focused on *Active Directory* and basic *web pentesting*. I also had a bit of *TryHackMe* for the fundamentals.

## The Training
The official *INE* content helps, but it's not fully aligned with the exam's path. Combine it with hands-on *Active Directory*, *password attacks*, and a few web labs to close the gaps.

### What to Skip on the Training
- *Client-Side Attacks* (rarely relevant for the attempt)
- *Intro x86/BOF* (great skills, low direct payoff here)
- *Full C2 sections* (nice to know; not strictly required)

**These are still valuable—circle back post-exam.**

## What to Add (to actually pass)

### Active Directory
- **HTB Academy**: Intro to AD; AD Enumeration & Attacks (I'll be sharing this later on)
- **Impacket fluency** (`secretsdump`, `wmiexec`, `GetUserSPNs`, etc.)
- **PowerView** basics & common AD misconfigs

### Web App
- Practice *WordPress* + common vulns (auth bypass, `LFI/RFI`, `SSRF`, `upload bypass`)
- Even though this may not probably be in you're exam, it's still good to know them
- Web portion is lighter—don't over-index on it

## Preparation
If you just passed `eJPTv2`, 20–40 days of focused practice is enough. Do the Machines & Modules listed here, take notes, and you'll be in great shape.

## The Exam
The exam runs in-browser via `Guacamole`, which can feel a bit odd if you're used to your own **VM**. Some tools live in containers and may have different names (e.g. `evil-winrm`). You get 24 hours—plenty to finish if you plan well.

## Personal Opinion
Personally I found this exam not rewarding at all as it's mostly done by *brute-forcing* **EVERYTHING**, if you're planning to buy this certification please don't, there are way better *Active Directory* broad certifications like `CRTP` 

## Exam Flaws / Caveats
1. Lab instability (dynamic flags sometimes missing until reset)
2. Provided cracking lists may mislead—bring your staples
3. Some tools not on the jump box—have backups ready
4. Expect some brute-forcing; AD is there but not the only path
5. Occasional misworded tasks (e.g., a user that doesn't exist)

## Tips
- Take meticulous notes—hosts, creds, footholds, privesc ideas
- Use only: `xato-net-10k`, `seasons`, `months`, `rockyou`
- Paste all questions into your notes (Obsidian is great)
- If stuck, brute-force the "low-hanging fruit" angles
- Don't forget to have fun (trust me)

---

## Machines & Modules by HackTheBox

### Linux Boxes
```
1. CozyHosting
2. Keeper
3. Jerry
4. Love
5. Trick
6. Spectra
7. Backdoor
8. Blocky
```
### AD Boxes
```
1. Active
2. Forest
3. Sauna
4. Monteverde
5. Cascade
6. Cicada
7. Resolute
```
### HTB Academy Modules
- [Login Brute Forcing](https://academy.hackthebox.com/module/details/57)
- [Attacking Common Applications](https://academy.hackthebox.com/module/details/113)
- [Intro to Active Directory](https://academy.hackthebox.com/module/details/74)
- [Active Directory Enumeration & Attacks](https://academy.hackthebox.com/module/details/143)
- [Hacking WordPress](https://academy.hackthebox.com/module/details/17)

### Quick Facts
- **Style**: Brute-Force is a must, AD-heavy
- **Time**: one-day exam window
- **Focus**: enumeration → chaining → privesc

---