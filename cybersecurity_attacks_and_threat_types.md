# Most Common Cybersecutiy attacks techniques and methods used by attackers
## 1.Initial Access
👉 Initial Access refers to the first step an attacker uses to enter a system, network, or application. It is how they gain their “foothold” before performing additional actions (lateral movement, privilege escalation, malware deployment).

**Common Methods:** <br>
- Phishing emails (malicious attachments or links)
- Exploiting public-facing applications
- Using stolen credentials
- Compromised VPN accounts
- Drive-by downloads

**Real-World Example:** <br>
ℹ️ Colonial Pipeline Attack (2021):Attackers gained initial access using a single compromised VPN password to enter the pipeline operator’s network.

## 2.Lateral Movement
👉 After an attacker enters an environment(after initial access), they move deeper into the network(try to persists or reside into System) to reach valuable systems (e.g., domain controllers, databases to get higher level privilege escalations). This is called lateral movement.

**Common Techniques:** <br>
- Using stolen credentials
- Remote desktop (RDP) hopping
- Pass-the-Hash / Pass-the-Ticket
- Exploiting system vulnerabilities
- Using administrative tools (PowerShell, WMI)

**Real-World Example:** <br>
ℹ️ NotPetya (2017):After gaining initial access, the malware used legitimate Windows admin tools and the EternalBlue exploit to move laterally at high speed.

## 3.Remote Code Execution (RCE)
👉 RCE is a vulnerability that allows an attacker to run arbitrary code on a target machine—usually without authentication. This is one of the most dangerous vulnerability types.

**Causes:** <br>
- Unsafe input handling
- Buffer overflows
- Deserialization flaws
- Logic errors

**Real-World Example:** <br>
ℹ️ Log4Shell (CVE-2021-44228): A critical RCE flaw in the Log4j library allowed attackers to execute code simply by making an application log a specially crafted string.

## 4.SQL Injection (SQLi)
👉 SQL Injection occurs when an application allows untrusted user input to be sent directly to a database query. Attackers insert malicious SQL statements to read, modify, or delete data.

**What attackers can do:** <br>
- Bypass logins
- Dump entire databases
- Alter, delete, or inject data
- Execute OS-level commands (with certain DB engines)

**Real-World Example:** <br>
ℹ️ Heartland Payment Systems Breach (2008): Attackers used SQL injection to compromise payment processing systems, ultimately exposing ~130 million credit card numbers.

## 5.Cross-Site Scripting (XSS)
👉 XSS vulnerabilities allow attackers to inject malicious scripts (usually JavaScript) into webpages viewed by other users.

**Types of XSS:** <br>
- Reflected
- Stored (most dangerous)
- DOM-based

**What attackers can do with XSS:** <br>
- Steal session cookies
- Impersonate users
- Modify webpage content
- Deliver malware

**Real-World Example:** <br>
ℹ️ Worm on MySpace (2005) “Samy Worm”: A stored XSS vulnerability allowed a self-propagating worm to infect over 1 million MySpace profiles in less than 24 hours.

## 6.Server-Side Request Forgery (SSRF)
👉 SSRF occurs when attackers trick a server into making internal or external requests on their behalf. It lets attackers reach systems that are not directly exposed to the internet.

**Why SSRF is dangerous:** <br>
- Access internal APIs
- Read cloud metadata endpoints
- Bypass firewalls
- Pivot into internal networks

**Real-World Example:** <br>
ℹ️ Capital One Breach (2019): An SSRF vulnerability in AWS metadata services enabled an attacker to access credentials and extract highly sensitive data of more than 100 million users.

## 7.Cross-Site Request Forgery (CSRF)
👉 CSRF tricks an authenticated user’s browser into performing actions they did not intend—like changing passwords, making purchases, or transferring funds.

**How it works:** <br>
- Victim is logged into a site (e.g., banking portal).
- Attacker sends a malicious link or auto-submitting form.
- The browser sends a legitimate request (with the victim’s cookies).

**Real-World Example:** <br>
ℹ️ Gmail CSRF Vulnerability (2007): A flaw allowed attackers to change users’ Gmail forwarding settings via CSRF, silently redirecting emails to attacker-controlled addresses.

## 8.Web Shells
👉 A web shell is a malicious script uploaded to a web server that gives attackers remote access, allowing them to run commands, browse files, upload malware, or pivot deeper into the network.

**Common forms:** <br>
- PHP web shells (e.g., c99.php, r57.php)
- ASPX backdoors
- Simple command runners (shell.jsp)

**Capabilities:** <br>
- Execute system commands
- Upload/download files
- Create new users
- Establish persistent access

**Real-World Example:** <br>
ℹ️ Microsoft Exchange Hafnium Attacks (2021): Attackers exploited Exchange zero-day vulnerabilities and deployed web shells on thousands of servers worldwide to maintain persistent remote access.

## 9.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Hardware-level Cyber attacks
## Rowhammer
## Meltdown and Spectre

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Software-level Cyber attacks
## Buffer Overflows
## Non-Validated inputs
## Race Condition
## SYNful Knock vulnerability discovered in Cisco Internetwork Operating System (IOS) in 2015.


-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Replay attacks
## Zero-day vulnerability or exploits
## ARP Posioning
## DNS Poisoning
## IP Spoofing
## MAC Spoofing
## Web Shell
## Zero-day Vulnerabilities
## Phishing & its types(Smishing, Vishing, Whaling, Spear phishing)
## Social Engineering
## Malware and its types
## MITM (Man-in-the-Middle-Attacks)
## DNS poisoning ARP poisoning MAC spoofing Ip spoofing DHCP spoofing
## Typo squatting
## KRACKS (Key reinstallation attacks)
## DOS & DDoS
## Cryptojacking
## Clickjacking
## Buffer overflows
## SQL injections
## Rowhammer
## Meltdown & spectre
## Eternalblue
## Ransomware
## Remote Code Executions
## Web Shell
## XSS , CSRF, SSRF
## C&C(C2) server attacks
## Wi-Fi based attacks
## Log4j
## Dumpster Diving
## Shoulder Surfing
## Spoofing
## Sniffing
## CEO fraud, President Fraud
## SMB
## Meltdown 2017, Side Channel Attack, meltdown and spectre
## Rowhammer
## SIM Swapping

