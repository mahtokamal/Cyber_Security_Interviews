# Terminology in Cyber Security

## Threat Vector
Threat Vector or attack vectors are the methods, process or mechanisms used by Cyber criminal to do cyber attack that enables them to gain unauthorized access, compromised the computer system and network access, exploit the vulnerabilities. Threat Vector can be Active or Passive.

![ChatGPT Image Jun 24, 2025, 10_29_01 PM](https://github.com/user-attachments/assets/111eb489-d0ba-4a6f-b533-b71f810a31ee)

- Passive attack - Eavesdropping or monitoring the data flow from or into the systems, the goal is to obatin as much as information during transimission without any alteration, modification or destroying the system. Examples - Phishing, Network Sniffing, Traffic Analysis.
- Active attack - In active attack, the attacker will directly interfere with the target to damage or gain unauthorized access to computer systems and networks. Examples-DDoS(Distributed Denial of Services) attack, Masquerading, Modification of Messages, Replay Attacks, Repudiation, Man-in the middle attacks.
- Threat Vector vs Attack Surface - An attack vector is a method of gaining unauthorized access to a network or computer system.
An attack surface is the total number of attack vectors an attacker can use to manipulate a network or computer system or extract data.

![Screenshot (734)](https://github.com/user-attachments/assets/14bce9a8-e14b-4fc4-b7de-d983da5f0716)

**Threat vector can be used interchangeably with attack vector and generally describes the potential ways a hacker can gain access to data or other confidential information.**


## Vulnerability
Vulnerability is a loophole, weakness, flaw or other shortcomings presents in a System (infrastructure, database, hardware & software), however it can also exist in a process, a set of controls, or simply just the way that something has been implemented or deployed.

Different types of Vulnerabilities available, but it is divided on two categories:

Technical Vulnerabilities: Hardware, Software or bugs in code or errors. in 2022, according to Positive Technologies, 72% of vulnerabilities were related to flaws in web application code.
Human Vulnerabilities: such as employees falling for phishing, smishing or other common attacks. The goal of 85% of these attacks is data theft.
## Exploit
In Cybersecurity, a exploit is any tools or techniques or piece of codes that attacker use to take advantge of vulnerability. Often, an exploit is delivered via a piece of code built to target that vulnerability such as (remote exploits, local exploits(physical system access ) or zero-days exploits).
## Threat
In Cybersecurity, anything that could exploit a vulnerability, which could affect the confidentiality, integrity or availability of your systems, data, people, and more.

A more advanced definition of threat is when an adversary or attacker has the opportunity, capability and intent to bring a negative impact upon your operations, assets, workforce and/or customers. Examples of this can include malware, ransomware, phishing attacks and more — and the types of threats out there will continue to evolve.

For example, your organization may have no vulnerabilities to exploit due to a solid patch management program or strong network segmentation policies that prevent access to critical systems. However, in the real world, chances are extremely likely that you do have vulnerabilities, so let’s consider the risk factor.
## Risk
In general, Risk = Likelihood × Impact. Vulnerability and threat are the sources for a risks.
Risk is the probability of a negative (harmful) event occurring as well as the potential of scale of that harm. Your organizational risk fluctuates over time, sometimes even on a daily basis, due to both internal and external factors.

![Screenshot (456)](https://github.com/user-attachments/assets/a71df272-33ec-4e29-a96f-b4ad6adec98b)

In order for organizations to begin risk mitigation and risk management, you first need to understand your vulnerabilities and the threats to those vulnerabilities.

Real-world example
Your organization might be looking to protect all its data, likely through data encryption methods and other approaches. But this approach is incredibly expensive, so you must pare down which ones to protect the best.

You could think about the risk involved in this way: if the mechanism for protecting certain data fails in some way, you’ll have one or more vulnerabilities. And if there is a threat actor who finds and exploits this vulnerability, the threat is realized.

Here, your risk is how valuable it would be to lose that data to the threat actor.

NOTE: Risk comes with universal truth: you cannot eliminate or entirely protect against all threats, no matter how advanced your systems are.
## Vulnerability vs threat vs risk
These terms are frequently used together, but they do explain three separate components of cybersecurity. In short, we can see them as a spectrum:

First, a **vulnerability(weakness or flaw)** exposes your organization to threats.

A **threat(causes harm, damage or loss)** is a malicious or negative event that takes advantage of a vulnerability.

Finally, the **risk** is the potential for loss and damage when the threat does occur.

## Impact
It refers to the negative consequences that occur when a cyberattack or security incident successfully compromises the confidentiality, integrity, or availability of an organization's or individual's digital assets.

- Technical Impact: (Hardware system, software, servers)
- Business Impact: (losing trust of customer, reputational damage)
Consequences and types of the impact:

- Financial Impact
- Reputational Impact
- Operational Impact (System Downtime or unavailability of services)
## Governance
GRC stands for governance, risk (management), and compliance.

Governance is the set of policies, rules, or frameworks that a company uses to achieve its business goals. It defines the responsibilities of key stakeholders, such as the board of directors and senior management.
## Compliance
Compliance is the act of following rules, laws, standards and regulations realted to information security . It applies to legal and regulatory requirements set by industrial bodies and also for internal corporate policies. In GRC, compliance involves implementing procedures to ensure that business activities comply with the respective regulations. For example, healthcare organizations must comply with laws like HIPAA that protect patients' privacy.

GDPR(Genera Data Protection Regulations) (to maintain data confidentiality and privacy of individuals), is a European Union regulation on information privacy in the European Union and the European Economic Area.
## PII (Personal Identifiable Information)
PII are the data used to uniquely idenfifies an individuals.
For example: Name, Email, Address, Phone numbers, Date of Birth, Social Security numbers etc.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## SIEM (Splunk, ELK Stack)
## SOAR ()
## MISSP
## IDPS (Snort, Suricata)
## Firewall (Pfsense)
## EDR / XDR (Wazuh)
EDR (Endpoint Detection and Response) - EDR provides security solutions to monitor, detect and respond the endpoint devices such PCs, Workstations, Server or networking devices against potential threats, which are undetecable by traditional Anitvirus.

EDR available in the markets:
- CrowdStrike Falcon
- SentinelOne ActiveEDR
- Microsoft Defender for Endpoint
- OpenEDR
- Symantec EDR

3 main features of EDR:
- Visibility: it provides better graphical representation of ednpoints collected data such as process modifications, registry modifications, file and folder modifications, user actions, and much more. With good visibility, it helps security analyst to analyzed the data in well-structured format.
- Detection: it consists of both signature-based and behaviour-based detection such as unexpected user activities. with modern machine learning capabilities, it identifies any deviation from the baseline behavior(normal) and instantly flags it, can also detect fileless malware that presents in the memory.
- Response: It responds with full-fledged details such when, where and what happened.you may decide to isolate a complete endpoint, terminate a process, or quarantine some files with the help of EDT console

EDR vs Anti-virus:
Unlike antivirus software's basic signature-based detection, it monitors and records the behaviors of the endpoint. An EDR also provides organization-wide visibility of any activity. For example, if a suspicious file is detected on one endpoint, the EDR will also check it across all the other endpoints.

Scenario Breakdown
- Step #1: A user receives a phishing email with a Word document embedded with a malicious macro (VBA script)
- Step #2: The user downloads the document and opens it
- Step #3: The malicious macro is silently executed, and it spawns PowerShell
- Step #4: The malicious macro runs an obfuscated PowerShell command to download a sophisticated second-stage payload
- Step #5: The payload is injected into a legitimate svchost.exe
- Step #6: The attacker gains remote access to the system

<img width="1399" height="478" alt="Screenshot (839)" src="https://github.com/user-attachments/assets/31604504-9a2b-4d0d-a3a6-f8e63718507c" />
<img width="1833" height="937" alt="Screenshot (840)" src="https://github.com/user-attachments/assets/cfaaa86b-469f-4ffa-8b05-96bc2ddabe8a" />

How EDR works?
<img width="1541" height="585" alt="Screenshot (841)" src="https://github.com/user-attachments/assets/b21a3b2e-05cf-400d-8f81-dcc62147608e" />
- EDR Agents(Sensors): EDR agents are deployed inside the endpoints. They are the eyes and ears of the EDR. Their job is to sit and monitor all the activities happen at the endpoints and the detailed activities about the information are directly send to central EDR Console.
- EDR Console: All details data that are sent by EDR agents is correlated and analyzed with help of complex logic and Machine learning algorithm.The threat intelligence information is matched with the collected data. The EDR is just like the brain connecting all the dots. These dots connect to form a detection, often called an alert.The detections are happening here. Based on the available data, the analyst's job is first to use their expertise to determine if the alert is a false positive or a true positive. In case of a true positive, the analyst can take actions from within the EDR console. 

Detection happening:
When detection triggers, the responsibility of SOC analyst comes into the picture to prioritize and acknowledge the alerts based upon the severity levels of alert(Critical, High, Medium,Low, Informational)

**EDR Telemetry?** <br>
The data collected by EDR agents from endpoints and fed directly to EDR console are known as Telemetry data.elemetry is the black box of an endpoint with everything necessary for detection and investigation.

Collected Telemetry
Since many activities going on the endpoints, most of them are legitimate and it is difficult to distinguish between regualr and malicious activity. The more data are collected to make better judgement. EDR collects detailed telemetry from the endpoints.

- Process Executions and Terminations
- Network Connections
- Command Line Activity
- Files and Folders Modifications
- Registry Modifications

NOTE: Advanced threats keep most of their activities stealthy, using legitimate utilities during execution. Individually, their activities may seem harmless, but when observed through detailed telemetry, they tell a different story. This detailed telemetry not only helps the EDR detect advanced threats and make better judgments on the legitimacy of the activities, but it is also very helpful for the analysts during the investigations. The analysts can understand the full chain of events, identify the root cause, and reconstruct the attack timeline.

https://tryhackme.com/room/introductiontoedrs <br>

**Detection and Response Capabilites**
**Detection** <br>
- Behavioral Detection
- Anomaly Detection
- IOC matching
- MITRE ATT&CK Mapping
- Machine Learning Algorithms

**Response** <br>
- Isolate Host
- Terminate Process
- Quarantine
- Remote Access

**Atrefacts Collection** <br>
- Memory Dump
- Event Logs
- Specific Folder Contents
- Registry Hives


**XDR(Extended Detection and Response)**

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Phishing
Phising is a type of cyber attack, in which attacker sends malicious link through email, texts, or direct phone calls, that tricks people into sharing the sensitive data or information, as a result, people become a victim knowingly or unknowingly. Phishing attack (a type of social-engineering attack used to steal sensitive data, including login credentials and credit card numbers). Phishing is one of the most effective cybersecurity threat vectors; it has defeated even the most sophisticated cyber defense systems by preying on people’s weaknesses.
## pretexting, baiting, piggybacking, tailgating
## Vulnerability
## Exploit
## Threat
## Impact
## Risk
## Governance 
## Compliance
## Payload
In the field of Cybersecurity, a payload consists of a malicious code and designed to execute a specific forms of task or action on a target system. The code can be in any forms of malicious nature such as Virus, Worms, Trojans, Ransomware etc. and it exploits the system vulnearbilities or security flaws. When it is successfully executed and delivered, it can expose various cyber threats such as such as stealing sensitive information, disrupting system operations, or taking control of the target system.

In simple terms, a payload in the context of computing and networking refers to the actual data that is carried by a protocol or data packet, excluding the header or routing information.

## Threat Vector
## Threat Actor
## CIA Triads
- Confidentiality (C): Ensure data privacy and prevent unauthorized access.
- Integrity (I): Ensure (tampering-proof, without alteratin of data)data isn't altered.
- Availability (A): Ensure services/data are accessible when needed.

## Victim
## Adversary
## TTPs (Tactics, Techniques and Procedure)
MITRE ATT&CK(Adversarial Tactics, Techniques, and Common Knowledge) framework, is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. It helps to map and understand attacker behaviors during the kill chain.

It is a guideline for classifying and describing cyberattacks and intrusions. It was created by the Mitre Corporation and released in 2013 and used for threat modeling and profiling.
The framework is an alternative to the cyber kill chain developed by Lockheed Martin.

|Tactics|Techniques|
|----|---|
|Reconnaissance|Active Scanning, Phishing for information|
## APT (Advanced Persistent Threat)
## VPN vs Proxy vs Reverse  Proxy
**1. VPN** <br>
   <img width="1024" height="739" alt="image-25" src="https://github.com/user-attachments/assets/8e20a41c-3310-4dd6-862a-46bd91cb8c23" />

🌍 1. What is a VPN (Virtual Private Network)? <br>
➤ A VPN is a secure, encrypted connection (a “tunnel”) between your device and another network over the Internet.
It hides your IP address, encrypts your data, and helps you browse safely and privately — especially on public or untrusted networks.<br>

➤ Simplified: A VPN makes your internet connection private and secure, even when using a public Wi-Fi. <br>

💡 Real-World Analogy:<br>
Imagine you’re sending a confidential letter (your internet data):<br>
- Without a VPN: You put it in a clear envelope — anyone (hackers, ISPs, government) can read it.
- With a VPN: You place it in a locked, opaque box and send it through a private courier — only the receiver can open it.

🔐 2. How a VPN Works (Step-by-Step) <br>
👉 You connect to the Internet through a VPN client (app on your phone, PC, or router).<br>
👉 The VPN app encrypts your data before it leaves your device.<br>
👉 The encrypted data goes through a secure tunnel to a VPN server located somewhere else (e.g., another country).<br>
👉 The VPN server decrypts the data and sends it to the final website (like Google or Netflix).<br>
👉 To the website, it appears that the request came from the VPN server’s IP, not yours.<br>

🧠 Example:<br>
If you are in India and connect to a VPN server in the US,<br>
- The website will think you’re browsing from the US.
- Your real IP (India) stays hidden.
- Your data is encrypted so your ISP or hackers can’t read it.

🧩Types of VPN<br>
|Type|Description|Use Case|
|---|---|---|
|Remote Access VPN|Allows individual users to securely connect to a private network remotely.|Employees working from home connecting to office network.|
|Site-to-Site VPN|Connects entire networks (e.g., two company branches).|Company A’s New York office connects securely to its London office.|
|Client-Based VPN|Installed software/app on a single device for encrypted browsing.|NordVPN, ExpressVPN, Surfshark, etc.|
|Router-Based VPN|Configured on routers, protects all devices connected to that router.|Home or small business networks.|
|Mobile VPN|Optimized for mobile networks with changing IPs and signals.|Secure mobile banking or email apps.|

⚙️ VPN Protocols (How VPNs Secure Data) <br>
A VPN protocol defines how data is encrypted and transmitted between your device and the VPN server. <br>

|Protocol|Description|Speed|Security|Typical Use|
|---|---|---|---|---|
|PPTP (Point-to-Point Tunneling Protocol)|Oldest VPN protocol; fast but weak security.|⚡Fast|	❌ Weak|	Streaming, legacy systems|
|L2TP/IPsec (Layer 2 Tunneling + IPsec)|Stronger encryption, adds IPsec security layer.|⚡ Moderate|	✅ Strong|General secure browsing|
|OpenVPN|Open-source and widely trusted; balances speed and security.|⚡ Moderate	|✅✅ Very Strong|Most commercial VPNs|
|IKEv2/IPsec|Very stable on mobile devices; reconnects quickly.|⚡⚡ Fast	|✅ Strong|Mobile VPNs|
|WireGuard|Newer protocol — faster, simpler, and very secure.|⚡⚡⚡ Very Fast|	✅✅ Very Strong|Modern VPN apps|
|SSTP (Secure Socket Tunneling Protocol)|	Uses SSL (HTTPS) port; works well behind firewalls.|⚡ Moderate|✅ Strong|Corporate VPNs (Windows)|

🧠 5. How VPNs Are Used in Daily Life<br>
|Real-World Application|Description|Example|
|--|--|--|
|Privacy & Anonymity|	Hide your IP address and browsing history from ISPs or websites.|	Avoid being tracked online.|
|Public Wi-Fi Security|	Protect your data on public networks (airports, cafes).|	Safe online banking in a coffee shop.|
|Bypassing Geo-Restrictions|Access content blocked in your country.|	Watch Netflix US while in India.|
|Corporate Access|Employees securely access company files remotely.|	Work-from-home secure login to office servers.|
|Data Encryption|	Encrypt data transmitted between device and internet.|Prevent data theft on unsecured Wi-Fi.|
|Avoid Bandwidth Throttling|ISPs can’t see your activities; prevents slowdowns.|Streaming HD videos without ISP throttling.|
|Gaming|Reduce ping or connect to game servers in other regions.|Join a Japan-based gaming server from Europe.|

🔒 6. Benefits of Using VPNs <br>
✅ Enhanced privacy and anonymity <br>
✅ Secure data transmission (especially on public Wi-Fi)<br>
✅ Bypass censorship and geo-blocks<br>
✅ Protects from hackers and data sniffers<br>
✅ Helps remote work securely<br>

⚠️ 7. Limitations of VPNs<br>
❌ Slight speed reduction (due to encryption overhead)<br>
❌ VPN providers can log data if not trustworthy<br>
❌ Some streaming services block known VPN IPs<br>
❌ Not a substitute for antivirus or good security practices<br>

🔍 8. Example VPN Setup<br>
Let’s say:<br>
- You’re at an airport using free Wi-Fi
- You open your VPN app (e.g., ProtonVPN)
- It connects to a VPN server in Germany
- Your data is now encrypted, and websites think you’re browsing from Germany
- Hackers on the same Wi-Fi cannot see your passwords or credit card info

🧠 In Simple Terms <br>
VPN = Private, Encrypted Tunnel Between You and the Internet.
It hides your real location, protects your data, and ensures privacy.

**3. Proxy** <br>
🌐 What is a Proxy Server?<br>
➤ A Proxy Server is an intermediary between a user’s device and the Internet.When you use a proxy, your internet requests go through the proxy first, which then forwards them to the target website or service on your behalf.<br>
Essentially, a proxy hides your real IP address, filters traffic, and sometimes caches data to improve performance.<br>

💡 Real-World Analogy:<br>
Imagine you don’t want to talk to a shop directly, so you send a messenger to do it for you.<br>
The messenger goes to the shop, buys the item, and brings it back to you.<br>

- You → Client/User
- Messenger → Proxy Server
- Shop → Website/Internet

The shop only sees the messenger — not you.<br>
That’s what a proxy does on the Internet.<br>

⚙️ How a Proxy Server Works<br>
🔄 Step-by-Step Process:<br>

👉 You send a request (e.g., “open www.google.com”) to the proxy server instead of directly to the Internet.<br>
👉 The proxy server evaluates your request based on its rules (security, filtering, caching).<br>
👉 It forwards the request to the target server (Google, in this case).<br>
👉 The response (Google’s webpage) returns to the proxy.<br>
👉 The proxy passes it back to you.<br>

During this process:<br>
- The target website sees the proxy’s IP, not yours.
- The proxy can filter, log, cache, or block certain requests.

🧩Types of Proxy Servers<br>
|Type|Description|Example Use|
|--|--|--|
|Forward Proxy|Placed between users and the Internet;used to control or monitor outgoing requests.|Corporate networks, schools.|
|Reverse Proxy|Placed in front of web servers to handle incoming requests; improves performance and security.|	Protecting websites (like NGINX, Cloudflare).|
|Transparent Proxy|Users aren’t aware of it; it automatically intercepts traffic.|Schools, libraries, or ISPs monitoring traffic.|
|Anonymous Proxy|	Hides your IP address but identifies itself as a proxy.|Basic privacy for users.|
|High-Anonymity Proxy (Elite Proxy)|Completely hides your IP and doesn’t reveal it’s a proxy.|Total privacy or bypassing restrictions.|
|Distorting Proxy|Sends a fake IP to the server but still identifies as a proxy.|Hiding your location for limited privacy.|
|Caching Proxy|Stores (caches) web content to reduce load times and bandwidth.|Large organizations to save bandwidth.|
|Open/Public Proxy|Free proxies available publicly online (often risky).|Temporary or anonymous browsing (not recommended).|

🧠 Proxy vs. VPN (Key Difference)<br>
|Feature|Proxy|VPN|
|---|---|---|
|Encryption|Usually doesn’t encrypt data.|Encrypts all data.|
|Scope|App-level (browser, single program).|	System-wide (entire device).|
|IP Hiding|Yes|Yes.|
|Speed|Usually faster (less overhead).|Slightly slower (encryption overhead).|
|Security|	Lower|High.|
|Best For|Bypassing restrictions, caching.|Secure, private connections.|

👉 In short:<br>
- Use a proxy for basic privacy or content filtering.
- Use a VPN for security and encryption.

🏗️ 5. Real-World Applications of Proxy Servers<br>
|Application|Description|Example|
|--|--|--|
|Content Filtering|Blocks access to unwanted or restricted websites.|Schools blocking social media or adult content.|
|Caching|Stores frequently accessed web pages to reduce bandwidth usage.|Corporate networks or ISPs improving speed.|
|Privacy/Anonymity|Hides user’s IP from websites.|	Browsing anonymously from a different country.|
|Load Balancing|Distributes incoming traffic across multiple servers.|Websites using reverse proxies (e.g., Cloudflare, NGINX).|
|Access Control|Allows or denies users based on rules or credentials.|Companies restricting employee internet access.|
|Bypassing Geo-Restrictions|Lets users access blocked or region-specific content.|Watching U.S. Netflix from another country.|
|Security Filtering|Scans or blocks malicious content before reaching internal systems.|Reverse proxy protecting web servers from DDoS attacks.|

🧠 6. Examples of Popular Proxy Implementations <br>
|Type|Example Software/Service|
|---|------|
|Forward Proxy|Squid Proxy, Privoxy|
|Reverse Proxy|NGINX, Apache HTTP Server, HAProxy|
|Caching Proxy|Varnish Cache|
|Commercial Proxies|	Cloudflare, Akamai, Blue Coat ProxySG|
|Public/Anonymous Proxies|	HideMyAss, ProxySite.com|

🧰 7. Proxy in Daily Life (Practical Examples)<br>
🏢 In a Company:<br>

- Employees’ web traffic passes through a corporate proxy.
- The proxy blocks Facebook or YouTube and logs browsing activity.
- Cached data (like company website resources) load faster.

🏠 At Home:<br>

- Parents use a proxy-based parental control to block adult content.
- ISPs use transparent proxies to monitor or optimize network traffic

🌍 For Bypassing Restrictions:<br>
- A user in China uses an anonymous proxy in the U.S. to access blocked websites like Google or YouTube.

🖥️ For Web Hosting:<br>
A website uses a reverse proxy (like Cloudflare) to hide its real server’s IP, protect from DDoS attacks, and load pages faster from nearby servers.<br>

✅ 8. Advantages of Proxies<br>

- Hides internal network IPs (privacy)
- Reduces bandwidth (via caching)
- Controls and filters user access
- Balances web server load (reverse proxies)
- Protects internal systems from direct Internet exposure

⚠️ 9. Limitations of Proxies<br>

- Most don’t encrypt data (less secure than VPNs)
- Public proxies can log your data or be malicious
- Can slow down traffic if overloaded
- Some websites detect and block proxy IPs

🧠 In Simple Terms<br>
A Proxy Server acts as a middleman between you and the Internet.<br>
It can filter, cache, hide, or protect your network traffic depending on how it’s configured.<br>


**4. Online Resources** <br>

- https://www.geeksforgeeks.org/computer-networks/what-is-vpn-how-it-works-types-of-vpn/
- https://en.wikipedia.org/wiki/Virtual_private_network#:~:text=In%20a%20VPN%2C%20a%20tunneling,one%20network%20host%20to%20another.&text=Host%2Dto%2Dnetwork%20VPNs%20are,office%20network%20and%20a%20datacenter.
- http://geeksforgeeks.org/computer-networks/types-of-virtual-private-network-vpn-and-its-protocols/
- https://www.geeksforgeeks.org/computer-networks/what-is-proxy-server/
- https://www.splunk.com/en_us/blog/learn/proxy-servers.html
   
6.  
## Firewall Vs IDP/IDS Vs SIEM
**Firewall** <br>
🔥 1. What is a Firewall?<br>
➤ A firewall is a security system (hardware, software, or both) that monitors and controls incoming and outgoing network traffic based on a set of security rules. <br>
It acts as a barrier between your trusted internal network (like your home or office) and untrusted external networks (like the Internet).

💡Real-World Analogy: 

Imagine your home is your computer/network, and the front door is your firewall.<br>
- You decide who can enter (trusted friends) and who cannot (strangers).
- You might also decide what kind of activity is allowed (deliver a package, not steal furniture).
Similarly, a firewall filters traffic — it allows safe connections and blocks harmful or unauthorized ones.<br>

⚙️ How a Firewall Works? <br>
A firewall examines data packets (small chunks of information) traveling between your network and the internet.
Each packet includes:<br>

- Source IP address
- Destination IP addess
- Port number
- Protocol (e.g., HTTP, HTTPS, FTP)

The firewall compares this information against predefined rules (like a checklist).<br>

🔄 Process:
1. A packet arrives at the firewall.
2. The firewall checks:
- Where it came from (source)
- Where it’s going (destination)
- What type of data it carries (protocol/port)

3. Based on the rule set:

✅ Allow (if trusted) <br>
❌ Block (if suspicious)<br>

4. Logs or alerts the administrator if necessary.

🧠 Example: <br>
Let’s say your company only allows web traffic (port 80 and 443) but blocks file-sharing traffic (port 21). <br>
If a hacker tries to access your system via port 21 (FTP), the firewall blocks it immediately.<br>

🧩 Types of Firewalls<br>
Firewalls come in several types, depending on how deeply they inspect and filter data.<br>
<img width="1779" height="772" alt="Screenshot (866)" src="https://github.com/user-attachments/assets/c84bbf78-f2d9-412f-b922-7f24c4870826" />

|Type|Descriptions|Example Use|
|--|--|--|
|Packet-Filtering Firewall|Examines packets’ headers (IP, port, protocol),allows or blocks based on simple rules.|Basic routers, early firewalls.|
|Stateful Inspection Firewall|Tracks active connections and understands the state of the traffic, smarter than simple packet filters.|Home/office routers.|
|Proxy Firewall (Application-Level Gateway)|Intercepts traffic at the application layer, filters by specific apps or content.|Web proxy or mail server filtering.|
|Next-Generation Firewall (NGFW)|Combines traditional filtering with intrusion detection, deep packet inspection (DPI), malware blocking, and user identity awareness.|Enterprise security systems.|
|Network Address Translation (NAT) Firewall|Hides internal IPs using NAT; prevents direct external access.|Home routers, corporate gateways.|
|Cloud Firewalls|Hosted in the cloud, protects virtual infrastructure (e.g., AWS, Azure).|Cloud servers and services.|
|Host-Based Firewall|Installed on a single device (e.g. Windows Firewall).|Personal laptops, phones.|

🧠 4. Firewall Rules (Access Control Lists – ACLs) <br>
Rules are typically written as:<br>
ALLOW TCP from 192.168.1.5 to ANY port 443 <br>
DENY  TCP from ANY to 192.168.1.5 port 21 <br>

ℹ️ Meaning:
- Allow HTTPS traffic from a specific internal machine to anywhere.
- Deny FTP traffic from anyone to a protected machine.

🌍 5. Usage of Firewalls in Daily Life
|Scenario|Firewall Function|Example|
|---|---|--|
|Home Wi-Fi Router|Blocks incoming internet traffic that’s not part of an established request.|Prevents hackers from connecting to your devices.|
|Corporate Networks|Enforces policies on what employees can access.|Blocks social media or torrent sites at work.|
|Personal Computers|Software firewall blocks unknown apps from using the Internet.|Windows Defender Firewall blocking suspicious programs.|
|Cloud Servers|Cloud firewalls control access to virtual machines.|AWS Security Groups or Azure Firewalls.|
|Public Wi-Fi Networks|Filters malicious packets and prevents attacks.|Hotel or airport network firewalls.|
|Data Centers|Protects critical databases and internal servers.|Enterprise-grade NGFWs from Cisco, Palo Alto, or Fortinet.|

🧠 6. Example of a Firewall in Action<br>
Imagine:

- You’re at a café using Wi-Fi.
- A hacker on the same network tries to scan your laptop’s open ports.
- Your firewall detects and blocks the suspicious packets — preventing access.
You remain safe, even though you’re on a public, untrusted network.<br>

💪 7. Benefits of Firewalls<br>
✅ Protects against unauthorized access<br>
✅ Blocks malicious traffic<br>
✅ Controls outgoing data (prevents leaks)<br>
✅ Enforces corporate or parental policies<br>
✅ Monitors and logs network activity<br>

⚠️ 8. Limitations of Firewalls <br>
❌ Cannot protect against insider threats<br>
❌ Doesn’t detect viruses hidden inside allowed traffic<br>
❌ Needs correct configuration i.e. weak rules = weak protection<br>
❌ Won’t stop phishing or social engineering attacks directly<br>

🔐 9. Real-World Examples of Firewalls <br>

- Software Firewalls: Windows Defender Firewall, macOS Firewall, Linux iptables
- Hardware Firewalls: Cisco ASA, FortiGate, Palo Alto Networks, SonicWall
- Cloud Firewalls: AWS WAF, Azure Firewall, Google Cloud Armor

🧠 In Simple Terms <br>
A firewall is your network’s security guard — it decides who can enter or leave your digital “building” based on predefined safety rules. <br>

**2. Resources** <br>
   - https://tryhackme.com/room/firewallfundamentals
   - https://www.geeksforgeeks.org/computer-networks/introduction-of-firewall-in-computer-network/
   - https://www.geeksforgeeks.org/computer-networks/types-of-network-firewall/
   - https://en.wikipedia.org/wiki/Firewall_(computing)
   - https://www.checkpoint.com/cyber-hub/network-security/what-is-firewall/5-types-of-firewalls-which-one-do-you-need/

## SSID
## Chain of Custody
## Update & Patching
## SLA
## SLO
## SeCSLA
## CSC
## CSP
## Bot Vs Botnets
## DFIR
## SOC
## Reconnaissance
## Red Team Vs Blue Team
## KQL (Kusto Query Language )
KQL can refer to Kusto Query Language in the context of Azure, and Kibana Query Language in the context of Elastic. Both are query languages used to explore and process data based on search terms and filters.

## Kibana
Kibana is a web-based visualisation tool for exploring data stored in Elasticsearch. It can be used to create interactive dashboards and charts that help users to understand data.

KQL, or Kibana Query Language, is an easy-to-use language that can be used to search documents for values. For example, querying if a value within a field exists or matches a value. If you are familiar with Splunk, you may be thinking of SPL (Search Processing Language).

## Defang IP
## SSID
## BSSID
## PSK
## WPS
## WEP, WPA WPA2 WPA3
## Obfuscation
## NVD, CVE. CVSS, CWE
## ISMS
## Cloud Exit
## Honey Well
## Firewall
## Honey Pot
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Most common Malware
## Virus
## Worm
## Trojan horses
## Ransomware
## Spyware
## Adware
## Scareware
## Rootkits
## Backdoor (RAT)
## Bots
