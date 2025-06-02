# List of Cyber Security Tools

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## General Skills
## Search Engine
Google (use google dorking), Microsoft Bing, China's Baidu
## SPECALIZED SEARCH ENGINE
- Shodan.io (Internet-Connected devices)
- censys (focuses on Internet-connected hosts, websites, certificates, and other Internet assets. Some of its use cases include enumerating domains in use, auditing open ports and services, and discovering rogue assets within a network.)
-  Have I Been Pwned
-  https://threatmap.checkpoint.com/
-  https://livethreatmap.radware.com/
-  https://cybermap.kaspersky.com/
-  Exploit Database (exploit.db.com)
-  GitHub
-  MITRE ATT & CK
-  VirusTotal
-  Hunter.io - this is  an email hunting tool that will let you obtain contact information associated with the domain
## Others
- Gobuster Gobuster is a free and open-source directory and file enumeration tool. Penetration testers and security professionals use it to fin hidden directories and files on web servers.

  Gobuster is a tool used to brute-force:
  
  URLs (directories and files) in web sites.
  DNS subdomains (with wildcard support).
  Virtual Host names on target web servers.
  Open Amazon S3 buckets
  Open Google Cloud buckets
  TFTP servers
-  Metadefender Cloud - OPSWAT
- bevigil.com
Industry’s first security search engine for Mobile Threats. Search and uncover Digital Footprints, Supply Chain and threats associated with any mobile app for free of cost.

With BeVigil , users can now ascertain the risk rating of an app, check the list of permissions it requests on installation, and ensure it is not malicious. BeVigil’s familiar and easy-to-use search engine interface allows users to simply search for the app name to get a risk score that is indicative of the app’s overall security posture. Moreover, app developers can proactively upload their applications to BeVigil to identify vulnerabilities and remediate them, avoiding any pitfalls prior to their launch.

## Sandboxing
Malware analysis and threat hunting.
- Hybrid Analysis
- Any.run
- Joe Sandbox

## Permanently data deletion with (0's and 1's)

- SDelete (Microsoft)
- Shred (Linux)
- Secure Empty trash Mac OS X
- Physical destroy the storage devices

## 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Blue Team
- SIEM (Splunk, ELK Stack) (security information and event management)
  - Splunk (Cisco)
  - IBM QRadar
  - MS Sentinel 
  - Elastic Stack (Open-Source ELK Stack)
  - ArchSight
  - LogRhythm
  -(Splunk, IBM QRadar, Microsoft Sentinel, ArcSight Enterprise Security Manager (Micro Focus), Sumo Logic, LogRhythm NextGen SIEM, Elastic Security (formerly Elastic SIEM), 
  SolarWinds Security Event Manager, Exabeam Advanced Analytics, Fortinet FortiSIEM )

- SOAR (Security Orchestration, Automation and Response)
  SOAR platforms help automate and coordinate the response to security incidents using playbooks, integrating with other tools (like SIEM, EDR, firewalls, etc.).<br>

  Popular SOAR Tools: <br>
  - Palo Alto Cortex XSOAR
  - IBM Resilient
  - Splunk SOAR (Phantom)
  - Swimlane
  - DFLabs IncMan  

  - Real-life example: Zensar’s Cybersecurity Team uses SOAR for faster email phishing attacks & incident response. The security team has automated the security 
    investigation process by manually searching for threats.

    CrowdStrike Falcon® Fusion SOAR for security analysis <br>

    Use cases - Threat Hunting, Case Management, Threat Intelligence Coordination Automation, Vulnerability Management, Automated Phishing Attacks Investigation, Analysis & 
    Response, Automated Remediation, Incident Response, Endpoint Protection, Forensic Investigation, Cloud security orchestration, Incident lifecycle case management, SSL 
    certificate expiration tracking, Detecting suspicious user login from IP address locations. <br>
  

- MSSP (Managed Security Service Providers)
  They are third-party vendors to your Cyber Security firms.
  -  CISCO, Palo Alto, Check Points, CheckPoint, Verizon, Fortinet, IBM, AT&T, Secure works,  Trust waves
  - CISCO(Networking devices and equipments), Palo Alto Networks
  - Fortinet (SOC-based services, Cloud security solutions)
  - Cloud security (Azure, AWS, GCP)
  - Okta (IAM , SSO, MFA user activity monitoring)
  - Qualys (Risk & Vulnerability Management Software)
  - Anivirus (McAfee, Quick Heal, )

- MISP (Malware Informatin Sharing Platform) <br>
  Popular Tools and Integrations: <br>
   - MISP (Official): https://www.misp-project.org
   - MISP integrations:
   - TheHive (incident response platform)
   - Cortex (analysis engine)
   - SIEMs like Splunk, QRadar, or ELK Stack
   - Suricata/Snort (IDS tools for using MISP IOCs in detection)
   - Maltego, OpenCTI for visualization and correlation
  
- Firewall <br>
     A firewall is a security device (hardware or software) that monitors and controls incoming and outgoing network traffic based on predefined security rules. <br>

     Popular Firewall Tools: <br>

    - Cisco ASA / Firepower
    
    - Palo Alto Networks NGFW
    
    - Fortinet FortiGate
    
    - Check Point
    
    - pfSense (open-source)
  
- IDPS (Snort, Suricata, CISCO Firepower) <br>
   IDPS detects suspicious activities and either alerts (IDS) or actively blocks (IPS) the malicious behavior on the network or host level. <br>

   Popular IDPS Tools:

    - Snort (open-source IDS/IPS)
    - Suricata
    - Cisco Firepower NGIPS
    - Palo Alto NGFW with Threat Prevention
    - Trend Micro TippingPoint
   
- EDR vs XDR
  - EDR(Wazuh) (Endpoint Detection and Response)
    - EDR have been created because antiviruses cannot catch every malicious binary and process running on the endpoint
    - CrowdStrike Falcon

     - SentinelOne

     - Microsoft Defender for Endpoint

     - Sophos Intercept X

     - Carbon Black (VMware)
  - XDR (Extended detection and response)
    - Microsoft 365 Defender (XDR solution)
    - Palo Alto Cortex XDR
    - Trend Micro Vision One
    - SentinelOne Singularity XDR
    - CrowdStrike Falcon XDR
    - Palo Alto Cortex XDR
- VPN (Virtual Private Network)
  - Popular VPN Tools:
  - OpenVPN (open-source, enterprise-grade)
  - NordVPN / ExpressVPN (consumer)
  - Cisco AnyConnect
  - Palo Alto GlobalProtect
  - WireGuard (lightweight, open-source)

- UEBA (user and entity behavior analytics)

- ASM (attack surface management)
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Red Team
- Wireshark
- Nmap
- Metasploit
- Nessus
- John the Ripper
- Air-Crack NG
- Burpsuite (web pentesting)
- 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Digital / Cyber Forensics
- Autopsy
- FTK
- Sleuth Kit
- Volatility

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## For Level 1 SOC Analysts, typical job responsibilities include:
Proactive monitoring of network traffic and events
Creating tickets
Investigating alerts
Remediation steps
Closing alerts
Triaging the incident and coordinating with Level 2 SOC Analysts
As Level 1 SOC Analysts gain more experience, they can then choose to progress to become a Level 2 SOC Analyst, Level 3 SOC Analyst, SOC Engineer/Architect, or SOC Manager.

## SOC L1 Pre-requisites Skills
Network Fundamentals - the core concepts of how computers communicate with each other are important to understand before learning how to attack and defend networks
Web Application Technologies - learn the building blocks of the world wide web to understand how to attack web applications
Linux Fundamentals - Many servers and security tools use Linux. Learn how to use the Linux operating system, a critical skill in cyber security
Windows Fundamentals - Get hands-on access to Windows and its security controls. These basics will help you in identifying, exploiting and defending Windows
SOC Analysts must also have soft skills like critical thinking, problem-solving, independence, resilience, and logical thinking.

## IT Support roles
## Stay Updated and Keeping up with the industry trends and technology
Here are a number of researchers, influencers, and key content creators in the field that share the very latest in defensive security, including Katie Paxton-Fear, Nicole Enesse, Simply Cyber, Florian Roth, Chris Greer, Alyssa Miller, Tracy Z. Maleef, Lesley Carhart, and Marcus J. Carey.

We also recommend regularly keeping up with ThreatPost, The Hacker News, PenTest Magazine, and the TryHackMe blog.

## SOC Roadmap
- SOC L1 (Analysts)
- SOC L2 (Analyst or Incident Responders)
- SOc L3 (Threat Hunter or Malware Analysts)
- SOC Manager
- CISO
