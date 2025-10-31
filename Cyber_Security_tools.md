# List of Cyber Security Tools

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## 1. General Skills
## 2. Search Engine
Google (use google dorking), Microsoft Bing, China's Baidu
## 3. SPECALIZED SEARCH ENGINE
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
## 4. Others
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

## 5. Sandboxing
Malware analysis and threat hunting.
- Hybrid Analysis
- Any.run
- Joe Sandbox

## 6. Permanently data deletion with (0's and 1's)

- SDelete (Microsoft)
- Shred (Linux)
- Secure Empty trash Mac OS X
- Physical destroy the storage devices

## 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## 7. Blue Team
## 7.1 SIEM (Splunk, ELK Stack) (security information and event management)
SIEM stands for "Security Information and Event Management".In 2005, the term "SIEM" (Security Information and Event Management) was introduced by Gartner analysts Mark Nicolett and Amrit Williams. It is the combination of SIM(Security Informatin Management) and SEM(Security Event Management).
SIM(Security Informatin Management): Long-term storage as well as analysis and reporting of log data.
SEM(Security Event Management): Real-time monitoring, correlation of events, notifications and console views.

SIEM acts as a centralized point in the (SOC)Security Operation Center where security professionals usually "Security analyst" employed for 24X7/365 days monitoring, analysis, detection and responding to the security alerts, logs, and events based upon their severity levels or behaviours wihtin an Organizations. 

**SIEM Data Sources** <br>
- Network devices: Routers, switches, bridges, wireless access points, modems, line drivers, hubs
- Servers: Web, proxy, mail, FTP
- Security devices: Intrusion prevention systems (IPS), firewalls, antivirus software, content filter devices, intrusion detection systems (IDS) and more
- Applications: Any software used on any of the above devices
- Cloud and SaaS solutions: Software and services not hosted on-premises

**Capabilitties**
- Data aggregation: comes from different sources such as hardware, software, OS(Windows, Linux, MacOS) databased, servers and applications
- Normalisation: Breaking down a log into several fields for ease of understanding is known as Parsing, and converting all the logs of various log sources(Windows, Linux and others) into one consistent format is known as Normalization. 
- Correlation: looks for common matching patterns, linkage of events and turned them into meaningful informations (What, When, How happend)
- Alerting: The automated analysis of correlated events.
- Dashboards: Tools can take event data and turn it into informational charts to assist in seeing patterns, or identifying activity that is not forming a standard pattern.
- Compliance:  Applications can be employed to automate the gathering of compliance data, producing reports that adapt to existing security, governance and auditing processes.
- Retention: Employing long-term storage of historical data to facilitate correlation of data over time, and to provide the retention necessary for compliance requirements. The Long term log data retention is critical in forensic investigations as it is unlikely that the discovery of a network breach will be at the time of the breach occurring
- Forensic analysis: The ability to search across logs on different nodes and time periods based on specific criteria. This mitigates having to aggregate log information in your head or having to search through thousands and thousands of logs.


**The role of UBA in SIEM** <br>
Other tools have made their way into the SIEM space, particularly user behavior analytics (UBA). Also known as user and entity behavior analytics (UEBA), UBA is used to discover and remediate internal and external threats. <br>

While UBA is often seen as a more advanced security tool, it’s increasingly folded into the SIEM category. For instance, the Gartner Magic Quadrant for SIEM includes information about UBA/UEBA offerings.<br>

UBA works in two ways: <br>

- Creating a baseline for any user or application’s data. Then, highlighting deviations from that norm that could be a threat.
- Monitoring malicious behavior and preventatively addressing security issues.
These functions play a critical role in any SIEM solution as they illuminate patterns of behavior within the organization’s network, offering context you didn’t have before. They also filter alerts before the security operations center (SOC) team is notified — helping reduce alert fatigue and freeing up analysts’ time for more complex or urgent threats. <br>

## Various system Log Management
- Windows: Windows records every event that can be viewed through the **Event Viewer**. It assigns a unique ID to each type of log activity, making it easy for the analyst to examine and keep track of.
- Linux: Linux OS stores all the related logs, such as events, errors, warnings, etc. These are then ingested into SIEM for continuous monitoring. Some of the common locations where Linux stores logs are:

/var/log/httpd: Contains HTTP Request  / Response and error logs. <br>
/var/log/cron: Events related to cron jobs are stored in this location. <br>
/var/log/auth.log and /var/log/secure: Stores authentication-related logs. <br>
/var/log/kern: This file stores kernel-related events. <br>


**Popular SIEM Tools** <br>
  - Splunk (Cisco)
  - IBM QRadar
  - MS Sentinel 
  - Elastic Stack (Open-Source ELK Stack)
  - ArchSight
  - LogRhythm
  -(Splunk, IBM QRadar, Microsoft Sentinel, ArcSight Enterprise Security Manager (Micro Focus), Sumo Logic, LogRhythm NextGen SIEM, Elastic Security (formerly Elastic SIEM), 
  SolarWinds Security Event Manager, Exabeam Advanced Analytics, Fortinet FortiSIEM )

**Online Resources** <br>
- https://en.wikipedia.org/wiki/Security_information_and_event_management
- https://www.splunk.com/en_us/blog/learn/siem-security-information-event-management.html?utm_campaign=google_emea_tier1_en_search_generic_security_siem&utm_source=google&utm_medium=cpc&utm_content=siem_learn_blog&utm_term=what%20is%20siem%20in%20cyber%20security&device=c&_bt=771525059501&_bm=e&_bn=g&gad_source=1&gad_campaignid=8200497833&gbraid=0AAAAAD8kDz34C3oUw8_Iv3mUky53wRA4r&gclid=Cj0KCQjwmYzIBhC6ARIsAHA3IkRa89pZNpjkVlciUX7lQJzXVp5jd5AChjBP-oKHnYRoy4_7U1Mp85YaAiPeEALw_wcB
- 

## 7.2 SOAR (Security Orchestration, Automation and Response)
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
   
- EDR vs XDR vs MDR <br>
   EDR(Wazuh) (Endpoint Detection and Response) EDR is a cybersecurity solution focused on monitoring, detecting, and responding to threats on endpoints (like laptops, desktops, servers).<br>
    - EDR have been created because antiviruses cannot catch every malicious binary and process running on the endpoint
    - CrowdStrike Falcon
    - SentinelOne
    - Microsoft Defender for Endpoint
    - Sophos Intercept X
    - Carbon Black (VMware)
      
  - XDR (Extended detection and response) <br>
     XDR expands on EDR by integrating multiple security layers (endpoints, email, servers, cloud, network) into one platform for detection and response. <br>
    - Microsoft 365 Defender (XDR solution)
    - Palo Alto Cortex XDR
    - Trend Micro Vision One
    - SentinelOne Singularity XDR
    - CrowdStrike Falcon XDR
    - Palo Alto Cortex XDR

  - MDR – Managed Detection and Response <br>

    MDR is an outsourced security service where an external team (SOC-as-a-service) provides 24/7 monitoring, threat hunting, and response using EDR/XDR tools, When you lack internal expertise or resources to run your own detection and response operations. <br>
    Popular MDR  Providers: <br>
   - Arctic Wolf
   - CrowdStrike Falcon Complete (MDR over Falcon)
   - Red Canary
   - Sophos MDR
   - SentinelOne Vigilance

  
- VPN (Virtual Private Network)

   A VPN encrypts internet traffic and routes it through a secure tunnel to a server, masking the user's IP address and protecting data from interception.
    
  - Popular VPN Tools:
  - OpenVPN (open-source, enterprise-grade)
  - NordVPN / ExpressVPN (consumer)
  - Cisco AnyConnect
  - Palo Alto GlobalProtect
  - WireGuard (lightweight, open-source)

- UEBA (user and entity behavior analytics) <br>
   UEBA is a cybersecurity technology that uses machine learning and analytics to detect abnormal behavior by users, devices, or applications in a network. Instead of relying solely on known attack signatures, UEBA identifies anomalies and risky behaviors that could indicate insider threats, compromised accounts, or advanced persistent threats (APTs). <br>
   Popular UEBA Tools: <br>
   - Microsoft Defender XDR (formerly Azure Sentinel UEBA)
   - Splunk UEBA

- ASM (attack surface management) <br>
   ASM (Attack Surface Management) is the process of continuously discovering, monitoring, and managing all external digital assets and potential exposure points (attack surfaces) that could be targeted by attackers. <br>
   Popular ASM Tools: <br>
   - AttackIQ
   - Palo Alto Cortex Xpanse
   - Randori Recon (IBM)
   - CyCognito
   - SecurityTrails
   - Shodan / Censys
   - IntrigueCore (open-source)
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## 8. Red Team
- Wireshark
- Nmap
- Metasploit
- Nessus
- John the Ripper
- Air-Crack NG
- Burpsuite (web pentesting)
- 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## 9. Digital / Cyber Forensics
- Autopsy
- FTK
- Sleuth Kit
- Volatility

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## 10. For Level 1 SOC Analysts, typical job responsibilities include:
Proactive monitoring of network traffic and events
Creating tickets
Investigating alerts
Remediation steps
Closing alerts
Triaging the incident and coordinating with Level 2 SOC Analysts
As Level 1 SOC Analysts gain more experience, they can then choose to progress to become a Level 2 SOC Analyst, Level 3 SOC Analyst, SOC Engineer/Architect, or SOC Manager.

## 11. SOC L1 Pre-requisites Skills
Network Fundamentals - the core concepts of how computers communicate with each other are important to understand before learning how to attack and defend networks
Web Application Technologies - learn the building blocks of the world wide web to understand how to attack web applications
Linux Fundamentals - Many servers and security tools use Linux. Learn how to use the Linux operating system, a critical skill in cyber security
Windows Fundamentals - Get hands-on access to Windows and its security controls. These basics will help you in identifying, exploiting and defending Windows
SOC Analysts must also have soft skills like critical thinking, problem-solving, independence, resilience, and logical thinking.

## 12. IT Support roles
## 13. Stay Updated and Keeping up with the industry trends and technology
Here are a number of researchers, influencers, and key content creators in the field that share the very latest in defensive security, including Katie Paxton-Fear, Nicole Enesse, Simply Cyber, Florian Roth, Chris Greer, Alyssa Miller, Tracy Z. Maleef, Lesley Carhart, and Marcus J. Carey.

We also recommend regularly keeping up with ThreatPost, The Hacker News, PenTest Magazine, and the TryHackMe blog.

## 14. SOC Roadmap
- SOC L1 (Analysts)
- SOC L2 (Analyst or Incident Responders)
- SOc L3 (Threat Hunter or Malware Analysts)
- SOC Manager
- CISO

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## 15. Incident Response and Incident Management
**What is a Cyber Incident?** <br>
The monitoring process starts from SOC (Security Operations Center) teams, where a team of Security analysts are responsible for 24X7 supervising and monitoring the oraganisation's security. Their task involves following:
- Closely monitors events and activity.
- Overview the events nature(Normal, anomaly or unexpected)
- alert is generated if the event is anomaly or unexpected
- Alert can be false or True (True Positive or False Positive)
- if it's real then team will perform triage process to determine the Severity level.
- Based on high severity level (Low, Medium, High, Critical)

**NOTE:** if the severity of the alert is sufficient, an incident will be raised.

- When an alert with high severity level then it becomes Cyber incident and Incident Response & Incident Management comes into the Play.

**Incident Response** <br>
Deals with Technical aspects "What happened?"
- EDR or AV alert (events activity i.e. Normal or abnormal)
- Network Tap alert (alerts for anomalour network)
- SIEM alert (log's activity)

Sometimes we need to take help from Digital Forensics team when the generated alert is not solid enough. We need following incidents:
- Recovering Hard disk of infected Host to get ideas aboout the Malware propagation into the System.
- Recovering data from RAM of infected Host to investigate the how malware works
- Recovering System and Network logs to uncover the malware spreading

**Incident Management** <br>
Deals with the actual incidents"How do we respond to what happened?"

- Triaging the incident to accurately update the severity of the incident as new information becomes available and getting more stakeholders involved to help deal with the incident, such as Subject Matter Experts (SMEs).
- Guiding the incident actions through the use of playbooks.
- Deciding which containment, eradication, and recovery actions will be taken to deal with the incident.
- Deciding the communication that will be sent internally and externally while the team deals with the incident.
- Documenting the information about the incident, such as the actions taken and the effect that they had on dealing with the incident.
- Closing the incident and taking the information to learn from the incident and improve future processes and procedures.

**NOTE:** Effective incident response and management are required to deal with an incident. It is often mistaken that only technical skills are required to deal with incidents. The management aspect is just as important.


**Levels of Incidents Response and Management** <br>
A user has reported a phishing email <br>
Level 1: SOC Incident <br>
At level one, these are often not even classified as incidents. Usually, these require a purely technical approach. At this level,  upon investigation of our example, the analyst finds that it is an isolated event and therefore simply updates the mail filtering rules to block the sender. These levels of incidents can happen several times a day and are usually quick to deal with and the analyst deals with this themselves.

However, in our example, a Computer Emergency Readiness Team (CERT) Incident may be invoked if the investigation found that several users received the email.
Level 2: CERT Incident <br>
At level two, several analysts in the SOC may be involved in the investigation. A CERT Incident is one where we don't yet have enough to raise the alarm bells. Still, we are concerned and therefore performing additional investigation to determine the scope of the incident. Usually, the analyst would request assistance and more members of the SOC team would get involved. In our example, at this point, we would be investigating if any of those users interacted with the email. We would also like to better understand what the email does.

If we were able to stop the incident before any of the users interacted with the email, we would usually stop at this level. However, if we discover that the email contains malware and that some of the users actually interacted with the email, we would invoke a Computer Security Incident Response Team (CSIRT) incident.
Level 3: CSIRT Incident <br>
At level three, the entire SOC is placed on high alert and actively working to resolve the incident. At this point, the entire SOC team will focus on the single incident to deal with it. Analysts and the forensic team work to uncover the full scope of the incident and the management team is taking action against the threat actor to contain the spread of the malware, eradicate it from hosts where it is discovered, and recover affected systems.

If the team is able to stop the spread of the attack before any disruptions can occur or the threat actor can escalate their privileges within the estate, the CSIRT team will close the incident. However, if it is determined that the scope is larger through investigation, we would invoke a Crisis Management Team (CMT) Incident.
Level 4: CMT Incident <br>
At level four, it is all hands on deck and officially a full-scale cyber crisis. The CMT would usually consist of several key business stakeholders such as the entire executive suite, members from the legal and communication teams, as well as other external parties, such as the regulator or police. Furthermore, at this level, we start to move into the territory of what is called "nuclear" actions. Rather than simple actions to contain, eradicate, and recover, this team can authorise the use of nuclear actions, such as taking the entire organisation offline to limit the incident's damage.

**The Different Roles during an incident:** <br>

<img width="1870" height="968" alt="Screenshot (843)" src="https://github.com/user-attachments/assets/da61e104-7853-4ee9-bb32-a54d3d423d2b" />

<img width="1872" height="1010" alt="Screenshot (844)" src="https://github.com/user-attachments/assets/b3755ba1-d5e9-4938-9013-346cc510c435" />

<img width="1865" height="923" alt="Screenshot (845)" src="https://github.com/user-attachments/assets/99a0a4d6-0532-4501-adce-e0b75f902950" />

----------------------------------------------------------------------------------------------------------------------------------------------------------------------
