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

<img width="847" height="683" alt="Screenshot (994)" src="https://github.com/user-attachments/assets/9f95137f-710f-4481-9637-660b24159299" />
 
**SIEM Data Sources** <br>
- Network devices: Routers, switches, bridges, wireless access points, modems, line drivers, hubs
- Servers: Web, proxy, mail, FTP
- Security devices: Intrusion prevention systems (IPS), firewalls, antivirus software, content filter devices, intrusion detection systems (IDS) and more
- Applications: Any software used on any of the above devices
- Cloud and SaaS solutions: Software and services not hosted on-premises

<img width="823" height="838" alt="Screenshot (995)" src="https://github.com/user-attachments/assets/0fc63deb-ad51-4db6-aeec-3f821be586c7" />

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

**Log Ingestion** <br>
All these logs provide a wealth of information and can help identify security issues. Each SIEM solution has its own way of ingesting the logs. Some common methods used by these SIEM solutions are explained below: <br>

- Agent / Forwarder: These SIEM solutions provide a lightweight tool called an agent (forwarder by Splunk) that gets installed on the Endpoint. It is configured to capture and send all the important logs to the SIEM server.
- Syslog: Syslog is a widely used protocol to collect data from various systems like web servers, databases, etc., and send real-time data to the centralized destination.
- Manual Upload: Some SIEM solutions, like Splunk, ELK, etc., allow users to ingest offline data for quick analysis. Once the data is ingested, it is normalized and made available for analysis.
- Port-Forwarding: SIEM solutions can also be configured to listen on a certain port, and then the endpoints forward the data to the SIEM instance on the listening port.

  
**Popular SIEM Tools** <br>
  - Splunk (Cisco)
  - IBM QRadar
  - MS Sentinel 
  - Elastic Stack (Open-Source ELK Stack)
  - ArchSight
  - LogRhythm
  -(Splunk, IBM QRadar, Microsoft Sentinel, ArcSight Enterprise Security Manager (Micro Focus), Sumo Logic, LogRhythm NextGen SIEM, Elastic Security (formerly Elastic SIEM), 
  SolarWinds Security Event Manager, Exabeam Advanced Analytics, Fortinet FortiSIEM )

**Components of Splunk** <br>
Splunk has three main components: Forwarder, Indexer, and Search Head. These components work together to help us search and analyze the data. These components are explained below:

<img width="1400" height="308" alt="Screenshot (1003)" src="https://github.com/user-attachments/assets/887bd120-994d-47e1-bdf2-de512f472141" />

**Splunk Forwarder** <br>
Splunk Forwarder is a lightweight agent installed on the endpoint intended to be monitored, and its main task is to collect the data and send it to the Splunk instance. It does not affect the endpoint's performance as it takes a few resources to process. Some of the key data sources are: <br>

- Web server generating web traffic.
- Windows machine generating Windows Event Logs, PowerShell, and Sysmon data.
- Linux host generating host-centric logs.
- Database generating DB connection requests, responses, and errors.
<img width="1191" height="451" alt="Screenshot (1004)" src="https://github.com/user-attachments/assets/acf2575f-3387-48ff-b680-e990d44e3e78" />
The forwarder collects the data from the log sources and sends it to the Splunk Indexer.  <br>

**Splunk Indexer** <br>
Splunk Indexer plays the main role in processing the data it receives from forwarders. It parses and normalizes the data into field-value pairs, categorizes it, and stores the results as events, making the processed data easy to search and analyze.<br>

<img width="827" height="392" alt="Screenshot (1005)" src="https://github.com/user-attachments/assets/40b7c694-2f78-4390-82ea-88e3e6b04478" />

Now, the data, which is normalized and stored by the indexer, can be searched by the Search Head, as explained below.<br>
**Splunk Search head** <br>
Splunk Search Head is the place within the Search & Reporting App where users can search the indexed logs, as shown below. The searches are done using the SPL (Search Processing Language), a powerful query language for searching indexed data. When the user performs a search, the request is sent to the indexer, and the relevant events are returned as field-value pairs.<br>

<img width="1074" height="268" alt="Screenshot (1006)" src="https://github.com/user-attachments/assets/940fbe0a-3ee4-4b72-a991-87e1a98b18d2" />

The Search Head also allows you to transform results into presentable tables and visualizations such as pie, bar, and column charts, as shown below:<br>
<img width="1200" height="736" alt="Screenshot (1007)" src="https://github.com/user-attachments/assets/3c81d866-4d9e-41d7-927c-59d3a3f3da36" />

**Splunk Navigations** <br>
When you access Splunk, you will see the default home screen as shown below: <br>
<img width="1920" height="832" alt="Screenshot (1008)" src="https://github.com/user-attachments/assets/92cc4da4-cf9f-4c11-b84b-348bc696acc4" />
Let's look at each section of this home screen.<br>
**Splunk Bar** <br>
The top panel is the Splunk Bar as shown below: <br>

<img width="1542" height="37" alt="splunk-bar" src="https://github.com/user-attachments/assets/013d809d-af70-4494-9173-03f92642e8ba" />

In the Splunk Bar, we have the following options available:
- Messages: View system-level notifications and messages.
- Settings: Configure Splunk instance settings.
- Activity: Review the progress of search jobs and processes.
- Help: View tutorials and documentation.
- Find: Search across the App.
The Splunk Bar, allows users to switch between installed Splunk apps instead of using the Apps panel.

**Apps Panel**<br>  

Next is the Apps Panel. This panel shows the apps installed for the Splunk instance. The default app for every Splunk installation is Search & Reporting.

<img width="409" height="520" alt="Screenshot (1009)" src="https://github.com/user-attachments/assets/7f54c641-ced5-40e5-b234-ad75c993bbf1" />
<img width="405" height="523" alt="Screenshot (1010)" src="https://github.com/user-attachments/assets/7644beaa-c5f8-45a0-9359-65e4b328f1a0" />

You can also switch between the Splunk Apps directly from the Splunk Bar, as shown below, without using the Apps Panel.<br>
<img width="367" height="35" alt="splunk-bar2" src="https://github.com/user-attachments/assets/bde5168a-bca0-48f5-92a1-e37216730d9b" />

**Explore Splunk** <br>
The next section is Explore Splunk . This panel contains quick links to add data to the Splunk instance, add new Splunk apps, and access the Splunk documentation. <br>
<img width="1512" height="405" alt="Screenshot (1011)" src="https://github.com/user-attachments/assets/63f6e7c3-e389-4b1a-8fb8-33b3393a1b33" />

**Splunk Dashboard** <br>
The last section is the Home Dashboard. By default, no dashboards are displayed. You can choose from a range of dashboards readily available within your Splunk instance. You can select a dashboard from the dropdown menu or by visiting the dashboards listing page.<br>

<img width="1920" height="830" alt="Screenshot (1012)" src="https://github.com/user-attachments/assets/0ac973c3-bf47-450f-a810-6aee5b3a6119" />

You can also create dashboards and add them to the Home Dashboard. The dashboards you create can be viewed separately from the other dashboards by clicking on the Yours tab.
<img width="1920" height="804" alt="Screenshot (1017)" src="https://github.com/user-attachments/assets/a0939b3b-edb1-42f3-b08f-ee8beed4df94" />

Please review the Splunk documentation on Navigating Splunk here.

**Adding Data** <br>
Splunk can ingest any data. According to the Splunk documentation, when data is added to Splunk, the data is processed and transformed into a series of individual events. The data sources can be event logs, website logs, firewall logs, etc. The data sources are grouped into categories.<br>

 Below is a chart listing from the Splunk documentation detailing each data source category. <br>
<img width="1626" height="668" alt="Screenshot (1018)" src="https://github.com/user-attachments/assets/a2f98519-7b2f-4ac1-a866-2cb614f44540" />

 In this task, we're going to focus on VPN logs. We're presented with the following screen when we click on the Add Data link on the Splunk home screen.
<img width="1512" height="405" alt="Screenshot (1011)" src="https://github.com/user-attachments/assets/0c73fdab-4510-4a4d-ba49-808dc152ab98" />
<img width="1454" height="675" alt="Screenshot (1019)" src="https://github.com/user-attachments/assets/29102aa3-0d4e-4e0f-9edd-c15f3080c2c0" />
<img width="1450" height="423" alt="Screenshot (1020)" src="https://github.com/user-attachments/assets/663bcc1b-11b9-4965-8276-dca9ef4b4485" />
We will use the Upload Option to upload the data from our local machine. <br>
Practical <br>
Download the log file VPN_logs from the Download Task Files button below and upload it to the Splunk instance we started in Task #2. If you are using the AttackBox, the log file is available in the /root/Rooms/SplunkBasic/ directory.<br>

To upload the data successfully, you must follow five steps, which are explained below:<br>

1. Select Source: Choose the Log file and the data source.
2. Select Source Type: Select what type of logs are being ingested, e.g, JSON, syslog.
3. Input Settings: Select the index where these logs will be dumped and the HOSTNAME to be associated with the logs.
4. Review: Review all the configurations.
5. Done: Complete the upload. Your data will be uploaded successfully and ready to be analyzed.

<img width="1920" height="885" alt="Screenshot (1021)" src="https://github.com/user-attachments/assets/d0d4a5fc-9dfb-48fc-a986-713db47ce4a2" />
<img width="1920" height="826" alt="Screenshot (1022)" src="https://github.com/user-attachments/assets/2404ef85-255e-4eb5-a7b0-56902fdd6de1" />
<img width="1920" height="790" alt="Screenshot (1023)" src="https://github.com/user-attachments/assets/5bc9ebcf-747a-452c-b57a-7caba02aca95" />
<img width="1920" height="878" alt="Screenshot (1024)" src="https://github.com/user-attachments/assets/27d87ef2-57cd-432e-a7ef-1268d155f59c" />
<img width="1920" height="886" alt="Screenshot (1025)" src="https://github.com/user-attachments/assets/f87044fb-7d17-493f-b5fe-7de280c7332b" />
<img width="1920" height="848" alt="Screenshot (1026)" src="https://github.com/user-attachments/assets/62175e7c-6b8a-4f4a-a933-ae63a03420d0" />
<img width="1920" height="936" alt="Screenshot (1027)" src="https://github.com/user-attachments/assets/ec14af40-2135-4ab5-a64d-108211bb793e" />
<img width="1920" height="1080" alt="Screenshot (1028)" src="https://github.com/user-attachments/assets/9ba52840-3656-4ed3-a187-a6e57c08abb5" />
<img width="1920" height="1080" alt="Screenshot (1029)" src="https://github.com/user-attachments/assets/54a91ade-60f3-4db2-8880-11a1b43d014c" />
<img width="1920" height="909" alt="Screenshot (1030)" src="https://github.com/user-attachments/assets/047ef4b4-2c93-4101-ad91-0a9697fdc673" />
<img width="1920" height="839" alt="Screenshot (1031)" src="https://github.com/user-attachments/assets/ea5ea40a-81cb-4301-8c7a-61120e4ebe8b" />
<img width="1920" height="1080" alt="Screenshot (1032)" src="https://github.com/user-attachments/assets/87a1d906-c068-4c7c-9741-30fe70187442" />
<img width="1920" height="741" alt="Screenshot (1033)" src="https://github.com/user-attachments/assets/e35b3131-66c3-45cc-8675-001f536c86cb" />
<img width="1920" height="721" alt="Screenshot (1034)" src="https://github.com/user-attachments/assets/faa9cc0f-7024-41b4-8a3d-fc1acf8d7c42" />
<img width="1920" height="1080" alt="Screenshot (1035)" src="https://github.com/user-attachments/assets/ba7cdd1b-640f-40da-8d08-7efe53a84b00" />
<img width="1920" height="830" alt="Screenshot (1036)" src="https://github.com/user-attachments/assets/b6beaa3f-eed1-4851-851d-3e47345a27d3" />
<img width="1920" height="960" alt="Screenshot (1037)" src="https://github.com/user-attachments/assets/cf2c48c8-c347-40dc-8663-af68a8ef562b" />
<img width="1920" height="994" alt="Screenshot (1038)" src="https://github.com/user-attachments/assets/5904777e-57b0-44de-8d77-0e04e6183e38" />
<img width="1920" height="994" alt="Screenshot (1039)" src="https://github.com/user-attachments/assets/9b2aeb49-a66a-457a-88a1-9ffd6c95cb74" />
<img width="1920" height="927" alt="Screenshot (1040)" src="https://github.com/user-attachments/assets/084ddb91-0547-438c-8e08-3d0dac9fc026" />











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
<img width="1736" height="740" alt="Screenshot (996)" src="https://github.com/user-attachments/assets/2fe1f85a-9f42-4d42-97e5-9e1151560f01" />
<img width="821" height="748" alt="Screenshot (997)" src="https://github.com/user-attachments/assets/f181f862-b055-495d-b2b8-7f1a35e546b6" />

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
