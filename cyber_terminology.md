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

**3. Proxy** <br>
**4. Online Resources** <br>

   https://www.geeksforgeeks.org/computer-networks/what-is-vpn-how-it-works-types-of-vpn/
  https://en.wikipedia.org/wiki/Virtual_private_network#:~:text=In%20a%20VPN%2C%20a%20tunneling,one%20network%20host%20to%20another.&text=Host%2Dto%2Dnetwork%20VPNs%20are,office%20network%20and%20a%20datacenter.
   
   http://geeksforgeeks.org/computer-networks/types-of-virtual-private-network-vpn-and-its-protocols/
   
6.  
## Firewall Vs IDP/IDS Vs SIEM
**1. Firewall** <br>
**2. Resources** <br>
   https://tryhackme.com/room/firewallfundamentals
   https://www.geeksforgeeks.org/computer-networks/introduction-of-firewall-in-computer-network/
   https://www.geeksforgeeks.org/computer-networks/types-of-network-firewall/
   https://en.wikipedia.org/wiki/Firewall_(computing)
   https://www.checkpoint.com/cyber-hub/network-security/what-is-firewall/5-types-of-firewalls-which-one-do-you-need/
4. 
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
