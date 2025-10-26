# Cyber Security Standard and Frameworks

## Cyber Kill Chain (R,W,D,E,I,C,A) 
The term kill chain is a military concept related to the structure of an attack.  It consists of target identification, decision and order to attack the target, and finally the target destruction.Lockheed Martin, a global security and aerospace company, that established the Cyber Kill Chain® framework for the cybersecurity industry in 2011 based on the military concept. The framework defines the steps used by adversaries or malicious actors in cyberspace. <br>

To succeed, an adversary needs to go through all phases of the Kill Chain. We will go through the attack phases and help you better understand adversaries and their techniques used in the attack to defend yourself. <br>

The Cyber Kill Chain will help you understand and protect against ransomware attacks, security breaches as well as Advanced Persistent Threats (APTs). You can use the Cyber Kill Chain to assess your network and system security by identifying missing security controls and closing certain security gaps based on your company's infrastructure. <br>

By understanding the Kill Chain as a SOC Analyst, Security Researcher, Threat Hunter, or Incident Responder, you will be able to recognize the intrusion attempts and understand the intruder's goals and objectives. <br>

![Screenshot (732)](https://github.com/user-attachments/assets/bbd3a101-c704-41cf-b704-0e2564bbfd32)

**Phases of Cyber Kill Chain** <br>
**1. Reconnaissance** <br> - Reconnaissance(Information Gathering) is discovering and collecting information on the system and the victim.OSINT (Open-Source Intelligence) also falls under reconnaissance.The attacker needs to study the victim by collecting every available piece of information on the company and its employees, such as the company's size, email addresses, phone numbers from publicly available resources to determine the best target for the attack.  <br>

Email harvesting is the process of obtaining email addresses from public, paid, or free services. An attacker can use email-address harvesting for a phishing attack (a type of social-engineering attack used to steal sensitive data, including login credentials and credit card numbers). The attacker will have a big arsenal of tools available for reconnaissance purposes. <br>

theHarvester - other than gathering emails, this tool is also capable of gathering names, subdomains, IPs, and URLs using multiple public data sources <br>
Hunter.io - this is  an email hunting tool that will let you obtain contact information associated with the domain <br>
OSINT Framework - OSINT Framework provides the collection of OSINT tools based on various categories <br>

An attacker would also use social media websites such as LinkedIn, Facebook, Twitter, and Instagram to collect information on a specific victim he would want to attack or the company. The information found on social media can be beneficial for an attacker to conduct a phishing attack. <br>

**2. Weaponization** <br> -  crafting a "weapon of destruction". Intruder creates remote access malware weapon, such as a virus or worm, tailored to one or more vulnerabilities. <br>

**Malware** is a program or software that is designed to damage, disrupt, or gain unauthorized access to a computer. <br>

An **exploit** is a program or a code that takes advantage of the vulnerability or flaw in the application or system. <br>

A **payload** is a malicious code that the attacker runs on the system. <br>

Create an infected Microsoft Office document containing a malicious macro or VBA (Visual Basic for Applications) scripts. If you want to learn about macro and VBA, please refer to the article "Intro to Macros and VBA For Script Kiddies" by TrustedSec. <br>
An attacker can create a malicious payload or a very sophisticated worm, implant it on the USB drives, and then distribute them in public. An example of the virus.  <br>
An attacker would choose Command and Control (C2) techniques for executing the commands on the victim's machine or deliver more payloads. You can read more about the C2 techniques on MITRE ATT&CK. <br>
An attacker would select a backdoor implant (the way to access the computer system, which includes bypassing the security mechanisms). <br>

**3. Delivery** <br> - Intruder transmits weapon to target or decides to choose the method for transmitting the payload or the malware. (e.g., via e-mail attachments, websites or USB drives).<br>

- Phishing email
- Distributing infected USB drives in public places like coffee shops, parking lots, or on the street.
- Watering hole attack.(An attack where a legitimate website frequently visited by a target is compromised and geared towards infecting visitors with malware.)This type of attack is called a drive-by download. An example can be a malicious pop-up asking to download a fake Browser extension.


**4. Exploitation** <br> - To gain access to the system, an attacker needs to exploit the vulnerability. <br> After gaining access to the system, the malicious actor could exploit software, system, or server-based vulnerabilities to escalate the privileges or move laterally through the network. <br>

**lateral movement** refers to the techniques that a malicious actor uses after gaining initial access to the victim's machine to move deeper into a network to obtain sensitive data. <br> 

Examples of Exploitations<br>
- The victim triggers the exploit by opening the email attachment or clicking on a malicious link.
- Using a zero-day exploit.
- Exploit software, hardware, or even human vulnerabilities. 
- An attacker triggers the exploit for server-based vulnerabilities.
  
**5. Installation** <br> - Malware weapon installs an access point (e.g., "backdoor"  A backdoor is also known as an access point.) usable by the intruder, the backdoor lets an attacker bypass security measures and hide the access.That is when the attacker needs to install a persistent backdoor. A persistent backdoor will let the attacker access the system he compromised in the past <br>

The persistence can be achieved through:<br>
- Installing web shell on the webserver.  A web shell is a malicious script written in web development programming languages such as ASP, PHP, or JSP used by an attacker to maintain access to the compromised system. Because of the web shell simplicity and file formatting (.php, .asp, .aspx, .jsp, etc.) can be difficult to detect and might be classified as benign.
  
- Installing a backdoor on the victim's machine. For example, the attacker can use Meterpreter to install a backdoor on the victim's machine. Meterpreter is a Metasploit Framework payload that gives an interactive shell from which an attacker can interact with the victim's machine remotely and execute the malicious code.
  
- Creating or modifying Windows services. This technique is known as T1543.003 on MITRE ATT&CK (MITRE ATT&CK® is a knowledge base of adversary tactics and techniques based on real-world scenarios). An attacker can create or modify the Windows services to execute the malicious scripts or payloads regularly as a part of the persistence. An attacker can use the tools like sc.exe (sc.exe lets you Create, Start, Stop, Query, or Delete any Windows Service) and Reg to modify service configurations. The attacker can also masquerade the malicious payload by using a service name that is known to be related to the Operating System or legitimate software.
  
- Adding the entry to the "run keys" for the malicious payload in the Registry or the Startup Folder. By doing that, the payload will execute each time the user logs in on the computer. According to MITRE ATT&CK, there is a startup folder location for individual user accounts and a system-wide startup folder that will be checked no matter what user account logs in.

In this phase, the attacker can also use the Timestomping technique to avoid detection by the forensic investigator and also to make the malware appear as a part of a legitimate program. The Timestomping technique lets an attacker modify the file's timestamps, including the modify, access, create and change times. <br>

**6. Command & Control (C2)** <br> - Malware enables intruder to have "hands on the keyboard" persistent access to the target network.The infected host will consistently communicate with the C2 server; that is also where the beaconing term came from.<br>

After getting persistence and executing the malware on the victim's machine, "Megatron" opens up the C2 (Command and Control) channel through the malware to remotely control and manipulate the victim. This term is also known as C&C or C2 Beaconing as a type of malicious communication between a C&C server and malware on the infected host.<br>

The most common C2 channels used by adversaries nowadays: <br>

- The protocols HTTP on port 80 and HTTPS on port 443 - this type of beaconing blends the malicious traffic with the legitimate traffic and can help the attacker evade firewalls.  
- DNS (Domain Name Server). The infected machine makes constant DNS requests to the DNS server that belongs to an attacker, this type of C2 communication is also known as DNS Tunneling.

Important to note that an adversary or another compromised host can be the owner of the C2 infrastructure.<br>

**7. Action on Objectives** <br> - Intruder takes action to achieve their goals, such as data exfiltration, data destruction, or encryption for ransom.

- Collect the credentials from users.
- Perform privilege escalation (gaining elevated access like domain administrator access from a workstation by exploiting the misconfiguration).
- Internal reconnaissance (for example, an attacker gets to interact with internal software to find its vulnerabilities).
- Lateral movement through the company's environment.
- Collect and exfiltrate sensitive data.
- Deleting the backups and shadow copies. Shadow Copy is a Microsoft technology that can create backup copies, snapshots of computer files, or volumes. 
- Overwrite or corrupt data.
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
## MITRE ATT & CK (Adversarial Tactics, Techniques, and Common Knowledge)
MITRE ATT&CK(Adversarial Tactics, Techniques, and Common Knowledge) framework, is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. It helps to map and understand attacker behaviors during the kill chain.

It is a guideline for classifying and describing cyberattacks and intrusions. It was created by the Mitre Corporation and released in 2013 and used for threat modeling and profiling. The framework is an alternative to the cyber kill chain developed by Lockheed Martin.

|Tactics| Techniques|
|----|-----|
|Reconnaissance|Active Scanning, Phishing for information|

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## HIPPA (Health Insurance Portability and Accountability Act)
Healthcare, health insurance, medical research.

HIPAA (Health Insurance Portability and Accountability Act) is a federal law that the U.S. passed in 1996 for the healthcare industry. Its main aim is to protect the privacy and security of a patient’s health information. 

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## GDPR (General Data Protection Regulation)
**Any organization handling EU citizen personal data** <br>

The GDPR is a data protection law implemented by the EU in May 2018 to protect personal data. Personal data is "Any data associated with an individual that can be utilised to identify them either directly or indirectly".

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## PCI-DSS (Payment Card Industry Data Security Standard)
Retail, e-commerce, financial services

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## ISO/IEC 270001 (International Standard Organizations / International Electrotechnical Commission)
International Standard for Information Security Management System(ISMS), applicable to all industries especially technology, finance, healthcare, manufacturing

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## NIST Cybersecurity Framework (CSF) National Institute of Standards and Technology (NIST)
**Sector - Energy, finance, healthcare, government** <br>



-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## OWASP TOP 10  Open Web Application Security Project (OWASP)

Software development, application security, cybersecurity consulting

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## SOC2 (System and Organization Controls 2)
Cloud services, SaaS, technology providers

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## ITIL (Information Technology Infrastructure Library)
IT service management, managed service providers, enterprise and IT Consulting.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## COBIT (Control Objectives for Information and Related Technologies)
Enterprise IT management, IT consulting, finance

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## CIS Controls (Center for Internet Security)
Cross-industry, especially for practical cybersecurity implementation

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## CMMC (Cybersecurity Maturity Model Certification)
Defense contractors, aerospace, military technology

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## FISMA (Federal Information Security Management Act)
U.S. government agencies, federal contractors, defense

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## BSI IT GrundSchutz

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## ITSM
IT service management

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## SANS top 25
-------------------------------------------------------------------------------------------------------------------------------------------------------------------

## KRITIS (Kritische Infrastrukturen or Critical Infrastructures)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## Gramm-Leach-Bliley Act (GLBA)

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## PDCA

-------------------------------------------------------------------------------------------------------------------------------------------------------------------
## STRIDE

-------------------------------------------------------
## 
-------------------------------------
## SMART
