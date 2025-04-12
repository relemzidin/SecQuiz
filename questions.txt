// questions.js
// Store all your Security+ questions in this array.

const quizData = [
    {
        question: "Which of the following ensures that data has not been tampered with during transit?",
        options: ["Confidentiality", "Integrability", "Availability", "Integrity"],
        correctAnswer: "Integrity"
    },
    {
        question: "What type of malware often disguises itself as legitimate software?",
        options: ["Worm", "Trojan Horse", "Spyware", "Ransomware"],
        correctAnswer: "Trojan Horse"
    },
    {
        question: "Which security principle prevents a user from denying that they performed a specific action?",
        options: ["Authentication", "Authorization", "Non-repudiation", "Accounting"],
        correctAnswer: "Non-repudiation"
    },
    {
        question: "A firewall that inspects the entire packet, including the application data, is known as what type of firewall?",
        options: ["Packet Filtering", "Circuit-Level Gateway", "Stateful Inspection", "Application-Level Gateway (Proxy)"],
        correctAnswer: "Application-Level Gateway (Proxy)"
    },
    {
        question: "Which encryption type uses a different key for encryption and decryption?",
        options: ["Symmetric", "Asymmetric", "Hashing", "Stream Cipher"],
        correctAnswer: "Asymmetric"
    },
     {
        question: "What is the primary purpose of implementing RAID 5?",
        options: ["Increase read/write speed significantly", "Provide fault tolerance with disk striping and parity", "Create an exact mirror of a disk", "Reduce storage costs"],
        correctAnswer: "Provide fault tolerance with disk striping and parity"
    },
     {
        question: "Which of the following is a common social engineering technique?",
        options: ["SQL Injection", "Cross-Site Scripting (XSS)", "Phishing", "Denial of Service (DoS)"],
        correctAnswer: "Phishing"
    },
    {
        question: "What does the acronym 'VPN' stand for?",
        options: ["Virtual Private Network", "Verified Public Network", "Virtual Public Node", "Verified Private Node"],
        correctAnswer: "Virtual Private Network"
    },
    {
        question: "In cryptography, what is a 'salt' primarily used for?",
        options: ["To increase encryption speed", "To prevent rainbow table attacks on stored passwords", "To generate public keys", "To ensure data integrity"],
        correctAnswer: "To prevent rainbow table attacks on stored passwords"
    },
    {
        question: "Which authentication factor is represented by a fingerprint scan?",
        options: ["Something you know", "Something you have", "Something you are", "Somewhere you are"],
        correctAnswer: "Something you are"
    },
    {
        question: "What type of security assessment involves actively trying to exploit vulnerabilities?",
        options: ["Vulnerability Scanning", "Penetration Testing", "Risk Assessment", "Security Audit"],
        correctAnswer: "Penetration Testing"
    },
	{
        question: "A user receives an email claiming to be from their bank, asking them to click a link and verify their account details due to suspicious activity. This is an example of:",
        options: ["Vishing", "Smishing", "Phishing", "Tailgating"],
        correctAnswer: "Phishing"
    },
    {
        question: "What type of malware encrypts files on a user's computer and demands payment for the decryption key?",
        options: ["Worm", "Trojan Horse", "Spyware", "Ransomware"],
        correctAnswer: "Ransomware"
    },
    {
        question: "An attacker sends a flood of SYN packets to a target server, overwhelming its ability to respond to legitimate connection requests. What type of attack is this?",
        options: ["Man-in-the-Middle (MitM)", "SYN Flood (DoS)", "SQL Injection", "Cross-Site Scripting (XSS)"],
        correctAnswer: "SYN Flood (DoS)"
    },
    {
        question: "Which social engineering technique involves an attacker looking over a person's shoulder to obtain information like passwords or PINs?",
        options: ["Impersonation", "Shoulder Surfing", "Dumpster Diving", "Hoax"],
        correctAnswer: "Shoulder Surfing"
    },
    {
        question: "A vulnerability that is exploited by attackers before the vendor is aware of it or has released a patch is known as a:",
        options: ["Zero-Day Exploit", "Buffer Overflow", "Race Condition", "Logic Bomb"],
        correctAnswer: "Zero-Day Exploit"
    },
    {
        question: "What kind of attack inserts malicious commands into database queries, often via web forms?",
        options: ["Cross-Site Scripting (XSS)", "XML Injection", "SQL Injection", "Command Injection"],
        correctAnswer: "SQL Injection"
    },
    {
        question: "Malware that replicates itself across networks without user intervention is classified as a:",
        options: ["Virus", "Trojan", "Worm", "Rootkit"],
        correctAnswer: "Worm"
    },
    {
        question: "An attacker sets up a fake Wi-Fi hotspot in a public place, hoping users will connect to it to steal their data. This is known as:",
        options: ["Evil Twin", "Bluejacking", "War Driving", "IV Attack"],
        correctAnswer: "Evil Twin"
    },
    {
        question: "Which attack technique specifically targets high-profile executives or senior management within an organization?",
        options: ["Phishing", "Spear Phishing", "Whaling", "Vishing"],
        correctAnswer: "Whaling"
    },
    {
        question: "Software secretly installed on a user's computer to gather information without their consent is called:",
        options: ["Adware", "Ransomware", "Spyware", "Keylogger"],
        correctAnswer: "Spyware" // Keylogger is a *type* of spyware
    },

    // --- Domain 2: Architecture and Design ---
    {
        question: "What network security zone is typically established to host public-facing servers like web and email servers, isolating them from the internal network?",
        options: ["Intranet", "Extranet", "DMZ (Demilitarized Zone)", "Honeynet"],
        correctAnswer: "DMZ (Demilitarized Zone)"
    },
    {
        question: "Which cloud computing model provides customers with hardware resources (processing, storage, networking) but requires them to manage the OS and applications?",
        options: ["SaaS (Software as a Service)", "PaaS (Platform as a Service)", "IaaS (Infrastructure as a Service)", "DaaS (Desktop as a Service)"],
        correctAnswer: "IaaS (Infrastructure as a Service)"
    },
    {
        question: "Which security concept ensures that a system or resource is available and accessible to authorized users when needed?",
        options: ["Confidentiality", "Integrity", "Availability", "Non-repudiation"],
        correctAnswer: "Availability"
    },
    {
        question: "What is the primary purpose of using a VPN (Virtual Private Network)?",
        options: ["To increase internet speed", "To create a secure, encrypted connection over a public network", "To block malware", "To replace a firewall"],
        correctAnswer: "To create a secure, encrypted connection over a public network"
    },
    {
        question: "A hardware device designed to manage and protect digital encryption keys is known as a:",
        options: ["TPM (Trusted Platform Module)", "HSM (Hardware Security Module)", "CPU (Central Processing Unit)", "SSD (Solid State Drive)"],
        correctAnswer: "HSM (Hardware Security Module)"
    },
    {
        question: "Implementing redundant servers, network paths, and power supplies primarily supports which security goal?",
        options: ["Confidentiality", "Integrity", "Scalability", "Availability"],
        correctAnswer: "Availability"
    },
    {
        question: "Which secure network protocol is commonly used to provide secure remote login and command execution?",
        options: ["Telnet", "FTP", "HTTP", "SSH (Secure Shell)"],
        correctAnswer: "SSH (Secure Shell)"
    },
    {
        question: "In network segmentation, what is the purpose of creating VLANs (Virtual Local Area Networks)?",
        options: ["To physically separate networks", "To logically segment a network without changing physical wiring", "To increase bandwidth", "To encrypt all network traffic"],
        correctAnswer: "To logically segment a network without changing physical wiring"
    },
     {
        question: "Which security design principle advocates granting users only the permissions necessary to perform their job functions?",
        options: ["Defense in Depth", "Least Privilege", "Separation of Duties", "Security through Obscurity"],
        correctAnswer: "Least Privilege"
    },
     {
        question: "What technology allows multiple operating systems to run concurrently on a single physical machine?",
        options: ["Clustering", "Load Balancing", "Virtualization", "RAID"],
        correctAnswer: "Virtualization"
    },

    // --- Domain 3: Implementation ---
    {
        question: "Which type of encryption uses the same key for both encryption and decryption?",
        options: ["Asymmetric", "Symmetric", "Hashing", "Public Key"],
        correctAnswer: "Symmetric"
    },
    {
        question: "What is the main function of a hash algorithm (like SHA-256) in security?",
        options: ["To encrypt data for confidentiality", "To ensure data integrity by creating a fixed-size fingerprint", "To generate digital signatures", "To decrypt messages"],
        correctAnswer: "To ensure data integrity by creating a fixed-size fingerprint"
    },
    {
        question: "Which authentication factor is represented by a smart card or a security token?",
        options: ["Something you know (e.g., password)", "Something you have (e.g., token)", "Something you are (e.g., fingerprint)", "Somewhere you are (e.g., location)"],
        correctAnswer: "Something you have (e.g., token)"
    },
    {
        question: "What does PKI (Public Key Infrastructure) primarily manage?",
        options: ["Symmetric Keys", "User Passwords", "Digital Certificates", "Firewall Rules"],
        correctAnswer: "Digital Certificates"
    },
    {
        question: "Which wireless security protocol is currently considered the most secure for Wi-Fi networks?",
        options: ["WEP", "WPA", "WPA2 with TKIP", "WPA3"],
        correctAnswer: "WPA3"
    },
    {
        question: "A network device that filters traffic based on predefined rules, typically inspecting source/destination IP addresses and ports, is a:",
        options: ["Router", "Switch", "Firewall", "Load Balancer"],
        correctAnswer: "Firewall"
    },
    {
        question: "What is the primary purpose of implementing MFA (Multi-Factor Authentication)?",
        options: ["To simplify the login process", "To increase security by requiring multiple types of verification", "To replace passwords entirely", "To monitor user activity"],
        correctAnswer: "To increase security by requiring multiple types of verification"
    },
    {
        question: "Which security control detects malicious activity on a network and can potentially block it automatically?",
        options: ["IDS (Intrusion Detection System)", "IPS (Intrusion Prevention System)", "SIEM (Security Information and Event Management)", "Honeypot"],
        correctAnswer: "IPS (Intrusion Prevention System)"
    },
     {
        question: "In cryptography, what ensures that the sender of a message cannot later deny having sent it?",
        options: ["Confidentiality", "Integrity", "Authentication", "Non-repudiation"],
        correctAnswer: "Non-repudiation"
    },
     {
        question: "What type of system is specifically designed to attract and trap potential attackers, diverting them from legitimate targets?",
        options: ["Firewall", "Proxy Server", "Honeypot", "VPN Concentrator"],
        correctAnswer: "Honeypot"
    },

    // --- Domain 4: Operations and Incident Response ---
    {
        question: "What is the first phase in a standard incident response process?",
        options: ["Containment", "Eradication", "Identification", "Preparation"],
        correctAnswer: "Preparation"
    },
    {
        question: "A system that aggregates and analyzes log data from various sources to detect security threats is known as:",
        options: ["Syslog Server", "SIEM (Security Information and Event Management)", "NIDS (Network Intrusion Detection System)", "Packet Sniffer"],
        correctAnswer: "SIEM (Security Information and Event Management)"
    },
    {
        question: "Regularly applying software updates and patches is a critical part of which security process?",
        options: ["Incident Response", "Vulnerability Management", "Risk Assessment", "Forensic Analysis"],
        correctAnswer: "Vulnerability Management"
    },
    {
        question: "What type of backup involves copying only the data that has changed since the *last full backup*?",
        options: ["Full Backup", "Incremental Backup", "Differential Backup", "Snapshot"],
        correctAnswer: "Differential Backup"
    },
    {
        question: "The process of isolating affected systems during a security incident to prevent further spread is called:",
        options: ["Identification", "Eradication", "Recovery", "Containment"],
        correctAnswer: "Containment"
    },
    {
        question: "What metric defines the maximum amount of time a system or service can be offline after a failure or disaster?",
        options: ["RPO (Recovery Point Objective)", "RTO (Recovery Time Objective)", "MTBF (Mean Time Between Failures)", "MTTR (Mean Time To Repair)"],
        correctAnswer: "RTO (Recovery Time Objective)"
    },
    {
        question: "Which of the following is crucial for ensuring the admissibility of digital evidence in court?",
        options: ["Hashing", "Encryption", "Chain of Custody", "Steganography"],
        correctAnswer: "Chain of Custody"
    },
    {
        question: "Reviewing logs, network traffic, and system configurations to understand how a security incident occurred is part of which phase?",
        options: ["Preparation", "Containment", "Lessons Learned / Post-Incident Activity", "Identification"],
        correctAnswer: "Lessons Learned / Post-Incident Activity" // Also part of Identification/Analysis, but Lessons Learned is a distinct phase focusing on review.
    },
     {
        question: "What is the primary goal of Disaster Recovery Planning (DRP)?",
        options: ["To prevent all disasters", "To ensure data confidentiality", "To restore IT operations at an alternate site after a catastrophe", "To perform daily backups"],
        correctAnswer: "To restore IT operations at an alternate site after a catastrophe"
    },
     {
        question: "Which activity involves actively scanning systems and networks to identify potential security weaknesses?",
        options: ["Penetration Testing", "Vulnerability Scanning", "Log Monitoring", "Risk Assessment"],
        correctAnswer: "Vulnerability Scanning"
    },

    // --- Domain 5: Governance, Risk, and Compliance (GRC) ---
    {
        question: "A document that outlines the overall security goals and acceptable practices for an organization is a:",
        options: ["Procedure", "Standard", "Guideline", "Policy"],
        correctAnswer: "Policy"
    },
    {
        question: "Which risk response strategy involves taking action to reduce the likelihood or impact of a risk?",
        options: ["Acceptance", "Avoidance", "Transference", "Mitigation"],
        correctAnswer: "Mitigation"
    },
    {
        question: "Training users about phishing scams, strong password creation, and safe web browsing habits is part of:",
        options: ["Incident Response", "Security Awareness Training", "Vulnerability Management", "Compliance Auditing"],
        correctAnswer: "Security Awareness Training"
    },
    {
        question: "Regulations like GDPR (General Data Protection Regulation) primarily focus on protecting:",
        options: ["Intellectual Property", "Financial Data", "Personal Data / PII (Personally Identifiable Information)", "Classified Government Information"],
        correctAnswer: "Personal Data / PII (Personally Identifiable Information)"
    },
    {
        question: "The process of identifying, assessing, and prioritizing potential threats and vulnerabilities is known as:",
        options: ["Business Impact Analysis (BIA)", "Risk Assessment", "Compliance Check", "Security Audit"],
        correctAnswer: "Risk Assessment"
    },
    {
        question: "What legal concept requires an organization to take reasonable measures to protect its assets and stakeholders?",
        options: ["Due Diligence", "Due Process", "Due Care", "Non-repudiation"],
        correctAnswer: "Due Care"
    },
     {
        question: "Transferring risk to a third party, such as by purchasing insurance, is an example of which risk response strategy?",
        options: ["Risk Acceptance", "Risk Avoidance", "Risk Mitigation", "Risk Transference"],
        correctAnswer: "Risk Transference"
    },
     {
        question: "A mandatory, step-by-step instruction that employees must follow to perform a specific task is a:",
        options: ["Policy", "Standard", "Guideline", "Procedure"],
        correctAnswer: "Procedure"
    },
     {
        question: "Personally Identifiable Information (PII) includes data like:",
        options: ["Server IP addresses", "Company profit margins", "Social Security Number", "Operating system version"],
        correctAnswer: "Social Security Number"
    },
     {
        question: "What is the purpose of an AUP (Acceptable Use Policy)?",
        options: ["To define how company assets and networks should be used by employees", "To outline the incident response plan", "To detail backup procedures", "To specify encryption standards"],
        correctAnswer: "To define how company assets and networks should be used by employees"
    },
    {
        question: "According to the SY0-701 overview, which type of security control is designed to identify attacks while they are in progress?",
        options: ["Preventative", "Detective", "Corrective", "Deterrent"],
        correctAnswer: "Detective"
    },
    {
        question: "Which element of the CIA Triad ensures that data is accurate and protected from unauthorized modification?",
        options: ["Confidentiality", "Integrity", "Availability", "Authentication"],
        correctAnswer: "Integrity"
    },
    {
        question: "What security concept provides irrefutable proof of data origin and integrity, preventing individuals from denying their actions?",
        options: ["Confidentiality", "Authorization", "Non-repudiation", "Accounting"],
        correctAnswer: "Non-repudiation"
    },
    {
        question: "In the AAA framework, what process determines the actions an authenticated user is allowed to perform?",
        options: ["Authentication", "Authorization", "Accounting", "Auditing"],
        correctAnswer: "Authorization"
    },
    {
        question: "What proactive security technique involves comparing the current security posture against a desired state to identify weaknesses?",
        options: ["Incident Response", "Gap Analysis", "Change Management", "Zero Trust Implementation"],
        correctAnswer: "Gap Analysis"
    },
    {
        question: "What is the core principle of the Zero Trust security strategy?",
        options: ["Trust but verify", "Trust internal users implicitly", "Never trust, always verify", "Verify once, trust always"],
        correctAnswer: "Never trust, always verify"
    },
    {
        question: "Using locks and surveillance systems to prevent unauthorized access to facilities falls under which security domain?",
        options: ["Logical Security", "Network Security", "Physical Security", "Operational Security"],
        correctAnswer: "Physical Security"
    },
    {
        question: "Deploying a honeypot to attract and analyze attacker behavior is an example of which type of security tactic?",
        options: ["Disruption", "Hardening", "Deception", "Mitigation"],
        correctAnswer: "Deception"
    },
    {
        question: "What is the primary purpose of a formal change management process in IT?",
        options: ["To increase system performance", "To minimize risk during updates and modifications", "To track user activity", "To discover zero-day vulnerabilities"],
        correctAnswer: "To minimize risk during updates and modifications"
    },
    {
        question: "Which cryptographic infrastructure uses digital certificates and pairs of keys (public and private) for secure communication?",
        options: ["Hashing Algorithm", "Symmetric Encryption", "Public Key Infrastructure (PKI)", "Steganography"],
        correctAnswer: "Public Key Infrastructure (PKI)"
    },
    {
        question: "Which type of encryption uses the same key for both encryption and decryption?",
        options: ["Asymmetric", "Symmetric", "Hashing", "Public Key"],
        correctAnswer: "Symmetric"
    },
    {
        question: "What is the term for securing data while it is being transmitted over a network, often using protocols like TLS/SSL?",
        options: ["Data at Rest Encryption", "Data in Use Encryption", "Data in Transit Encryption", "Database Encryption"],
        correctAnswer: "Data in Transit Encryption"
    },
    {
        question: "Hardware Security Modules (HSMs) and Trusted Platform Modules (TPMs) are primarily used for what purpose?",
        options: ["Increasing network bandwidth", "Storing user passwords", "Securely storing and managing cryptographic keys", "Performing data backups"],
        correctAnswer: "Securely storing and managing cryptographic keys"
    },
    {
        question: "Which obfuscation technique involves replacing sensitive data with non-sensitive placeholders?",
        options: ["Steganography", "Data Masking", "Tokenization", "Encryption"],
        correctAnswer: "Tokenization"
    },
    {
        question: "What cryptographic process creates a unique fixed-size fingerprint of data, primarily used to ensure data integrity?",
        options: ["Encryption", "Hashing", "Digital Signature", "Steganography"],
        correctAnswer: "Hashing"
    },
    {
        question: "What combines hashing with asymmetric encryption to verify sender identity and ensure data hasn't been tampered with?",
        options: ["Symmetric Key", "Message Digest", "Digital Signature", "Certificate Signing Request (CSR)"],
        correctAnswer: "Digital Signature"
    },
    {
        question: "What is the primary role of a digital certificate in online communications?",
        options: ["To encrypt all website content", "To act as an electronic credential verifying identity", "To guarantee website uptime", "To replace passwords"],
        correctAnswer: "To act as an electronic credential verifying identity"
    },
    {
        question: "What is a Certificate Signing Request (CSR)?",
        options: ["A request to revoke a compromised certificate", "A method for checking certificate status", "The process of generating a public/private key pair", "A formal request sent to a Certificate Authority to get a digital certificate"],
        correctAnswer: "A formal request sent to a Certificate Authority to get a digital certificate"
    },
    {
        question: "Which protocol or mechanism allows clients to efficiently check if a server's digital certificate has been revoked?",
        options: ["CSR", "PKI", "OCSP Stapling", "TLS Handshake"],
        correctAnswer: "OCSP Stapling"
    },
     {
        question: "Which security control category aims to discourage potential attackers from attempting an attack in the first place?",
        options: ["Preventative", "Detective", "Corrective", "Deterrent"],
        correctAnswer: "Deterrent"
    },

    // --- Section 2: Threats, Vulnerabilities, and Mitigations ---
    {
        question: "Which type of threat actor is typically characterized by having significant resources and focusing on cyber espionage or warfare?",
        options: ["Organized Crime", "Hacktivist", "Nation State", "Shadow IT"],
        correctAnswer: "Nation State"
    },
    {
        question: "Unauthorized IT systems or software used within an organization without explicit approval are referred to as:",
        options: ["Legacy Systems", "Embedded Systems", "Shadow IT", "Honeypots"],
        correctAnswer: "Shadow IT"
    },
    {
        question: "An attacker compromising websites frequently visited by a specific group to infect them is known as what type of attack?",
        options: ["Phishing", "Impersonation", "Watering Hole Attack", "Buffer Overflow"],
        correctAnswer: "Watering Hole Attack"
    },
    {
        question: "What type of vulnerability occurs when an application doesn't properly handle the size of input, potentially allowing attackers to overwrite memory?",
        options: ["Race Condition", "SQL Injection", "Buffer Overflow", "Cross-Site Scripting (XSS)"],
        correctAnswer: "Buffer Overflow"
    },
    {
        question: "Injecting malicious SQL code into a web form to manipulate a backend database is characteristic of which attack?",
        options: ["Cross-Site Scripting (XSS)", "SQL Injection", "DLL Injection", "Directory Traversal"],
        correctAnswer: "SQL Injection"
    },
    {
        question: "Exploiting browser vulnerabilities to inject malicious scripts into a trusted website, which then execute on a victim's browser, is known as:",
        options: ["SQL Injection", "Cross-Site Scripting (XSS)", "Buffer Overflow", "VM Escape"],
        correctAnswer: "Cross-Site Scripting (XSS)"
    },
    {
        question: "A vulnerability that allows an attacker to break out of a virtual machine and potentially access the host system is called:",
        options: ["Resource Reuse", "VM Escape", "Containerization Flaw", "Hypervisor Attack"],
        correctAnswer: "VM Escape"
    },
    {
        question: "Weaknesses introduced through the network of suppliers and vendors an organization relies on are categorized as:",
        options: ["Cloud Vulnerabilities", "Misconfiguration Vulnerabilities", "Supply Chain Vulnerabilities", "Zero-Day Vulnerabilities"],
        correctAnswer: "Supply Chain Vulnerabilities"
    },
    {
        question: "A previously unknown vulnerability in software or hardware for which no patch or fix currently exists is called a:",
        options: ["Legacy Vulnerability", "Zero-Day Vulnerability", "Misconfiguration", "Race Condition"],
        correctAnswer: "Zero-Day Vulnerability"
    },
    {
        question: "Malware that replicates itself without requiring user interaction, often spreading across networks, is known as a:",
        options: ["Trojan Horse", "Spyware", "Worm", "Logic Bomb"],
        correctAnswer: "Worm"
    },
    {
        question: "What type of malware executes its malicious payload only when specific conditions are met (e.g., a certain date)?",
        options: ["Keylogger", "Rootkit", "Logic Bomb", "Fileless Virus"],
        correctAnswer: "Logic Bomb"
    },
    {
        question: "Malware designed to hide its presence or other malicious software from the operating system and security tools is a:",
        options: ["Worm", "Spyware", "Rootkit", "Bloatware"],
        correctAnswer: "Rootkit"
    },
    {
        question: "An attack aimed at overwhelming a service or network resource to make it unavailable to legitimate users is known as:",
        options: ["On-Path Attack", "Replay Attack", "Denial of Service (DoS)", "Privilege Escalation"],
        correctAnswer: "Denial of Service (DoS)"
    },
    {
        question: "An attack where the adversary secretly intercepts and possibly alters communications between two parties is called:",
        options: ["Denial of Service (DoS)", "Replay Attack", "On-Path Attack", "DNS Spoofing"],
        correctAnswer: "On-Path Attack"
    },
    {
        question: "Capturing legitimate network traffic and retransmitting it later to gain unauthorized access is known as a:",
        options: ["Replay Attack", "Downgrade Attack", "Session Hijacking", "On-Path Attack"],
        correctAnswer: "Replay Attack"
    },
    {
        question: "An attacker gaining higher-level permissions than initially authorized is an example of which application attack?",
        options: ["Directory Traversal", "Privilege Escalation", "Input Validation Failure", "Code Injection"],
        correctAnswer: "Privilege Escalation"
    },
    {
        question: "Which type of cryptographic attack forces a system to abandon a higher-security mode of communication in favor of an older, less secure mode?",
        options: ["Hash Collision", "Brute Force Attack", "Downgrade Attack", "Birthday Attack"],
        correctAnswer: "Downgrade Attack"
    },
    {
        question: "Trying a large number of common or weak passwords against many user accounts is known as what type of password attack?",
        options: ["Brute Force", "Dictionary Attack", "Password Spraying", "Rainbow Table Attack"],
        correctAnswer: "Password Spraying"
    },
    {
        question: "Forensic artifacts or pieces of data that indicate a system or network has been compromised are known as:",
        options: ["Threat Intelligence Feeds", "Vulnerability Scans", "Indicators of Compromise (IOCs)", "Security Baselines"],
        correctAnswer: "Indicators of Compromise (IOCs)"
    },
    {
        question: "Dividing a network into isolated segments and using Access Control Lists (ACLs) are examples of which mitigation technique?",
        options: ["Hardening", "Encryption", "Segmentation and Access Control", "Security Monitoring"],
        correctAnswer: "Segmentation and Access Control"
    },

    // --- Section 3: Security Architecture ---
    {
        question: "Managing and provisioning computing infrastructure using machine-readable definition files, rather than physical hardware configuration, is known as:",
        options: ["Virtualization", "Containerization", "Infrastructure as Code (IaC)", "Serverless Architecture"],
        correctAnswer: "Infrastructure as Code (IaC)"
    },
    {
        question: "Which cloud computing model allows developers to run code in response to events without managing the underlying servers?",
        options: ["Infrastructure as a Service (IaaS)", "Platform as a Service (PaaS)", "Software as a Service (SaaS)", "Serverless Architecture"],
        correctAnswer: "Serverless Architecture"
    },
    {
        question: "The technology that allows for the management and automation of networks using software, enabling logical segmentation in the cloud, is:",
        options: ["Virtual Private Network (VPN)", "Software-Defined Networking (SDN)", "Load Balancing", "Network Address Translation (NAT)"],
        correctAnswer: "Software-Defined Networking (SDN)"
    },
    {
        question: "Packaging an application along with its dependencies, libraries, and configuration files into a single unit is characteristic of:",
        options: ["Virtualization", "Containerization", "Embedded Systems", "Serverless Computing"],
        correctAnswer: "Containerization"
    },
    {
        question: "Designing a network to withstand failures and continue operating is focused on which infrastructure consideration?",
        options: ["Cost", "Scalability", "Resilience", "Responsiveness"],
        correctAnswer: "Resilience"
    },
    {
        question: "Defining distinct areas within a network infrastructure based on risk level and trust is known as creating:",
        options: ["Security Zones", "Jump Servers", "DMZs (Demilitarized Zones)", "Honeynets"],
        correctAnswer: "Security Zones"
    },
    {
        question: "Which network security device actively analyzes traffic and can block detected threats based on defined rules or signatures?",
        options: ["Sensor", "Collector", "Intrusion Prevention System (IPS)", "Load Balancer"],
        correctAnswer: "Intrusion Prevention System (IPS)"
    },
    {
        question: "A hardened, intermediary host used to securely access and manage devices in a separate security zone is called a:",
        options: ["Application Proxy", "Load Balancer", "Jump Server", "Network Sensor"],
        correctAnswer: "Jump Server"
    },
    {
        question: "Which type of firewall is specifically designed to protect web applications by filtering and monitoring HTTP traffic between clients and servers?",
        options: ["Packet Filtering Firewall", "Stateful Firewall", "Next-Generation Firewall (NGFW)", "Web Application Firewall (WAF)"],
        correctAnswer: "Web Application Firewall (WAF)"
    },
    {
        question: "Which technology creates secure, encrypted connections over a public network, often used for remote access?",
        options: ["Load Balancer", "Virtual Private Network (VPN)", "Software-Defined WAN (SD-WAN)", "Web Application Firewall (WAF)"],
        correctAnswer: "Virtual Private Network (VPN)"
    },
    {
        question: "What framework integrates network capabilities and cloud-native security functions like firewalls, SWG, and ZTNA into a unified cloud service?",
        options: ["SD-WAN", "VPN Concentrator", "Secure Access Service Edge (SASE)", "Intrusion Prevention System (IPS)"],
        correctAnswer: "Secure Access Service Edge (SASE)"
    },
    {
        question: "Applying security controls based on whether data is stored, being transmitted, or being actively processed relates to considering the:",
        options: ["Data Classification", "Data Types", "States of Data (Rest, Transit, Use)", "Data Ownership"],
        correctAnswer: "States of Data (Rest, Transit, Use)"
    },
    {
        question: "Grouping multiple servers together to act as a single system to provide redundancy and improved availability is known as:",
        options: ["Load Balancing", "Server Clustering", "Site Resiliency", "Capacity Planning"],
        correctAnswer: "Server Clustering"
    },
    {
        question: "Regularly validating the effectiveness of disaster recovery plans through simulated events is called:",
        options: ["Capacity Planning", "Recovery Testing", "Backup Verification", "Resiliency Auditing"],
        correctAnswer: "Recovery Testing"
    },
    {
        question: "What provides short-term backup power during an outage, allowing systems to shut down gracefully or generators to start?",
        options: ["Generator", "Power Distribution Unit (PDU)", "Uninterruptible Power Supply (UPS)", "Load Balancer"],
        correctAnswer: "Uninterruptible Power Supply (UPS)"
    },
    {
        question: "Which IEEE standard is commonly used for port-based network access control, often in conjunction with RADIUS or EAP?",
        options: ["IEEE 802.3 (Ethernet)", "IEEE 802.11 (Wi-Fi)", "IEEE 802.1X", "IEEE 802.1Q (VLANs)"],
        correctAnswer: "IEEE 802.1X"
    },
    {
        question: "The process of restricting data storage or access based on the physical location of users or data is known as implementing:",
        options: ["Data Masking", "Geographic Restrictions", "Tokenization", "Data Classification"],
        correctAnswer: "Geographic Restrictions"
    },
     {
        question: "Running multiple operating systems simultaneously on a single physical machine is achieved through:",
        options: ["Containerization", "Virtualization", "Serverless Computing", "Embedded Systems"],
        correctAnswer: "Virtualization"
    },
     {
        question: "A network of interconnected physical devices, vehicles, and other items embedded with electronics, software, sensors, and connectivity is known as:",
        options: ["Cloud Computing", "Internet of Things (IoT)", "Embedded Systems", "Software-Defined Networking (SDN)"],
        correctAnswer: "Internet of Things (IoT)"
    },
     {
        question: "Distributing incoming network traffic across multiple servers to improve performance and availability is the primary function of a:",
        options: ["Firewall", "Jump Server", "Load Balancer", "Application Proxy"],
        correctAnswer: "Load Balancer"
    },

    // --- Section 4: Security Operations ---
    {
        question: "Defining a known-good state for system configurations to help detect unauthorized changes is referred to as establishing:",
        options: ["Security Zones", "Secure Baselines", "Change Management", "Vulnerability Scans"],
        correctAnswer: "Secure Baselines"
    },
    {
        question: "Securing mobile devices, servers, and IoT devices by disabling unnecessary services and applying strict configurations is part of:",
        options: ["Asset Management", "Hardening Targets", "Vulnerability Scanning", "Incident Response"],
        correctAnswer: "Hardening Targets"
    },
    {
        question: "What framework provides centralized administration for securing, monitoring, and managing mobile devices like smartphones and tablets?",
        options: ["Bring Your Own Device (BYOD)", "Corporate Owned, Personally Enabled (COPE)", "Mobile Device Management (MDM)", "Extensible Authentication Protocol (EAP)"],
        correctAnswer: "Mobile Device Management (MDM)"
    },
    {
        question: "Which wireless security protocol is considered the most current and secure standard?",
        options: ["WEP", "WPA", "WPA2", "WPA3"],
        correctAnswer: "WPA3"
    },
    {
        question: "Validating user input to prevent malicious data from being processed by an application is a crucial aspect of:",
        options: ["Code Signing", "Sandboxing", "Input Validation", "Secure Cookies"],
        correctAnswer: "Input Validation"
    },
    {
        question: "Executing code or applications in a restricted, isolated environment to limit potential damage is known as:",
        options: ["Hardening", "Sandboxing", "Code Signing", "Input Validation"],
        correctAnswer: "Sandboxing"
    },
    {
        question: "The process of securely wiping data from storage media to ensure it is unrecoverable is called:",
        options: ["Asset Tracking", "Procurement", "Media Sanitization", "Physical Destruction"],
        correctAnswer: "Media Sanitization"
    },
    {
        question: "Gathering information about potential threats from publicly available sources like websites, forums, and social media is known as:",
        options: ["Penetration Testing", "Vulnerability Scanning", "Open Source Intelligence (OSINT)", "Dark Web Monitoring"],
        correctAnswer: "Open Source Intelligence (OSINT)"
    },
    {
        question: "Simulating real-world attacks to actively identify and exploit vulnerabilities in systems is the goal of:",
        options: ["Vulnerability Scanning", "Threat Intelligence Gathering", "Penetration Testing", "Security Auditing"],
        correctAnswer: "Penetration Testing"
    },
    {
        question: "Centrally collecting, analyzing, and correlating log data from various network devices and systems is the primary function of a:",
        options: ["Firewall", "Intrusion Detection System (IDS)", "Security Information and Event Management (SIEM)", "Data Loss Prevention (DLP)"],
        correctAnswer: "Security Information and Event Management (SIEM)"
    },
    {
        question: "Which set of email authentication standards (SPF, DKIM, DMARC) helps prevent email spoofing and phishing?",
        options: ["Email Encryption Standards", "Email Filtering Rules", "Email Authentication Methods", "Email Archiving Protocols"],
        correctAnswer: "Email Authentication Methods"
    },
    {
        question: "Technologies designed to monitor and prevent sensitive information from leaving an organization's control are known as:",
        options: ["File Integrity Monitoring (FIM)", "Data Loss Prevention (DLP)", "Endpoint Detection and Response (EDR)", "Web Filtering"],
        correctAnswer: "Data Loss Prevention (DLP)"
    },
    {
        question: "Advanced endpoint security solutions that monitor endpoint events, detect threats, and provide remediation capabilities are called:",
        options: ["Antivirus Software", "Host-based Intrusion Detection System (HIDS)", "Endpoint Detection and Response (EDR)", "Mobile Device Management (MDM)"],
        correctAnswer: "Endpoint Detection and Response (EDR)"
    },
    {
        question: "Granting users only the permissions necessary to perform their job functions adheres to the principle of:",
        options: ["Defense in Depth", "Least Privilege", "Separation of Duties", "Need to Know"],
        correctAnswer: "Least Privilege"
    },
    {
        question: "Which access control model assigns permissions based on roles or job functions within an organization?",
        options: ["Discretionary Access Control (DAC)", "Mandatory Access Control (MAC)", "Role-Based Access Control (RBAC)", "Attribute-Based Access Control (ABAC)"],
        correctAnswer: "Role-Based Access Control (RBAC)"
    },
    {
        question: "Requiring users to provide multiple types of verification (e.g., password + fingerprint) before granting access is known as:",
        options: ["Single Sign-On (SSO)", "Federated Identity Management", "Multifactor Authentication (MFA)", "Password Complexity"],
        correctAnswer: "Multifactor Authentication (MFA)"
    },
    {
        question: "Using scripts or specialized tools to automate repetitive security tasks like log analysis or incident response actions is an example of:",
        options: ["Manual Remediation", "Security Orchestration", "Tabletop Exercise", "Digital Forensics"],
        correctAnswer: "Security Orchestration"
    },
    {
        question: "What is the first phase in a typical incident response plan?",
        options: ["Containment", "Eradication", "Recovery", "Preparation"],
        correctAnswer: "Preparation"
    },
    {
        question: "Simulated incident response activities used to practice and refine procedures without affecting production systems are called:",
        options: ["Penetration Tests", "Vulnerability Scans", "Tabletop Exercises", "Security Audits"],
        correctAnswer: "Tabletop Exercises"
    },
    {
        question: "Maintaining a detailed log of how digital evidence was collected, handled, and stored to ensure its admissibility is known as:",
        options: ["Legal Hold", "E-discovery", "Chain of Custody", "Event Reporting"],
        correctAnswer: "Chain of Custody"
    },

    // --- Section 5: Security Program Management and Oversight ---
    {
        question: "Establishing the overall security processes, procedures, and guidelines for an organization falls under:",
        options: ["Risk Management", "Security Operations", "Security Governance", "Incident Response"],
        correctAnswer: "Security Governance"
    },
    {
        question: "A document outlining rules for how employees and users should use an organization's IT assets is known as an:",
        options: ["Information Security Policy", "Acceptable Use Policy (AUP)", "Business Continuity Plan (BCP)", "Disaster Recovery Plan (DRP)"],
        correctAnswer: "Acceptable Use Policy (AUP)"
    },
    {
        question: "The continuous process of identifying, assessing, prioritizing, and mitigating potential security risks is:",
        options: ["Compliance Monitoring", "Security Auditing", "Risk Management", "Vulnerability Management"],
        correctAnswer: "Risk Management"
    },
    {
        question: "Evaluating the security posture of external partners, suppliers, and vendors is specifically addressed by:",
        options: ["Internal Risk Assessment", "Third-Party Risk Management", "Compliance Auditing", "Security Awareness Training"],
        correctAnswer: "Third-Party Risk Management"
    },
    {
        question: "Ensuring an organization adheres to relevant laws, regulations, standards, and internal policies is the focus of:",
        options: ["Risk Assessment", "Security Compliance", "Incident Response Planning", "Change Management"],
        correctAnswer: "Security Compliance"
    },
    {
        question: "Independent evaluations, conducted either internally or by external parties, to verify the effectiveness of security controls are known as:",
        options: ["Risk Assessments", "Vulnerability Scans", "Audits and Assessments", "Penetration Tests"],
        correctAnswer: "Audits and Assessments"
    },
    {
        question: "Programs designed to educate all members of an organization about security threats and encourage secure behavior are called:",
        options: ["Compliance Training", "Technical Training", "Security Awareness Programs", "User Onboarding"],
        correctAnswer: "Security Awareness Programs"
    },
    {
        question: "Which aspect of security program management focuses specifically on ensuring employees, management, and partners understand their specific roles in maintaining security?",
        options: ["Risk Assessment", "Security Governance", "User Training", "Security Auditing"],
        correctAnswer: "User Training"
    },
    {
        question: "A plan focused on maintaining critical business functions during and after a disruption is a:",
        options: ["Incident Response Plan", "Business Continuity Plan (BCP)", "Acceptable Use Policy", "Information Security Policy"],
        correctAnswer: "Business Continuity Plan (BCP)"
    },
    {
        question: "Including a 'right-to-audit' clause in contracts with vendors is a strategy used within:",
        options: ["Internal Risk Management", "Security Awareness", "Compliance Monitoring", "Third-Party Risk Management"],
        correctAnswer: "Third-Party Risk Management"
    },

    // --- Additional Mixed Questions ---
    {
        question: "Which element of the CIA Triad is most concerned with ensuring timely and reliable access to data and services for authorized users?",
        options: ["Confidentiality", "Integrity", "Availability", "Non-repudiation"],
        correctAnswer: "Availability"
    },
    {
        question: "What does the 'Accounting' component of the AAA framework track?",
        options: ["User identity verification", "User permissions", "User activity and resource consumption", "User password strength"],
        correctAnswer: "User activity and resource consumption"
    },
    {
        question: "Which obfuscation technique involves hiding data within other non-secret data, like embedding text in an image file?",
        options: ["Tokenization", "Data Masking", "Encryption", "Steganography"],
        correctAnswer: "Steganography"
    },
    {
        question: "What is the primary motivation for organized crime threat actors?",
        options: ["Political disruption", "Espionage", "Financial gain", "Ideological protest"],
        correctAnswer: "Financial gain"
    },
    {
        question: "A vulnerability that arises due to the timing and sequence of operations in multi-threaded applications is known as a:",
        options: ["Buffer Overflow", "Race Condition", "Memory Leak", "SQL Injection"],
        correctAnswer: "Race Condition"
    },
    {
        question: "Which type of firewall examines traffic at Layer 7 (Application Layer) and can understand specific applications and protocols like HTTP and SMTP?",
        options: ["Packet Filtering Firewall", "Stateful Firewall", "Application-Level Gateway (Proxy)", "Circuit-Level Gateway"],
        correctAnswer: "Application-Level Gateway (Proxy)"
    },
    {
        question: "Protecting data stored on hard drives, databases, or backup tapes falls under securing data:",
        options: ["In Transit", "In Use", "At Rest", "In Memory"],
        correctAnswer: "At Rest"
    },
    {
        question: "What policy allows employees to use their personal devices for work purposes?",
        options: ["Corporate Owned, Business Only (COBO)", "Corporate Owned, Personally Enabled (COPE)", "Choose Your Own Device (CYOD)", "Bring Your Own Device (BYOD)"],
        correctAnswer: "Bring Your Own Device (BYOD)"
    },
    {
        question: "What is the purpose of code signing applications?",
        options: ["To encrypt the application's source code", "To ensure the software author's identity and that the code hasn't been tampered with", "To make the application run faster", "To hide the application from security scanners"],
        correctAnswer: "To ensure the software author's identity and that the code hasn't been tampered with"
    },
    {
        question: "Which IAM technology allows a user to log in once and gain access to multiple related systems without being prompted to log in again?",
        options: ["Multifactor Authentication (MFA)", "Federated Identity Management (FIM)", "Single Sign-On (SSO)", "Role-Based Access Control (RBAC)"],
        correctAnswer: "Single Sign-On (SSO)"
    }
];
    // Add many more Security+ questions here...
