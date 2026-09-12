# Kaevex Full Team AI Operations Center

The **Full Team** tab in Kaevex provides an integrated, multi-agent AI cybersecurity team running on **Groq Cloud API** (`llama-3.3-70b-versatile`) with sub-second inference speeds.

---

## The Five Specialized Cyber Teams

### 1. Red Team (Offensive Operations)
- **Role Focus**: Penetration testing, vulnerability weaponization, exploit development, reconnaissance, social engineering simulations, lateral movement planning.
- **Command Persona**: Elite offensive security researcher and ethical hacker.
- **Tools Simulated**: Nmap, Metasploit, Burp Suite, BloodHound, Impacket, Mimikatz.

### 2. Blue Team (Defensive & SOC)
- **Role Focus**: Incident response, threat hunting, SOC Tier 1/2 triage, SIEM correlation, malware analysis, digital forensics, and IOC extraction.
- **Command Persona**: Lead SOC Incident Responder and Threat Hunter.
- **Frameworks**: MITRE ATT&CK, NIST SP 800-61, SANS Incident Handling.

### 3. Purple Team (Adversary Emulation & Bridge)
- **Role Focus**: Joint exercise coordination, validating security control efficacy, adversary emulation, gap analysis, and detection engineering.
- **Command Persona**: Adversary Emulation Director bridging offensive techniques to detection rules (Sigma, YARA, Snort).

### 4. Yellow Team (Application Security & DevSecOps)
- **Role Focus**: SAST/DAST automation, secure code review, OWASP Top-10 remediation, container hardening, API security assessment.
- **Command Persona**: Enterprise AppSec Architect.
- **Standards**: OWASP ASVS, CWE Top-25, NIST Secure Software Development Framework (SSDF).

### 5. Green Team (Awareness & Compliance)
- **Role Focus**: Security policy drafting, phishing campaign design, user education, compliance framework mapping (ISO 27001, SOC 2, PCI-DSS, HIPAA).
- **Command Persona**: Chief Information Security Officer (CISO) Advisor.

---

## Technical Integration Details

- **API Endpoint**: `https://api.groq.com/openai/v1/chat/completions`
- **Model**: `llama-3.3-70b-versatile`
- **Transport**: Native WinHTTP (`WinHttpOpen`, `WinHttpConnect`, `WinHttpSendRequest`) over TLS 1.3.
- **Thread Management**: Non-blocking `CreateThread` worker pool with UI listbox streaming and automatic retry.
- **Offline Fallback**: In the event of network disconnection or timeout, on-device SOC heuristics take over seamlessly.
