# Domain Glossary

This glossary defines the canonical terminology used throughout this security toolkit project.

## Core Concepts

**Worm**: A self-propagating malware that spreads across networked systems without user intervention, exploiting known vulnerabilities to gain unauthorized access.

**C2 (Command and Control)**: Infrastructure enabling remote communication between compromised systems and the operator, typically using encrypted channels for stealth.

**C2 Protocol**: The fixed message structure exchanged between the worm's agent and the operator's C2 — host registrations, heartbeats, secret uploads, and the host, secret and task records the operator reads back. Every participant in the exchange speaks the same structure, so a field that exists on one side exists on all of them.
_Avoid_: C2 API, REST contract, wire format

**Exfiltration**: The process of extracting sensitive data (credentials, keys, configurations) from compromised systems and transmitting it to an external location.

**Exfiltrated Secret**: A credential that has been extracted from a compromised host and transferred to the operator. It carries the identity of the host it was taken from, so that every exfiltrated secret points back to a known host.
_Avoid_: Secret (an extracted secret still lives on the compromised host and has not been transferred)

**Persistence**: Techniques used to maintain access to a system across reboots or security tool resets, including scheduled tasks, registry modifications, and service creation.

## Exploitation Terminology

**CVE (Common Vulnerabilities and Exposures)**: Standardized identifier for publicly disclosed security vulnerabilities in software.

**Payload**: The malicious code or data delivered to a target system to achieve the attacker's objectives, often including reverse shells or backdoors.

**Vector**: The method or pathway used to deliver a payload to a target system, such as network protocols, email attachments, or web exploits.

## Network Security Terms

**Reconnaissance**: Initial phase of penetration testing involving information gathering about target systems, including open ports, services, and potential attack vectors.

**Lateral Movement**: Technique for moving between systems within a network after initial compromise, often to access more valuable assets or escalate privileges.

**Privilege Escalation**: Process of gaining higher-level access (administrative rights) on a compromised system to perform additional malicious activities.

## Dashboard and Monitoring

**IOC (Indicators of Compromise)**: Evidence of a system compromise, including file hashes, network signatures, or behavioral patterns that indicate malicious activity.

**Telemetry**: Data collected from compromised systems for analysis, including system information, network connections, and user activities.
