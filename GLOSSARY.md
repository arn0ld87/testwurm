# Domain Glossary

This glossary defines the canonical terminology used throughout this security toolkit project.

## Core Concepts

**Worm**: A self-propagating malware that spreads across networked systems without user intervention, exploiting known vulnerabilities to gain unauthorized access.

**C2 (Command and Control)**: Infrastructure enabling remote communication between compromised systems and the operator, typically using encrypted channels for stealth.

**C2 Protocol**: The fixed message structure exchanged between the worm's agent and the operator's C2 — host registrations, heartbeats, secret uploads, and the host, secret and task records the operator reads back. Every participant in the exchange speaks the same structure, so a field that exists on one side exists on all of them.
_Avoid_: C2 API, REST contract, wire format

**C2 Transport**: The single implementation that carries the C2 Protocol over the wire — TLS setup, the bearer header, URL construction, and the mapping of an HTTP status onto an error. It exists once, next to the protocol it carries, so that the agent, the operator CLI, and the server's own test all speak through the same code.
_Avoid_: C2 client (the client is an adapter over the transport), HTTP layer

**Exfiltration**: The process of extracting sensitive data (credentials, keys, configurations) from compromised systems and transmitting it to an external location.

**Exfiltrated Secret**: A credential that has been extracted from a compromised host and transferred to the operator. It carries the identity of the host it was taken from, so that every exfiltrated secret points back to a known host. It carries the key it was sealed with, so that every exfiltrated secret opens on its own — even when the host entry has since moved on to another key.
_Avoid_: Secret (an extracted secret still lives on the compromised host and has not been transferred)

**Meldung**: What the agent reports to the C2 — the hosts it knows and the loot it found on them, in the order the contract requires: first the host, then its loot. A Meldung carries its own outcome: what was delivered and what was lost. Loot whose host could not be announced stays with the agent; it is lost, not transferred.
_Avoid_: Upload (one call, not the whole report), Reporting (the act without the outcome)

**Fund**: What the agent found on one host: the host, its status, and the loot taken from it. A Fund is the unit of discovery; the Meldung is the unit of reporting.
_Avoid_: Exfiltrated Secret (a Fund is not yet transferred)

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
