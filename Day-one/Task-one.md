# 🛡️ Cybersecurity Day-01 Assignments & Mini Project

**Foundations of Cybersecurity \| Risk Awareness \| CIA Triad \|
CVE/CVSS \| NIST NICE**

This repository contains Day-01 theory assignments, lab exercises, and a
beginner-friendly cybersecurity mini project designed to build strong
foundational knowledge and provide students with an interview-ready
project.

------------------------------------------------------------------------

## 📌 Learning Objectives

-   Understand core cybersecurity concepts\
-   Learn CIA Triad and its real-world application\
-   Differentiate between Threat, Vulnerability, and Risk\
-   Explore CVE and CVSS using NVD\
-   Gain awareness of cybersecurity roles (NIST NICE)\
-   Perform basic system risk assessment and hardening

------------------------------------------------------------------------

## 📘 THEORY ASSIGNMENT -- DAY 01

### 🔹 Section A -- Short Answer

1.  Define Cybersecurity.
Ans: Cybersecurity is the practice of protecting computers, networks, applications, and digital data from unauthorized access, misuse, attacks, or damage.
Example: Using antivirus software and firewalls to protect a laptop from malware and hackers.

2.  What is an Asset in cybersecurity?\
Ans: An asset is any data, system, application, hardware, or service that has value to an organization and must be protected from unauthorized access, loss, or damage.
Example: Organizational assets include confidential files, customer databases, email systems, servers, intellectual property, and cloud storage resources.

3.  What is a Threat?\
Ans : A threat is any potential source of harm that can intentionally or accidentally exploit an organization’s assets.
Examples include phishing attacks, malware, insider misuse, ransomware, and denial-of-service attacks.

4.  What is a Vulnerability?\
Ans : A vulnerability is a weakness or gap in an organization’s systems, software, configuration, or processes that can be exploited by a threat.
Examples include unpatched systems, weak passwords, misconfigured servers, or lack of security awareness.

5.  What is Risk?\
Ans: Risk is the potential impact or loss to an organization when a threat successfully exploits a vulnerability.
For example, a phishing attack exploiting poor email security can lead to data breaches and financial loss.

6.  Expand CIA Triad.\
Ans:CIA Triad stands for Confidentiality, Integrity, and Availability, which form the foundation of information security in organizations.

7.  What is CVE?\
Ans: CVE (Common Vulnerabilities and Exposures) is a standardized system for identifying and cataloging publicly known cybersecurity vulnerabilities.
It helps organizations consistently track and manage security flaws in their systems.

8.  What is CVSS?\
Ans: CVSS (Common Vulnerability Scoring System) is a framework used to assess the severity of vulnerabilities by assigning a numerical score based on impact and exploitability.
Organizations use CVSS scores to prioritize vulnerability remediation.

9.  What is a Security Control?\
Ans:A security control is a technical, administrative, or physical measure implemented to reduce risk and protect organizational assets.
Examples include access controls, encryption, firewalls, antivirus software, and security policies.

10. What is a Framework?
Ans:A framework is a structured set of standards, guidelines, and best practices that helps organizations design, implement, and manage cybersecurity programs.
Examples include the NIST Cybersecurity Framework and ISO/IEC 27001.


### 🔹 Section B -- Explain

11. Explain CIA Triad with one real-life example for each component.\
Ans: The CIA Triad represents the three core principles of cybersecurity:

Confidentiality
Ensures that information is accessible only to authorized users.
Real-life example: Employee salary files are protected using passwords so that only HR staff can view them.

Integrity
Ensures that data remains accurate and is not altered without authorization.
Real-life example: Antivirus software prevents unauthorized modification of important system files.

Availability
Ensures that systems and data are accessible when needed.
Real-life example: Regular data backups ensure files are available even after a system crash.


12. Differentiate between Threat, Vulnerability, and Risk with
    examples.\
Ans: Threat

A threat is any potential action or event that can cause damage to an organization’s system or data.
Example: A hacker attempting to exploit an outdated web server.

Vulnerability

A vulnerability is a weakness in a system, software, or configuration that can be exploited by a threat.
Example: The web server is running an unpatched operating system with known security flaws.

Risk

Risk is the possibility of loss or damage when a threat successfully exploits a vulnerability.
Example: The hacker exploits the unpatched server, gains unauthorized access, and steals sensitive organizational data.


13. Explain why cybersecurity frameworks are important.\
Ans:Cybersecurity frameworks provide structured guidance to help organizations manage security risks effectively.

They help identify and protect important assets and data

They provide best practices instead of random security measures

They help organizations respond to and recover from cyber incidents

They ensure consistency in security implementation across systems

Example: Using the NIST framework helps an organization systematically identify risks, apply controls, and improve security posture.


14. Explain NIST NICE Framework in your own words.\
Ans:The NIST NICE Framework is mainly about people working in cybersecurity, not tools or software.
It explains what kind of cybersecurity jobs exist and what skills are needed for each job.

It helps organizations understand:

what roles they need in their security team

what knowledge and skills employees should have

It also helps students and beginners:

understand different cybersecurity career options

choose a role based on their interest and skills

Example: A company can use the NIST NICE Framework to decide roles like Security Analyst or Incident Responder and then train employees for those specific roles.


15. Explain how CVSS score helps organizations.
Ans:The CVSS (Common Vulnerability Scoring System) score helps organizations measure how dangerous a vulnerability is so they can take the right action at the right time.

It provides a numerical score (0 to 10) that shows the severity of a vulnerability

A higher score means higher risk to systems and data

It helps security teams decide which vulnerabilities must be fixed first

It supports better decision-making by focusing on the most critical threats

It reduces effort and time by avoiding equal treatment of all vulnerabilities

It helps management understand technical risks in a simple number format

Example:
If one vulnerability has a CVSS score of 9.8, it means attackers can easily exploit it and cause serious damage. This will be fixed immediately.
A vulnerability with a score of 4.0 is less dangerous and can be patched later.


### 🔹 Section C -- Scenario Based

Scenario 1 and Scenario 2 as discussed in assignment.

Scenario 1: Phishing Email Attack
Asset: Organization’s official email account and employee login credentials
Threat: Phishing email sent by an attacker pretending to be IT support
Vulnerability: Lack of employee awareness and weak email filtering
Risk: Employee may click the malicious link and share credentials
Impact: Unauthorized access to email and internal systems, possible data breach
Security Control: User awareness training, spam filters, and multi-factor authentication (MFA)


Scenario 2: Weak Password on Organizational System
Asset: Organizational computer system and sensitive files
Threat: Unauthorized access by an attacker
Vulnerability: Weak, reused, or predictable passwords
Risk: Attacker may guess or crack the password
Impact: Data loss, system misuse, and compromise of data integrity
Security Control: Strong password policy, password manager, account lockout, and regular password updates

### 🔹 Section D -- Practical Research

Find one CVE from https://nvd.nist.gov and document details.
CVE Practical Research

CVE ID: CVE-2023-4863

Description:
CVE-2023-4863 is a security vulnerability found in the Google Chrome browser. This vulnerability exists in the WebP image processing component and can be exploited when a user opens a malicious image file.

Affected Product(s):
Google Chrome browser (multiple versions before the security update)

Type of Vulnerability:
Heap buffer overflow

CVSS Score (Severity):
High (CVSS score: 8.8)

Impact:
An attacker can exploit this vulnerability to execute malicious code on the victim’s system. This may lead to system compromise, data theft, or unauthorized access.

Remediation:
Update Google Chrome to the latest patched version provided by the vendor to fix the vulnerability.

### 🔹 Section E -- CIA Mapping

Map security controls to CIA.
Confidentiality
Strong passwords prevent unauthorized access
Multi-Factor Authentication (MFA) protects sensitive accounts
Encryption ensures data privacy

Integrity
Antivirus software prevents unauthorized modification of data
Access control ensures only authorized users can change data
System updates maintain data accuracy

Availability
Regular backups ensure data is available during failures
Firewall protection prevents denial-of-service attacks
System monitoring ensures continuous access to services

### 🔹 Section F -- Career Awareness

Explain one cybersecurity role.

Cybersecurity Role: Security Analyst
A Security Analyst is responsible for protecting an organization’s systems, networks, and data from cyber threats. This role involves monitoring security alerts, identifying potential attacks, and responding to security incidents.

A Security Analyst also:
Analyzes security logs and alerts
Identifies vulnerabilities in systems
Helps prevent attacks like malware and phishing
Recommends security controls and improvements
Example:
If a phishing email is detected in an organization, a Security Analyst investigates the incident, blocks the malicious source, and helps prevent similar attacks in the future.



------------------------------------------------------------------------

## 🧪 LAB EXERCISES

-   CVE Research\
-   Asset Identification\
-   Threat Risk Mapping\
-   CIA Mapping\
-   Password Strength Testing

------------------------------------------------------------------------

## 🎯 MINI PROJECT

### Personal Cybersecurity Risk Assessment & Hardening Project

Modules:

1.  Asset Inventory\
2.  Threat Identification\
3.  CVE Research\
4.  Hardening Actions\
5.  CIA Mapping\
6.  Final Report

------------------------------------------------------------------------

## 📄 Deliverables

-   Final_Report.pdf\
-   Screenshots\
-   Filled Lab Sheets

------------------------------------------------------------------------

## 🧾 Resume Project Example

Personal Cybersecurity Risk Assessment & System Hardening

------------------------------------------------------------------------

Happy Learning & Stay Secure!
