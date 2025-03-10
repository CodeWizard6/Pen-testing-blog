---
title: 'Escape Machine Walkthrough'
keywords: []
layout: single
header:
  image: /assets/images/Escape.png
toc: true
toc_label: "Table of Contents"
sidebar:
  nav: "sidebar"
---

## Machine Summary

Escape is a medium difficulty machine running the Microsoft Windows OS and demonstrates how weak authentication and authorization, insecure stroage of credentials in the local file system, and security misconfigurations in Microsoft Active Directory Certificate Services (ADCS) combined, can result in the complete compromise of the AD domain.<!-- excerpt-end -->

A summary of the attack path to escalate privileges to the local Administrator in the AD domain is as follows:

* As a result of a sensitive PDF file containing login credentials being stored on a SMB file share without requiring user authentication, credentials to Microsoft SQL Server were obtained
* The net-NTLM hash of the MS SQL service account was obtained and subsequently cracked to reveal the plaintext password
* Using the credentials from previous step, remote access to the machine was obtained upon which a log file containing the password of a user account was discovered.
* As a result of several security misconfigurations in the AD Certificate Services service (ADCS), a fraudulent certificate for the local Administrator user on the domain was created, enabling full privilege escalation to Administrator privileges via account impersonation using a pass the hash attack.

![Escape Machine exploitation matrix](/Pen-testing-blog/assets/images/Escape_machine_exploitation_matrix.png "Figure 1 - Escape machine exploitation matrix")

### Step 1 — Enumeration

As always, I begin by enumerating the victim’s machine seeking to obtain as much information about OS type and version, open ports, services running on the open ports etc. as possible. I will use the **nmap** scanner.

### Enumerating with nmap

I first run a scan to discover open ports (Figure 1) and then run the default set of nmap enumeration scripts and service detection scan only on those open ports for greater efficiency (Figures 2 and 3). Explanation of flags:

* /-p — Ports on victim machine to scan
* /-n — Do not resolve DNS
* /-sC — run default set of nmap enumeration scripts
* /-sV — Detect services running on the open ports
* /-T4 — Scan in aggressive mode to speed up the scan results

```bash
nmap 10.10.11.202 -p- -T4

nmap 10.10.11.202 -p 53,88,135,139,389,445,464,1433,3268-3269,5985,9389 -n -sC -sV -T
```

![Nmap output 1](/Pen-testing-blog/assets/images/1__7nEGbgQaewRuOBCH5663GQ.png "Figure 2 - Nmap output 1")

![Nmap output 2](/Pen-testing-blog/assets/images/1__zO6K3Oy91wdeWQEWMZOlyw.png "Figure 3 - Nmap output 2")

![Nmap output 3](/Pen-testing-blog/assets/images/1__LQa6zDQz3tZXrwg5HGQrow.png "Figure 4 - Nmap output 3")

The Nmap output show that the machine is running Microsoft Windows OS and is a domain controller due to the types of ports open and the services running on those ports. The results show the following:

* Dynamic name resolution (DNS) service running on default port of 53.
* Kerberos authentication protocol is running on default port 88.
* Remote procedure call (RPC) service running on default port 135
* Server messaging block (SMB) for network resource sharing is running on default port of 445 and also on port 139 via the NetBios service
* Kerberos password service is running on default port of 464.
* Lightweight directory access protocol (LDAP) is active on default port 389, 636, 3268 and 3269 for running unencrypted LDAP, Global Catalog for AD, and the encrypted LDAP over SSL/TLS respectively.
* Microsoft SQL Server services is running on default port of 1433.
* Windows remote management (WinRM) service over HTTP is active on default port of 5985.

### Enumerating SMB file shares — port 445

The first service I enumerate is SMB file shares, hoping to be able to view the contents of the file shares for sensitive information such as credentials. The null login attempt was successful using the tool **smbclient.** per Figure 4. Explanation of flags:

* /-L — List all shares on the file share
* /-N — Do not use a password to login (null session)

```bash
smbclient -N -L //10.10.11.202
```

![Successful null session for SMB](/Pen-testing-blog/assets/images/1__GJpqymvwaDmlAKMRfXO03A.png "Figure 5 - successful null session for SMB")

The only non — default file share is **Public**. I connect to the share and use the **ls** command to list out files on the share. There is only one pdf file — **SQL Server Procedures.pdf** , which I download to my Kali Linux machine via **get** command per Figure 5.

![Downloading PDF document to local machine](/Pen-testing-blog/assets/images/1__391GAbfH8BoSmFB3SY8BsQ.png "Figure 6 - Downloading PDF document to local machine")

### Enumerating LDAP — port 389

As there are no other files or non — default shares, I move on to enumerating LDAP using the **ldapsearch** tool, hoping to find a list of domain users, possibly for a [Kerberos AS-REP-roasting attack](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/helping-protect-against-as-rep-roasting-with-microsoft-defender/ba-p/2244089), but had no luck as null bind requests were not allowed per Figure 6 below. Explanation of flags:

* /-x — Login without a password (null bind)
* /-H — Specify the IP address of the host to bind to
* /- b — Specify the search base to begin searching

```bash
ldapsearch -x -H ldap://10.1011.202 -b "dc=htb, dc=sequel"
```

![Null LDAP sessions disallowed](/Pen-testing-blog/assets/images/1__oohIoN__TsQ2Z8SC2N6GIsQ.png "Figure 7 - Null LDAP session disallowed")

### Enumerating RPC for users and domain security groups — port 139

I try to use RPC protocol to enumerate domain users and AD security groups using a null bind and although successful, was not able to enumerate users or user groups due to access being denied per Figure 7 below. Explanation of flags:

* /-U — Specify user to login as (use empty double quotes for null login)
* /-N — Do not use a password to login

```bash
rpcclient -U "" -N 10.10.11.202
```

![Null RDP session allowed but unable to enumerate users](/Pen-testing-blog/assets/images/1__fsC4VeCSda3LKtF6c14Nug.png "Figure 8 - Null RDP session allowed but unable to enumerate users")

## Step 2 — Obtaining initial foothold as Sql_svc

As both LDAP and RPC enumeration led to dead ends, I go back to exploring Microsoft SQL server on port 1433 using the tool **mssqlclient** from the Impacket collection of tools. The downloaded PDF file earlier contain MS SQL Server credentials per Figure 8 below.

![User credentials found in downloaded PDF file](/Pen-testing-blog/assets/images/1__bATNc__QoarkC__gJ2wGhkRg.png "Figure 9 - User credentials found in downloaded PDF file")

Per Figure 9, I use was able to use the obtained credentials to login to the SQl server.

```bash
PublicUser:GuestUserCantWrite1@10.10.11.202
```

![Logging into SQL server with found credentials](/Pen-testing-blog/assets/images/1__ttq4PJUR__tjR5BgIfsXJ4A.png "Figure 10 - Logging into SQL server with found credentials")

I begin by checking which users have access to run OS level commands with **xp_cmdshell** and whether I am currently logged in with elevated **sysadmin** privileges at the SQL server level. As Figure 10 below shows, I am dont have sufficient access to run xp_cmdshell command nor do I have sysadmin privileges on the SQL server.

![Inadequate permissions on SQL server](/Pen-testing-blog/assets/images/1______rvrzc4Qx7AK1x0KQx6fA.png "Figure 11 - Inadequate permissions on SQL server for cmdshell and not a sysadmin")

### Obtaining net NTLMv2 hash of the AD account running SQL Server

As I can’t do much on SQL server, I next attempt to steal the net-NTLMv2 hash of the AD account running MS SQL Server and cracking it offline so I can login to domain with such account. I kconfigure the native **Responder** tool in Kali Linux to listen on the VPN network interface used to connect to the HackTheBox server as shown in Figure 11 below. Explanation of syntax:

* -I — Specify the interface for Responder to listen for event on.

![Configuring Responder tool to intercept NTLMv2 hash for svc_sql account](/Pen-testing-blog/assets/images/1__FbR5IMD6rtQQ4XhG7a4rVA.png "Figure 12 - Configuring Responder tool to intercept NTLMv2 hash for svc_sql account")

Upon forcing the SQL server to lookup an arbitrary file share on my Kali Linux machine, Responder tool intercepted the net-NTLMv2 hash of the AD account running SQL server per Figure 12 below. **While I used “my/_share” for the file share name, any value can be used**.

![Responder interception of te NTLMv2 hash for AD account svc_SQL](/Pen-testing-blog/assets/images/1__HJwxvSIL9HfvzaG5RTH4Qg.png "Figure 13 - Responder interception of te NTLMv2 hash for AD account svc_SQL")

### Cracking the net NTLMv2 hash to obtain plaintext password

As I now have the net NTLMv2 hash, I use the native **Hashcat** tool in Kali Linux to crack the hash and obtain the plaintext password of the AD account running MS SQL Server. The input syntax is shown in Figure 13 below. The hash was successfully cracked to reveal the plaintext password for the **sql_svc** AD domain account per Figure 14 below. Explanation of syntax:

* -a — Specify the attack type — Choose 0 for a straight or dictionary attack
* -m — Specify the hash type — Choose 5600 for net NTLMv2 hash
* /usr/share/wordlists/rockyou.txt — Specify the wordlist to use
* -o — Specify the output file where the plain text password will be stored

```bash
hashcat -a 0 -m 5600 'hash to crack' /usr/share/wordlists/rockyou.txt -o cracked/_hash.txt
```

![Input to Hashcat for cracking captured NTLMv2 hash from Responder tool](/Pen-testing-blog/assets/images/HashCrackCommand_Escape.png "Figure 14 - Input to Hashcat for cracking captured NTLMv2 hash from Responder tool")

![Cracked NTLMv2 hash for svc_SQl AD account](/Pen-testing-blog/assets/images/CrackedHash_Escape.png "Figure 15 - Cracked NTLMv2 hash for svc_SQl AD account")

### Logging in as sql_svc user via Evil-winrm tool

The final step to gain the initial foothold on the victim’s machine is to log in as the sql_svc service account via the **Evil-winrm** tool. Explanation of syntax:

* /-i — Specify the IP address of the remote host machine to connect to
* /-u — Specify the username to connect as
* /-p — Specify the password of the user to connect as

```bash
evil-winrm -i 10.10.11.202 -u sql_svc -p REGGIE1234ronnie
```

![Logging in as svc_sql domain account](/Pen-testing-blog/assets/images/SuccessfulLoginSvcSQL_Escape.png "Figure 16 - Successfully logging in as svc_sql domain account")

## Step 3 — Lateral Movement — sql_svc > Ryan.Cooper

### Enumerating resources on AD domain as sql_svc user

I enumerate the resources I have access to as **sql_svc** looking for additional credentials to move laterally to other, more privileged, domain users. In the root directory of the C:/ drive, I found 2 non — default directories per Figure 16. Further enumeration of the SQLServer directory showed a log file highlighted in Figure 17. Finally, a review of the log files revealed the AD domain password for user **Sequel//Ryan. Cooper** per Figure 18 below.

![Discovery of two non-default directories](/Pen-testing-blog/assets/images/TwoNondefaultDirectoriesSvcSql_Escape.png "Figure 17 - Discovery of two non-default file shares")

![Discovery of log file on SQLServer file share](/Pen-testing-blog/assets/images/ErrorLogDiscoverySvcSql_Escape.png "Figure 18 - Discovery of error logs on SQLServer file share")

![Password of user Ryan Cooper revealed](/Pen-testing-blog/assets/images/RyanCooperPasswordRevealed_Escape.png "Figure 19 - Password of domain account Ryan Cooper revealed in error log")

### Logging in as Ryan Cooper user via Evil-winrm tool

I attempt to log in to the AD domain account of Ryan.Cooper using the credentials I discovered and was successful.

```bash
evil-winrm -i 10.10.11.202 -u Ryan.Cooper -p NuclearMosquito3
```

![Successful login as domain account Ryan Cooper](/Pen-testing-blog/assets/images/SuccessfulLoginRyanCooper_Escape.png "Figure 20 - Successfully logged in as domain account Ryan Cooper")

## Step 4 — Privilege Escalation to Administrator

### Confirming Active Directory Certificate Services (ADCS) status

One of the first checks I like to do when the victim machine is a domain controller is to check if ADCS is enabled. The output from the **certutil -dump** command shown in Figure 21 confirmss ADCS is active with the certificate authority being **sequel-DC-CA.**

![ADCS active](/Pen-testing-blog/assets/images/ADCSActive_Escape.png "Figure 21 - ADCS active with CA seqel-DC-CA")

### Confirming presence of vulnerable certificate templates

After confirming that ADCS is enabled, I next confirm whether there are any insecurely configured certificate templates that could be vulnerable to forgery such as via the [ESC1 escalation path](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation). Command input and output are shown in Figure 22 and 23 below respectively. Explanation of syntax:

* Find — Put the certificate abuse and enumeration tool of [Certipy-AD](https://www.bing.com/ck/a?!&&p=510c6f89c69f440aJmltdHM9MTcyMTAwMTYwMCZpZ3VpZD0yMjBkZWIwZi05MThhLTY5NjMtMzFhMS1mZjZlOTA3NDY4MjcmaW5zaWQ9NTIyMw&ptn=3&ver=2&hsh=3&fclid=220deb0f-918a-6963-31a1-ff6e90746827&psq=Certipy+AD&u=a1aHR0cHM6Ly93d3cua2FsaS5vcmcvdG9vbHMvY2VydGlweS1hZC8&ntb=1) into search mode
* /-u — Specify the AD domain user account for Certipy to scan as
* /-p — Specify the password of the domain user Certipy uses to scan
* /-dc-ip — Specify the IP address of the domain controller for Certipy to scan against
* /-Vulnerable — Filter for only insecure certificate templates

```bash
certipy-ad -u <Ryan.Cooper@Sequel.htb> -p Nuclearosquito3 -dc-ip 10.10.11.202 -vulnerable
```

![Input command to list vulnerable certificate templates](/Pen-testing-blog/assets/images/CommandFindVulnerableCertificateTemplates_Escape.png "Figure 22 - Command to list vulnerable certificate templates")

Privilege escalation via impersonation of the local AD Administrator user account is possible due to the following set of configuration settings being enabled simultaneously as shown in Figure 23 below.

![Details of vulnerable certificate](/Pen-testing-blog/assets/images/VulnerableCertificateDetails.png " Figure 23 - Vulnerable certificate details")

* **Client Authentication setting set to true** — This setting enables the certificate to be used to login to an AD domain user account in lieu of using the password of such account to log in.
* **Enrollee supplies subject setting set to true** — This setting enables the enrollee to supply another account identity (subject alternative name — SAN) to login as, **to include the local Administrator account and domain admin users.**
* **Requires manager approval setting** **set to false** — By setting the value to false, certificate validation by the certificate manager will be bypassed when the certificate is enrolled.
* **Authorized signatures required setting set to 0** — By setting this value to 0, no additional manual check to ensure the certificate is appropriate will be done.

### Generating a forged certificate for local Administrator AD domain account

The next step after confirming that the UserAuthentication certificate template is vulnerable to the ESC 1 privilege escalation attack is to generate a fraudulent certificate using the insecure template discovered with the local Administrator user account as the SAN. The input syntax and command output is shown in Figure 24 below.  Explanation of syntax:

* req — Put the Certipy-AD certificate abuse and enumeration tool into certificate request mode
* /-u — Specify the AD domain user account requesting the certificate (i.e.: certificate enrollee)
* /-p — Specify the password of the certificate enrollee
* /-upn — Specify the unique user principal name of the AD domain account for the enrollee to impersonate
* /-ca — Specify the certificate authority the AD domain is using
* /-template — Specify the vulnerable certificate template to be used to generate the forged certificate (UserAuthentication discovered earlier)
* dc-ip — Specify the IP address of the AD domain controller

```bash
certipy-ad req -u Ryan.Cooper -p NuclearMosquito3 -upn <Administrator@Sequel.htb> -ca sequel-DC-CA -template UserAuthentication -dc-ip 10.10.11.202
```

![Requested forged certificate for local administrator account](/Pen-testing-blog/assets/images/1__WfkNIL9AxUlEPID4BzJzzw.png "Figure 24 - Requesting forged certificate for local Administrator account")

### Authenticating as Local Administrator user using forged certificate and capturing the password hash

The next step is to authenticate as the local Administrator user via the forged certificate generated in the previous step and capture the password hash of the Administrator user account. The input syntax and command output in shown in Figure 25 below.  Explanation of syntax:

* faketime ‘2024–07–18 08:15:30’ — Use the faketime tool to trick the victim’s machine into thinking that the ticket granting ticket (TGT) request from my Kali Linux instance is coming within 5 minutes of the system time on the victim’s machine. This step is necessary as Kerberos default tolerance for clock skew is 5 minutes to mitigate against replay attacks, after which client authentication requests will fail.
* auth — Set the Certipy-AD tool to authenticate mode
* /-pfx — Specify the pfx file containing the forged local Administrator certificate from the previous step
* /-dc-ip — Specify the IP address of the domain controller to authenticate against

```bash
faketime '2024-07-18 08:15:30' certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.202
```

![Authenticating as local Administrator using the forged certificate](/Pen-testing-blog/assets/images/SuccessTGTAuthenticationForgedCertificate_Escape.png "Figure 25 - Authenticating as local Administrator account using forged certificate")

### Logging in as local Administrator user on domain via pass the hash attack

The final step to escalating my privileges to local Administrator user is to login as the local Administrator via a pass the hash attack, using the captured password hash from the previous step.

```bash
evil-winrm -i 10.10.11.202 -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee
```

![Successfully login as local administrator user via pass the hash attack](/Pen-testing-blog/assets/images/SuccessfulEscalationPrivilegeAdministratorPTH_Escape.png "Successful privilege escalation to local administrator via a pass the hash attack")

## Vulnerabilities - Exploitation and mitigation summary

This machine demonstrated the following vulnerabilities and showed how they can be exploited. I've also included some security controls that can mitigate exploitation:

### Security misconfiguration - Null SMB sessions enabled

Enabling enumeration of file shares via SMB protocol without authentication can result in access to sensitive data by unauthorized users. In this machine, as a result of SMB null sessions being enabled, I was able to enumerate a file share containing a sensitive document with credentials without having to authenticate.

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Disable SMB null authentication so that only authenticated users can access file share via the SMB protocol. In general, all access to system resources should occur only after authentication of end user identity.
* Restrict which users can access file shares via SMB protocol such as via editing Group Policy or the Windows registry
* Log all attempts to access file shares via SMB protocol. This monitoring will help to detect anomalous SMB access such as from null SMB sessions.

### Sensitive credential exposure

The storage of credentials in insecure locations on the local file system can result in their compromise by malicious actors. In this machine, a PDF document containing credentials were stored on a file share that did not require any authentication. As a result, I was able to use such credentials to obtain an initial foothold on the victim's machine on the AD domain.

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Do not store credentials in files on the local file system in an insecure manner such as in plaintext and / or in an location that lacks access controls.
* Use a password manager to securely store credentials instead of on files in the local file system.

### Security misconfiguration - Insecure AD certificate enrollment rights

If security configurations governing certifcate enrollment in an Active Directory domain environment are misconfigured, malicious actors can create fraudulent certificates to impersonate end users. In this machine as a result excessively loose certificate enrollment permissions alongside disabling of certificate signing by certificate authority and manual checks upon certificate issuance, I was able to generate a forged certificate to impersonal the local Administrator account.

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Restrict users who can enroll / request certificates to only users with a business need to do so. Excessively loose permissions such as Domain users AD security group (allowing all domain users to request certificates) should not be used.
* Use certificate templates or disable SAN setting. Certificate templates should be used in lieu of allowing users to specifiy the subject alternative name to avoid compromise of highly privileged accounts such as local Administrator.
* Enforce certificate signing by the CA and manual inspection of certificates before their issurance. These practices help to ensure that certificates are issued to appropriate entities and for apppropriate purposes.
