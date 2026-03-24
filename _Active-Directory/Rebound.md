---
title: 'Rebound Machine Walkthrough'
keywords: []
excerpt: "Rebound is a Insane difficulty level machine that shows how excessively permissive access control lists (ACLs) in Active Directory and improper delegation of access rights can lead to the complete compromise of an AD domain"
layout: single
classes: wide
header:
  image: /assets/images/Rebound/Rebound.png
toc: true
toc_label: "Table of Contents"
sidebar:
  nav: "sidebar"
---

## Introduction

Rebound is an Insane difficulty level machine that shows how excessively permissive access control lists (ACLs) in Active Directory and improper delegation of access rights can lead to the complete compromise of an AD domain. Throughout this exercise, I will show techniques to compromise AD including abuse of shadow credentials and resource based constrained delegation (RBCD). The attack path is as follows. Please note there are IP addresses for the same vulnerable machine as I wrote this in several different sessions.

* A list of user accounts is obtained via a RID cycling attack and an account is found to be vulnerable to a Kerberoasting attack.
* Another user shares the password of the compromised attack above and through a misconfigured ACL, can add themselves to a AD security group.
* A shadow credential is obtained for a third user that has access to windows remote management login functionality.
* A cross session relay attack is performed for a 4th user who has the ability to read the GMSA password of a service account.
* A resource based constrained delegation (RBCD) attack is used to impersonate the domain controller machine account and dump hashes which allows full escalation to Administrator role.

![Machine exploitation characteristics matrix](/Pen-testing-blog/assets/images/Rebound/MachineMatrix.png "Figure 1 - Machine exploitation characteristics matrix")

## Pen testing techniques used

* [As-REP roasting](https://thehackernews.com/2021/09/what-is-as-rep-roasting-attack-really.html)
* Kerberoasting directly from service tickets instead of via traditional ticket granting ticket (TGT) from DC
* Abuse of excessively loose access control privileges on AD security groups
* [Abuse of shadow credentials](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials)
* [Group managed service acount (GMSA) password hash cracking](https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword)
* [Cross session relay attacks](https://www.thehacker.recipes/ad/movement/ntlm/relay)
* [Abuse of role based constrained delegation](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)

## Prerequisites - Configuring Kerberos authentication

Rebound machine is deliberately hardened and NTLM authentication has been disabled. Therefore Kerberos authentication must be used for any tool that  needs to authenticate to the HTB domain. Several important steps are needed to ensure Kerberos works properly.

### Configuring krbt5 config file

I'm running a Kali virtual machine. The Kali package krb5-user provides the required tools of kinit, klist and kdestroy used to request, view, and destroy Kerberos ticket granting tickets (TGT). When krb5-user package is installed via native Linux package manager of APT, it will install all other prerequisite packages too. The Kerberos configuration file is stored in /etc/krb5.conf. Before a Kerberos TGT can be requested, I must first populate this file with the HTB domain controller and realm information. Please note the following **important details** as this config file is strict about section formatting and capitalization of AD domain objects. Please see Figure X below for a example of a properly confgured and formatted krbt5.conf configuration file.

* All REALM NAMES must be CAPITALIZED
* All domain names must be in lowercase
* Ensure each section - libdefaults, realms, and domain_realm has matching opening and closing braces at the matching level. Key to value pairs must be on a single line to parse correctly.

###

## Step 1 - Enumeration

As always, I begin with enumeration of the remote machine with the goal of gathering as much information as I can about it such as open ports, services running on the open ports, and operating system type and version. I will use the network scanner, **nmap.**

### Enumerating with Nmap

I first run a scan to discover open ports per Figure 2 below and then run the service detection scan and default set of nmap enumeration scripts only on those open ports for greater efficiency as show in Figure 3. Explanation of flags:

* -p — Ports on remote machine to scan
* -n — Do not resolve DNS
* -sC — run default set of nmap enumeration scripts
* -sV — Detect services running on the open ports
* -T4 — Scan in aggressive mode to speed up the scan results

```bash
nmap 10.129.232.31 -p- -T4

nmap 10.129.232.31 -p 53,88,135,139,389,445,593,3268,5985 -sC, -sV, -n -T4
```

![Nmap scan 1](/Pen-testing-blog/assets/images/Rebound/nmapOutput1.png "Figure 2 - Nmap scan output 1")
![Nmap scan 2](/Pen-testing-blog/assets/images/Rebound/NmapOutput2.png "Figure 3 - Nmap scan output 2")
![Nmap scan 3](/Pen-testing-blog/assets/images/Rebound/NmapOutput3.png "Figure 4 - Nmap scan output 3")

The Nmap output shows the following:

* The machine is a Windows OS and is a an Active Directory domain controller due to the ports open and the services running on those ports.
* Dynamic name resolution (DNS) service is running on default port of 53.
* Kerberos authentication protocol is running on default port 88.
* Remote procedure call (RPC) service running on default port 135
* Server messaging block (SMB) for network resource sharing is running on default port of 445 and also on port 139 via the NetBios service
* Lightweight directory access protocol (LDAP) is active on default port 389 and 3268 for running unencrypted LDAP and the LDAP service communicating with the AD Global Catalog.
* Windows remote management (WinRM) service over HTTP is active on default port of 5985.

### Enumerating SMB protocol using guest account and null binds

I begin by enumerating the SMB protocol using netexec tool for anything interesting (such as non - default file shares) using the low privileged guest account. Per **Figure 5** below, the guest account is able to list shares found by default on a AD domain controller plus the Shared file share. This vulnerability due to lack of hardening of the guest account, will be exploited to obtain AD user names in the next step. Summary of syntax is as follows:

* nxc  smb - Set the tool to enumerate using the SMB protocol
* -u - Specify the user account to use , in this case the guest AD account
* -p - Specify the password of the user account above, in this case the empty string for a null bind
* --shares - command used to list all file shares

```bash
nxc smb 10.129.232.31 -u guest -p '' --shares
```

![Guest account enumeration enabled over SMB](/Pen-testing-blog/assets/images/Rebound/SMBGuestAuthenticationEnabled.png "Figure 5 - Guest account enumeration enabled")

I next check if I can access any files on the shares using the guest account by spidering the share via the tool Crackmapexec. Per **Figure 6** below, I can't access any files using the guest account. Summary of syntax is as follows: (duplicate syntax omitted)

* -M spider_plus - Configure the tool to recursively spider the share

```bash
nxc smb 10.129.232.31 -u guest -p '' -M spider_plus
```

![File shares spidering results](/Pen-testing-blog/assets/images/Rebound/ShareSpiderResults.png "Figure 6 - File share spidering results")

## Step 2 - Gaining initial foothold as Ldap_monitor account

### Obtaining list of AD domain user accounts via RID cycling attack

I use the enabled guest account to enumerate AD accounts on the domain via a [relative identifier (RID) cycling attack](https://notes.benheater.com/books/active-directory/page/null-session-enumeration). Please reference **Figure 7** below. Summary of syntax is as follows with duplicate syntax omitted

* --rid-brute 10000 - Configure netexec tool to brute force a list of all AD objects on the domain via RID cycling and continue until reaching RID of 10000

```bash
nxc smb 10.129.232.31 -u guest -p '' --rid brute 10000 | grep SidTypeUser | cut -d '\' -f2 | cut -d '(' -f1
```

![RID cycling brute force attack results](/Pen-testing-blog/assets/images/Rebound/RIDCyclingResults.png "Figure 7 - AD User list obtained via RID cycling brute force attack")

### Obtaining NTLM hash for user JJones via AS-REP roasting attack

After obtaining the list of user names on the AD domain, I test to see if any are susceptible to AS-REP roasting attack by having the Kerberos option of "Do not require pre-authentication enabled". A short summary of how AS-REP roasting attacks work is as follows:

* A malicious actor with access to the domain controller (DC) obtains a listing of AD user accounts on the domain.
* Tools such as [GetNPUsers.py from Impacket set of scripts](https://www.kali.org/tools/impacket-scripts/) are used to identify which accounts have the "Do not require preauthentication" option enabled.
* An authentication request (AS_REQ) is sent to DC to obtain a authentication response (AS-REP) for the account that contains encrypted material derived from user's AD password.
* The DC responds because without preauthentication, the DC does not require the the requesting entity to authenticate itself by providing its password. Hence **any user** can obtain the AS-REP.
* The AS-REP is cracked offline to obtain the plaintext password of the user AD account.

Per **Figure 8** below, the GetNPUsers.py script found that the AD user account **jjones** does not require Kerberos preauthentication, allowing me to steal the AS-REP response from DC. Summary of syntax is below:

* rebound.htb - Specify the domain of the account to AS-REP roast against
* -usersfile - Specify the list of AD domain user accounts to test against, in this case userlist.txt
* -dc-ip - Specify the IP address of the domain controller

```bash
impacket-GetNPUsers.py rebound.htb/ -usersfile userlist.txt -dc-ip 10.129.68.217
```

![AS-REP roasting results](/Pen-testing-blog/assets/images/Rebound/AS-REPRoastingResults.png "Figure 8 - AS-REP roasting successful for AD user account JJones")

### Cracking encrypted blob for AD account jjones via Hashcat - no success

I next attempt to crack the hash to obtain the plaintext AD account password of user JJones but was not successful. Syntax for cracking using Hashcat application as follows. Please reference **Figure 9** and **Figure 10** below.

* -a - Select hash cracking mode - In this case choose 0 for a straight or dictionary attack
* -m - Select the hash type to crack. Choose 18200 for AS-REP
* 'hash to crack' - Specify the hash to be cracked obtained from the output of GetNPUsers.py script in the previous step
-o - Specify the file to write hash cracking results to

```bash
hashcat -a 0 -m 18200 ''$krb5asrep$23$jjones@REBOUND.HTB:807466059d2d78e9960b932fee71bb8f$f8d330bc8ba5cca05498fa0c565a7348f4354d02af6f67d7bcb3373994f4c89d08d089b0534c2a8597c45208b9fbf4cdb8725f6c9673eeb3b943faa0cabb1ddb59bd5f3312d8d561ac0fd8cd2bda479a9abb4345771c9450ce0d6eb68ba23bd27d2b8120752a9e137535ebfb6d6b1c9309e8ac43a4a1f007fadddf1e409e33eb422c99ceb0b80513639508b2110d5dcb521473a4d5db27d5185749f8c42365b06cc4f1b8b8399a723c85485366a4e474de3ccefa35ded13eeb66e5ffe4af12fab26761603b1928df6098847b482198f0d167a12d78cfb547aa95e6c830220719bd86b7a237611c9c5c63' -o crackedhash.txt
```

![JJones AD account hashcat inputs](/Pen-testing-blog/assets/images/Rebound/JJonesHashCatInput.png "Figure 9 - Hashcat inputs to crack JJones AD account passoword hash")
![JJones AD account hash cracking unsuccessful](/Pen-testing-blog/assets/images/Rebound/JJonesHashCatCrackFailure.png "Figure 10 - AS-REP cracking for JJones AD account unsuccessful")

### Kerberoasting directly to obtain service tickets

As hash did not crack with the well known wordlist of rockyou.txt, most likely I need to try another method of gaining further access. After [doing some research](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/), I found it was possible to do Kerberoasting attack by directly requesting service tickets. This is possible because Kerberos armoring is not enforced for AD domain accounts that do not require preauthentication meaning AS-REQ requets can be intercepted and modified. I use the [Impacket Python script GetUserSPN.py](https://www.kali.org/tools/impacket-scripts/). Per **Figure 11** below, I first save the command output to a text file, kerberoast_hashes.txt.  Syntax summary is as follows:

* -no-preauth - Specify the name of the AD domain account that does not have Kerberos preauthentication enabled (jjones)
* -usersfile - Specify the list of user accounts
* -dc-host - Specify the IP address of the domain controller

![Kerberoasting command output saved to text file](/Pen-testing-blog/assets/images/Rebound/AS-REPRoastingResults.png "Figure 11 - Kerberoasting output saved to text file")

When I take a look at the contents of the kerberoast_hashes.txt text file, I see the password hashes of the following 4 AD domain accounts - **krbtgt**, **DC01**,**ldap_monitor**, and **delegator**. Please see **Figure 12** below. From the account naming convention, Ldap_monitor seems to be the only account whose password hash seems feasible to crack as the other accounts are either built-in service accounts for AD services (krbtgt) or seem to serve an elevated role with likely hardened passwords.

![Kerberoast hashes captured](/Pen-testing-blog/assets/images/Rebound/KerberoastHashes.png "Figure 12 - Kerberoasting hashes captured")

I isolate the hash of the AD account ldap_monitor and export it to a text file to be fed to Hashcat for cracking. Please see **Figure 13** below. Per **Figure 14** below, the hash is easily cracked in Hashcat to reveal the plaintext AD account password. Per **Figure 15**, below, the credentials for ldap_monitor account work only for smb protocol, not winrm or ldap, with or without Kerberos authentication (-k flag)

![Ldap monitor AD account hash isololated](/Pen-testing-blog/assets/images/Rebound/LDAPAccountHash.png "Figure 13 - LDAP monitor account hash")
![Ldap monitor AD account hash cracked](/Pen-testing-blog/assets/images/Rebound/Ldap_monitor_cracked.png "Figure 14 - LDAP monitor account hash cracked")
![Ldap monitor credentials testing](/Pen-testing-blog/assets/images/Rebound/Ldap_monitor_workOnlySMB.png "Figure 15 - LDAP monitor account only work for smb protocol")

## Step 3 - Lateral movement to Oorend AD account

### Password spraying password for ldap_monitor across AD domain

I suspect Ldap_monitor to be a service account based on the naming convention and was curious to see if the password was reused elsewhere. I test for this using the netexec (nxc) tool with the **option continue on success enabled** in case there are more than 1 account with reused passwords. Per Figure 16 below, the AD domain account of **Oorend** has the same password as **ldap_monitor** Summary of flags is as follows:

* --continue-on-success - Continue enumeration after 1 successful login is found in case multiple accounts share the same password
* --no-bruteforce - Do not do bruteforce attacks, but spray the single password for ldap_monitor account against all other AD domain accounts
* --shares - List all file shares

![Oorend AD account password reuse](/Pen-testing-blog/assets/images/Rebound/OorendAccountPasswordReused.png "Figure 16 - Oorend account password reuse")

## Step 4 - Lateral movement to WinRM_SVC AD account

### AD domain enumeration with Bloodhound

As I can see no other obvious method for further domain compromise, I enumerate the domain objects using the Bloodhound tool. The first step is to ingest AD domain objects with a AD ingestor tool like Rusthound. Syntax is as follows in Figure 17 below along with successful ingestion output in a zip file.