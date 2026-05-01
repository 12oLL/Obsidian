Logs are records of past events that provide insights to address malicious activities.

# Log Types
There are many types of logs, here are the most common ones:
- Application Logs: Messages about specific applications, including status, errors, and warnings
- Audit Logs: Activities related to operational procedures crucial for regulatory compliance.
- Security Logs: Security events such logins, permission changes, firewalls activity etc
- Server Logs: Various logs a server generates, including system, event, error, and access logs
- System Logs: Kernel activities, system errors, boot sequences, and hardware status
- Network Logs: Network traffic, connections, and other network-related events
- Database Logs: 
- Web Server Logs

# Sysmon
System Monitor is a Windows system service and device driver that once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It can be utilized to identify malicious or anomalous activity and get a grasp on how malware can operate on your network.

Sysmon is commonly used with an SIEM system or other log parsing solutions that aggregate, filter, and visualize events. Once installed on an endpoint, it will start early in the Windows boot process. 

## Event IDs
Knowing crucial Event IDs can help you filter and detect what you are looking. You can filter using Windows Event Viewer.
**EventID 1: Process Creation**
This event looks for processes that have been created. It can be used to look for known suspicious processes or processes with typos that would be considered an anomaly.
This event will use the CommandLine and Image XML tags.
```xml
`<RuleGroup name="" groupRelation="or">
   <ProcessCreate onmatch="exclude">
        <CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel  -p -s camsvc</CommandLine>
           </ProcessCreate>
              </RuleGroup>`
```

The above code snippet is specifying the Event ID to pull from as well as what condition to look for. In this case, it is excluding the svchost.exe process from the event logs.

**Event ID 3: Network Connection**
The network connection event looks for events that occur remotely. This will include files and sources of suspicious binaries as well as opened ports. This event will use the Image and DestinationPort XML tags.
```xml
<RuleGroup name="" groupRelation="or">  
<NetworkConnect onmatch="include">  
  <Image condition="image">nmap.exe</Image>  
  <DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>  
</NetworkConnect>  
</RuleGroup>
```

This code includes two ways to identify suspicious network connection activity. The first way will identify files transmitted over open ports. As you can see, we are specifically looking for **nmap.exe**. The second method identifies open ports specifically **port 4444** which is commonly used with Metasploit.

**Event ID 7: Image Loaded**
This event looks for DLLs loaded by processes, which is useful when hunting for DLL injection and DLL hijacking attacks.
```xml
<RuleGroup name="" groupRelation="or">  
<ImageLoad onmatch="include">  
  <ImageLoaded condition="contains">\Temp\</ImageLoaded>  
</ImageLoad>  
</RuleGroup>
```

This code snippet will look for any DLLs that have been loaded within the \Temp\ directory. If a DLL is loaded within this directory it can be considered an anomaly and should be further investigateded.

Below is a list of more Sysmon Event IDs that can help with further analysis:
**11/13**: File Create/ Registry Value Set. This detects files dropped by malware and changes made to the registry.
**3/ 22**: Network Connection / DNS Query. This detects processes from untrusted sources or known malicious destinations.
# Windows Security Monitoring

**4624 & 4625**
**Logon Type** is the login method. Knowing the logon type can help further with the analysis, knowing where to go after knowing this step. Below is a list of logon types.

```bash
2: Interactive logon (logon at keyboard and screen of system)
3: Network (connection to a shared folder on the computer from elsewhere on network)
4: Batch (scheduled task)
5: Service (service startup)
7: Unlock (unattended workstation with password protected screen saver)
8: NetworkCleartext (logon with credentials sent in clear text. Most often indicates a logon to IIS with "basic authentication")
9: NewCredentials such as with RunAs or mapping network drive with alternate credentials. This logon type does not seem to show up in any events. To check if users are attempting to logon with alternate credentials, check for 4648. 
10: RemoteInteractive (Terminal Services, RDP, or Remote Assistance)
11: CachedInteractive (logon with cached domain credentials such as logging on to a laptop when away from the network)
```

## Detection Methods
In this chapter, i will share methods on how to detect malware and abnormal behavior. This will be done in Event Viewer & PowerShell.
### Detect Mimikatz
Detect file creation with the name Mimikatz. Unlikely, but still possible.
**Event Viewer:**
```xml
<RuleGroup name="" groupRelation="or">  
<FileCreate onmatch="include">  
<TargetFileName condition="contains">mimikatz</TargetFileName>  
</FileCreate>  
</RuleGroup>
```
### Detect Abnormal LSASS Behavior
**Event Viewer:**
```xml
<RuleGroup name="" groupRelation="or">  
<ProcessAccess onmatch="include">  
       <TargetImage condition="image">lsass.exe</TargetImage>  
</ProcessAccess>  
</RuleGroup>
``` 
**PowerShell:**
```xml
`<RuleGroup name="" groupRelation="or">   <ProcessAccess onmatch="exclude">   <SourceImage condition="image">svchost.exe</SourceImage>   </ProcessAccess>   <ProcessAccess onmatch="include">   <TargetImage condition="image">lsass.exe</TargetImage>   </ProcessAccess>   </RuleGroup>
```
## Malware Detection
Detecting malware 

**Structure of 4624**
![[4624E.png]]

**1**: The logon type is **2**, which falls under interactive logon.
**2**: This is the actual user logged in. Take note of the Logon ID.
**3**: Network information of the device. It is always more accurate to take note of the source IP address rather than the hostname.
**4**: The Event ID 4624, which indicates a successful logon.
As we can see, gathering information and connecting the dots leads finding the unauthorized login or other anomalous behavior.

Below is  a list of common event IDs to use for further investigation:
**4720/4722/4738**: These IDs indicate that a user account was created/ enabled/ changed (In order of the Event IDs). Adversaries might create a backdoor or enable an old unused account to avoid detection.

**4725/4726**: A user account was disabled/ deleted. Attackers may disable privileged SOC accounts to slow down their movement. 

**4723/4724**: A user changed their password / User's password was reset. With enough permission gained, threat actors might reset the password and then access the required user.

**4732/4733**: A user was added to/ remove from a security group. Malicious actors often add backdoor accounts to privileged groups like Administrators. 

**Quick Tip**
**Logon IDs** can be helpful to match across multiple events. For example, Logon IDs are written in hex. Lets take the logon id **0x3e7**. Converted to decimal its **999**. Converting doesnt reveal much, but matching it across multiple events is the key. Look for **0x3e7** Logon events (4624), privilege use, process creation and logoffs (4634). If two events same the share Logon ID, they belong to the **same session**. 

