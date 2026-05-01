As a SOC analyst looking for data exfiltration, there is multiple methods to spot such activities by analyzing network traffic, monitoring cloud, and checking host activities like Powershell being executed and many more. Here are some of the methods and guides to where to look and what to look for there.  

# What is data exfiltration?
Data exfiltration is the process of unauthorized transfer of data of sensitive information from a device, network or computer to an outside destination without permission.  Data exfiltration is the last stage in the cyber kill chain, where the attacker exports the data of the victim.

# Indicators and techniques

**Network-based** 
For a network-based attack, you'd want to look after the following:
1- HTTP/HTTPS uploads to cloud services
2- FTP,SFTP,SCP,DNS tunnelling
3- ICMP/covert protocols
4- custom TCP/UDP

**IoC & Where to look** 
1- Proxy and web gateway logs (large POSTs, uploads to cloud endpoints).
2- Firewall/NGFW flows (high bytes to single IP/ASN).
3- Netflow (Spikes/outbound flows).
4- DNS logs (Long hostnames, TXT queries).

**Host-based**:
Powershell invoking web requests
rclone
awscli
curl/wget
archive creation (.zip,.rar)
use of removable USBs
ADS/hidden streams.

**IoC & Where to look**
1- Sysmon/EDR (Process Create, Network Connect, File Create, events)
2- Windows Security (4663/4656 object access)
3- auditid/shell history on Linux and removable-media events.

**Cloud exfiltration**
1- S3 PutObject / multipart upload.
2- Azure Blob uploads.
3- Google Cloud storage obejcts.
4- Insert Drive/SharePoint external sharing.

**IoC & Where to look** 
1- CloudTrail / Azure activity / GCP Audit.
2- Cloud storage access logs.
3- Unusual service account or IP activity.

**Covert & encoding**
1- DNS tunnelling.
2- Base64 or chunked encoding.
3- Steganography into images/audio.
4- Splitting files into many small requests (low-and-slow).

**IoC & Where to look:**
1- DNS logs.
2- Proxy logs with many small POSTs.
3- Correlation of intermittent uploads + suspicious process activity.

**Insider & collaboration tools**
1- Slack/Teams/DropBox/Google Drive/Box uploads or sharing to external users.
2- Compromised employee accounts.

**IoC & Where to look**
1- Audit logs (Share events, file downloads).
2- Mail logs.

**Genreal IoAs & triage signals**
1- Large outbound volume to external IPs/Domains.
2-  Unknown destination domains.
3- Suspicious processes/command lines.
4- Many file read events followed by an outbound conneciton.
5- Multipart/streamed uplods.

**IoC & Where to look**
1- Correlate : Proxy/Firewall/Netflow.
2- DNS.
3- Sysmon/EDR (EventID 1/3/11).
4- Mail server logs.

Data exfiltration is a high-impact threat that combines opportunistic methods, legitimate tools and creative covert channels to move sensitive assets outside an organisation. Effective detection requires focus on single-alerts and more on rapid correlation across host, network and cloud telemetry. By doing that, you identify who accessed data, what was transferred, how and where it was sent.

# DNS
DNS tunnelling is one of the most common ways adversaries exfiltrate data. It is used for transferring data from a host device to a suspicious usually long domain (30+ characters) with many requests to that domain without a response. 
## **IoA**
- Many DNS queries are sent to a single external domain, especially with very high counts.
- Long subdomain labels or unusually long full query names (>60-100 characters).
- High entropy or Base32/Base64-like patterns in the query name (lots of mixed up case letters, - and = are signs of Base64).



# FTP
FTP is one of the oldest protocols for transferring files. Attackers use it to transfer large amount of data off a network, often via compromised credentials or misconfigured servers. The detection relies on a mix of packet inspection (FTP), server logs, SSH session metadata, and network flow/size/pattern analysis.

## IoA
What to look for:
**USER** and **pass** commands (cleartext credentials).
**Stor** (upload) and **RETR** (download) commands; repeated or large transfers.
Large data connections to unusual external IPs, especially outside business hours.
Data channel opening on ephemeral ports (PASV) paired with large payloads.

## Isolating FTP control & data
First, lets filter to find FTP only, using the Wireshark filter ***ftp || ftp-data*** 
![[WS FTP.png]]
This will only give us FTP control traffic

## Looking for credentials
To filter to only login attempts you type ***ftp.request.command == "USER" || ftp.request.command == "PASS"***
![[FTP Creds.png]]
This will give us login attempts showing USER and PASS
#### Searching anomalies
When data is being exfiltrated via FTP, the data is harvested and stored in extensions such as .txt , .pdf or csv. To look for anomalies, we type ***ftp contains "STOR"***. STOR is a command indicating an upload, and **RETR** is download.

![[11.png]]
To get a better view of the TCP stream, right-click on the packet --> Follow --> TCP Stream. This will give you the following clearer view. 
![[TCP follow.png]]
![[Screenshot_2026-03-25_21-16-03.png]]

To search for a specific extension you can use the command ***ftp contaisn "csv"***. You will receive packets where data is being stored in a comma-separated values file (csv).
![[1222.png]]

#### Payloads
A big indicator of a FTP attack is a large payload size. To search and identify such payloads, we use the capture filter ***ftp && frame.len > 90***. 
![[fff.png]]
When it comes to payloads, a size of < 200 bytes isnt suspicious, but in this case the context matters. In this case, we can see a login attempt through a default username guest and a weak password guest as well.
After the successful login attempt, STOR command is being used to send data to a .csv file. The data being sent is THM{ftp_exfil_hidden flag}, which is a CTF from a THM lab in this case, but this is the demonstration of how data exfiltration through FTP would look like in real-world scenarios. 


# HTTP
Data exfiltration vita HTTP is when an attacker moves sensitive data out of a target network using HTTP as transport. HTTP is a commonly abused protocol because it blends with normal web traffic, can traverse firewalls and proxies, and can be obfuscated (encoding, encryption, tunnelling). To detect a HTTP attack as SOC analysts, we aim to identify signs of HTTP-based exfiltration in packet captures using **Wireshark** and logs using **Splunk**.

Identifying and responding to HTTP attacks is important due to the following reasons:
- HTTP attacks are very common. Attackers hide exfiltration in the noise of legitimate web usage.
- Successful detection stop data breaches and help trace attacker activity post-compromise.
- Organizations must detect and respond to protect sensitive data and meet compliance requirements.
## How is HTTP used for data exfiltration
To detect HTTP attacks, we need to look for and understand the following request methods. The following are methods attackers use and indicators to look for.

- **POST Uploads**: A common request method to send data to a server. A suspicious POST request is a large amount of data being sent to a attacker-controlled host or cloud storage.
- **GET Requests**: GET requests with encoded data is a common technique adversaries use. Data being squeezed into query strings or path segments for low-and-slow exfiltration. 
- **Use of common services**: Exfiltration masked as uploads to popular services or attacker-controller subdomains under reputable domains.
- **Chunked transfer/multipart**: Large payloads split into multiple requests to avoid size thresholds.
- **HTTPS/TLS tunnelling**: The encrypted channel hides the payload. Detection requirest TLS inspection, SNI analysis, or metadata-based detection
- **Staging via cloud services**: Uploading to trusted cloud services like Dropbox/Github/Gist and then fetch externally.

Lastly, it is important to take note that not all attacks are sudden and will be spiked on a network traffic. Most of the time it could be a low-and-slow approach, where adversaries take their time encrypting/encoding, and use legitimate services to evade detection. This is why connecting the dots and gathering context is the key approach during analysis.

## IoA
**Common network indicators**:
- Unusually large HTTP POST requests to external and unexpected hosts.
- HTTP requests to domains with low reputation or uncommon in daily traffic.
- Frequent small requests (beaconing) to the same host followed by a large upload.
- Chunked or multipart transfers where requests compose large files.

## Wireshark HTTP analysis
We can use Wireshark to analyze ad look for HTTP attacks. We start by filtering to only HTTP traffic using the **http*** filter. After that, we go ahead and filter out an HTTP method like POST **http.request.method == "POST" &&/and frame.len > 300***.

As we can see in HTTP Stream, a POST upload to github.com with the 
Lets break the filter down:
**http.request.method** : Filtering specific methods such as POST,GET or HEAD.
**frame.len**: Filters out a specific frame length, a large frame length could be an indicator to an attack.
Tip: Check out the TCP/HTTP stream of the packet for cleartext details.
# ICMP
ICMP is a network layer protocol used for diagnostics and controls like **ping**. Because it is commonly allowed through firewalls and typically inspected less strictly than TCP/UDP, ICMP can be abused to tunnel and exfiltrate data. Malicious actors encode data into ICMP payloads (echo request/reply, timestamp,info) and send it to a remote listener under their control.
## How ICMP is used for exfiltration
- **ICMP echo (type 8) / reply (type 0) tunnelling**: Attackers place encoded **base64** or **hex** chunks of files inside **ICMP** payloads. 
- **Custom ICMP types/code**: Using uncommon ICMP types or non-zero codes to avoid signature-based detections.
- **Fragmentation & reassembly**: Large payloads split across multiple packets
- **Encryption/obfuscation**: Encrypting payloads e.g using base64 to look like random data.
## Indication of maliciousness
- Persistent ICMP sessions to an external host not used for legitimate monitoring.
- Unusually large ICMP payloads or frequent ICMP with payload larger than a typical ping size.
- ICMP payloads that contain high-entropy data or patterns consistent with base64/hex.
- Bursts of ICMP immediately followed by no other legitimate application traffic from the same host.

## Wireshark analysis
Again, Wireshark can be used for analyzing ICMP packets. It is important to know where to look and what to identify while analyzing.
## IoA
- **ICMP packet volumes**: A single host sending large amount of ICMP echo requests to an external IP.
- **Large frame.len or icmp.payload**: Pings with payloads much larger than the typical (e.g > 64 bytes).
- **ICMP type/code unusual values**: Unusual use of timestamp (13/14) or custom codes.
- **Periodicity**: even timing of ICMP packets carrying similiar-sized paylods.
- Multiple ICMP fragments from the same src/dst pair. 

Using the capture command ***icmp.type == 8 && frame.len > 100***, we receive malicious packets, as a usual ICMP ping is ~74 bytes, which makes anything above a 100 bytes suspicious.  
![[21.png]]
As we can see, this packet has 148 bytes, which is way over the usual ICMP bytes. The text is in hex but it is truncated in cleartext on the right side.
# Conclusion
Data exfiltration through DNS,FTP, and HTTP and other protocols usually does not have one big red flag to look for that indicates an IoA/IoC, but rather analyzing multiple factors and connecting the dots, which is a common approach in network traffic analysis. Knowing where and what to look for is the important part, allowing you to find the malicious actor and respond accordingly.