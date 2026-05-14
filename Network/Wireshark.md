This is my full guide to Wireshark. By understanding how packets travel, protocols, ports, and network traffic. This is helpful for any path you are pursing, whether its  SOC, pentest, or security engineer.  

## Wireshark
Wireshark is a standard tool for analyzing and monitoring network traffic. It can be of great value to those who understand what they are seeing. It shows data packets being sent and received over the network. IPs and MAC addresses on the network. You can use it for troubleshooting network issues and slow connections, as well as detect suspicious or malicious activity. After understanding the usual type of traffic and addresses, you will be able to tell when unusual traffic is occurring.

## Protocols
Before we start, below is a list of protocols you need to be familiar with. These are very common on any network traffic. Understanding protocols and how they work is essential before proceeding to analyze them.

**ICMP** - Used for diagnosing and reporting network communication issues. Important for spotting C2 tunnels and DoS attacks.

**HTTP** - Hypertext transfer protocol is an older insecure version of websites. Preceded by **HTTPS**.

**DNS** - Foundational protocol that  translate websites IP addresses into human-readable names.

**FTP/SFTP** - File transfer protocol used to transfer files over networks. SFTP is the secure version using **SSH**.

**SNMP** - Manages and monitor network devices across IP networks.

**SMB** - Server message block.

**TCP**  - Transmission control protocol used for ensuring connection over the internet.

**UDP** - User datagram protocol, unlike **TCP**, it does not ensure the packets to reach their destination. Mostly used for services such as streaming, which needs speed over accuracy of every packet reaching.

**SMTP** - Used for sending and routing emails.

**IMAP/POP3** - Email protocols used for retrieving and managing emails.

**ARP** - Used to map an IPv4 address to its corresponding MAC address.

**TLS** - Cryptographic protocol that ensures secure communication over the network.

## GUI
Lets say you understand the protocols and have knowledge about the OSI model, then you see this when you start  sniffing (capturing traffic).