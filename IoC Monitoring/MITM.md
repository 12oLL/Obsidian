Man-in-the-middle attacks is one of the most insidious threats in network security. It is 
a common attack by adversaries in a network to intercept, modify, or redirect traffic. 

A man in the middle attack generally involves two main steps:
**Interception**: To perform a MITM attack, the attacker needs to be on the network. To do so, the attacker inserts themselves int a communication stream, by exploiting vulnerabilities or performing IP, DNS, or ARP Spoofing.

**Manipulation/Decryption (or explotation)**: In this phase, the attacker uses the intercepted data for malicious purposes. For instance, sensitive information can be decrypted like poorly secured login credentials, modify or inject malicious code into transactions.  
# ARP Spoofing
Address resolution protocol (ARP) is a network protocol that maps IP addresses to MAC addresses in a local network. A device wanting to send data to another IP, it asks "Who has this IP?" The correct the device responds with its MAC address.
![[ARPz.png]]


![[ARP ATT.png]]
ARP Spoofing demonstration.


# DNS Spoofing 
DNS spoofing is another common attack adversaries use. While most of the time DNS traffic is allowed through firewalls and users use it every single day, it is hard to detect without needed knowledge and awareness.  