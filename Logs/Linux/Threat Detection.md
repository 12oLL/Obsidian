Linux isn't the unhackable as most people might think. Threats and malware can exist on every system, but of course, there are ways to reduce the attack surface so you can reduce the chances of being compromised.

# SSH
Just like RDP on Windows, SSH is the most common method for initial access when it comes to Linux systems. As Linux is used for most servers and IoT devices, it can also be intruded. 

## How does it happen?
An exposed SSH is the beginning, leaving it open without authentication or having weak credentials that can be brute forced easily. 

**SSH Brute Force**

``` bash
May 10 02:14:11 kali-ssh sshd[1842]: Failed password for invalid user admin from 203.0.113.45 port 49822 ssh2  
May 10 02:14:13 kali-ssh sshd[1844]: Failed password for invalid user test from 203.0.113.45 port 49824 ssh2  
May 10 02:14:15 kali-ssh sshd[1846]: Failed password for root from 203.0.113.45 port 49826 ssh2  
May 10 02:14:17 kali-ssh sshd[1848]: Failed password for root from 203.0.113.45 port 49828 ssh2  
May 10 02:14:19 kali-ssh sshd[1850]: Failed password for root from 203.0.113.45 port 49830 ssh2  
May 10 02:14:21 kali-ssh sshd[1852]: Failed password for root from 203.0.113.45 port 49832 ssh2  
May 10 02:14:23 kali-ssh sshd[1854]: Failed password for root from 203.0.113.45 port 49834 ssh2  
May 10 02:14:25 kali-ssh sshd[1856]: Failed password for root from 203.0.113.45 port 49836 ssh2  
May 10 02:14:27 kali-ssh sshd[1858]: Accepted password for root from 203.0.113.45 port 49838 ssh2  
May 10 02:14:27 kali-ssh sshd[1858]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
```

As we can see the common brute force sign of multiple failed logins at the same time with few seconds in difference, it could be manual or automated. The user eventually gains access to **root** and a session is opened.

# Detection Methods
It is pretty simple to investigate for such type of behavior. We will strictly use the terminal as it is more straightforward without needing to know too much. If you are new to Linux logs take a look [here](https://github.com/12oLL/Labz/blob/main/LogAnalysis/Linux/Logging%20in%20Terminal.md) so you are prepared better.

![[Accepted 1.png]]

Filtering for **Accepted** will give us the logins that approved and whether they were SSH keys or passwords. Talking about this seems easy, but what do we look for exactly that indicates a red flag?

- **Username**: Who is this person?
- **IP Address**: Is it internal or external?
- **Login Method:** When and how did this person get in? 

For IP addresses specifically, it can be of great assistance in knowing if someone logged in from within the network or not. Below is a guide:

- `10.0.0.0 – 10.255.255.255` (`10.0.0.0/8`)
- `172.16.0.0 – 172.31.255.255` (`172.16.0.0/12`)
- `192.168.0.0 – 192.168.255.255` (`192.168.0.0/16`)
- `127.0.0.0/8` = localhost
- `169.254.0.0/16` = link-local/APIPA

Now the next step is, should you continue to investigate this log or not? To know so, you connect the dots as i mentioned before. Combining the **time of the login**, **IP address**, and **actions done by user after login** will help you handle the situation better.

# Discovery
Most of the time attackers gain access and end up in a terminal via SSH for example. If you are in that position, what is the first thing you would do? Most likely you would use commands like *pwd* for instance to know where you are at and get to know where to go. 

This is the first step in discovery, to think like an attacker. Lets go through some common commands that should alert you. 

**OS and file system**: pwd, ls /, env, uname -a, lsb_release -a, hostname

**User and Groups**: id, whoami, w, last, cat /etc/sudoers, cat /etc/passwd

**Process & Network**: ps aux, top, ip a, ip r, arp -a, ss -tnlp, netstat tnlp

As you might have noticed, the commands mentioned are very common, so how would you know if it was used legitimately or by an unauthorized user? Thats our next step.

# Detecting Discovery
Motives of attackers vary, it can be credential harvesting, cryptomining, and other intentions. 

Detecting discovery can be done by several methods. First we configure **auditd** as we mentioned before [here](https://github.com/12oLL/Labz/blob/main/LogAnalysis/Linux/Logging%20in%20Terminal.md). We configure the rules to our liking by adding commands that alerts us when executed such as whoami, id, netstat and whatever else. 

Configuration of rules up to your needs.

![[auditd 1.png]]

After applying the rules, an alert will come out like this with the key equal to whatever you named it during the rules configuration. You can also filter using the keyword to search for specific triggered alerts like **discovery_user**.

![[ppid.png]]

As with everything else, context remains the most important key. The commands can be used by anybody, which is why you go further with the analysis to see who it was and what they did. You can do so by filtering logs using the **pid or ppid** to see what started and the processes following the parent process.

For instance over here, I filtered for the command of **id**, and below i can see the users that executed the command as well as go further with the analysis using the process id. 

![[idcom.png]]

Analyzing using PID

![[pid.png]]

Processes of PPID

![[ppidrez.png]]

When you find a process that interests you, such as a .sh shell, you can check the **cwd** option. Below is an example.

![[cwd.png]]

![[sh.png]]

As we can see, we found a script that was found to be executed when analyzed using auditd.

