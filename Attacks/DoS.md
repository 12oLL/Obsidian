# Introduction
Denial-of-service is a type of attack that is done by either a single device from a single network, or multiple devices to flood a website or a web application with massive amount of requests, leading to a disruption in the servers.
# DoS

![[DoS.png]]

A DoS attack, is considered successful if it prevents a web service from functioning as it should. Let's see how a simple DoS attack can cause a great impact. 

Suppose you have a website for selling your own publications. In your site, you have a search form. This search form takes user input and perform queries to the database to return a result. A simple feature that should be normal. If the search form doesn't validate or handle user input correctly, a malicious user can abuse the search bar by sending many or a single massive request that causes a DoS outage.   
# DDoS

![[DDoS.png]]

We have discussed DoS, now its time for the big brother, DDoS. They both work the same way, only that a DDoS work more efficiently, with an increased success rate. A DDoS works by sending requests the same way a DoS does, only with a large amount of devices referred to as *botnets*. A botnet is a collection of compromised devices such as computers, IoT devices, and even servers hijacked by malware. The attacker controls them via a Command and Control server (C2), sending them instructions to execute.

# Types of Denial-of-Service Attacks
**Slowloris**: Sending many partial HTTP requests and not completing them.
**HTTP Flood**: Sending a large number of HTTP requests to overwhelm the server.
**Cache Bypass**: Bypassing CDN edge servers and forcing the origin server to respond.
**Oversized Query**: Forcing the server to process large, resource intensive requests.
**Login/Form Abuse**: Overloading authentication logic with login attempts of password resets.
**Faulty Input Validation Abuse**: Exploiting poorly designed input handling.
# Log Analysis
Now we know what are DoS and DDoS attacks, lets move on to how we can spot them.
Web servers are valuable due to logs. Every major web service records web requests in a log format. Examining these logs can help you identify suspicious behavior.
## Indicators of attack
**High Request Rate**: 192.168.100.244 -> 1000 GET/login.
**Description**: A resource-heavy page like `/login` is flooded with requests to overwhelm authentication processes. Login pages are common targets since each request may trigger password checks and database queries.

**Odd User-Agents**: curl/7.6.88 -> /index repeatedly.
**Description**: Attackers spoof outdated or unusual User-Agents to blend in or bypass filters. Spotting traffic with tools like `curl` or `Python-urllib/3.x`, for example, can be a red flag for automated attacks.

**Geographic Anomalies**: IP address origins dotted around the world.
**Description**: Legitimate traffic typically comes from a few regions where real users are located. A globally distributed botnet may utilize IP addresses from around the world

**Burst Timestamps**: 80 requests in 3 seconds -> /search 
**Description**: A sudden spike of requests packed into the same second creates an unnatural traffic pattern that points to automation.

**Server Errors (5xx)**: A significant spike of 503 Service Unavailable errors.
**Description**: A sudden surge of server error responses (`500` - `511`) indicates resources are maxed out and the service is struggling under attack traffic.

**Logic Abuse**: GET /products?limit=999999.
**Description**: Attackers craft queries that overload the server, forcing it to load huge amounts of information and slowing it down for everyone.

![[DoS 1.png]]

In this log, we can see the normal behavior from different users. Take a look at the underlined IP address. We start seeing unusual behavior from the user of `203.12.23.195`. Lets break the log down and see what actually occurred and why its unusual.
- **203.12.23.195**: A user started sending GET requests.
- **Timestamp**: Timestamp shows multiple requests at the same time.
- **/login**: The page the user is sending requests to.
- **curl/7.88.1**: The user-agent of the user.

Now, why is this weird? As we saw, the logs looked normal before this user joined in. Random pages requested, multiple users, and usual user-agents such as Mozilla. The red flag is the massive amounts of GET requests to the /login page using the outdated curl user-agent. Lets see what happened after the requests this user made.

![[503.png]]
As we can see, the site became unresponsive. We can see that by the status code 503 that the users are receiving when querying, indicating no response.
