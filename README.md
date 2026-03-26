# HTTP-Splunk-Log-analysis

Title: Splunk HTTP Log analysis

Analyst: Savon Masters 

Date: February 2nd, 2026

					                                    Summary
          
At April 25th, 2025 6:49 am I received an error of different selections of errors happening on the network.  I investigated to see the chain of events developing on the network.

					                                  Investigation

![image alt](https://github.com/SavonMasters/HTTP-Splunk-Log-analysis/blob/da49a37f14713b72f79c6a58770509b03f906242/Splunk%20HTTP%201.png)
I began my investigation by looking to see the complete amount of events for this log and how long it lasted. I did this by using the timeline.

 
![image alt](https://github.com/SavonMasters/HTTP-Splunk-Log-analysis/blob/054d53a25fc2ddad4d2410e24ac29f7fe1362d3f/Splunk%20HTTP%202.png)
Then, I am working with HTTP logs so I wanted to get the top source IP addresses. I wanted a general sense of who was generating the most traffic to the network devices. I used the “Stats count by id.orig_h | sort - count.”. 



Next, I wanted to see server errors on the network side to see how the IP addresses might be affecting the network. All server errors happen between 500. I made “Status.code >=500 status.code <600 | stats count as server_errors.” just to find the server error codes of 500.



Following that, I wanted to see the User agents of the IP addresses to verify if they were legitimate. I found 4 that were out of the normal. I did a google search and learned “Botneck-checker/1.0” is used for reconnaissance to see weak points in the CPU or GPU usage, “Curl 7.68.0” is used as a command-line tool to evade detection, exfiltrate data, and etc this is a MITRE technique of T1041, “Python-request 2.25.1” is used for credential exfiltration attacks over a HTTP server this is a MITRE technique of TA0006, and “Sqlmap 1.5.1”
 is used for Command and Control (C2) line to establish a connection while executing attacks this is the MITRE technique of T1071.001. The recognizable User agent’s actions and history emphasizes the HTTP network was being misused. 




As soon as I knew there were malicious User agents I wanted to see their actions on the system. It didn't seem to be any attacks inside the User agents. I typed “User_agent, | table ts, id.orig_h, method, uri.”.


To continue, I viewed the methods being used to see what other IP addresses were doing on the network. I found a lot of “Connect, Options, Delete, Put” requests which are not typically used.  I looked with “Method in CONNECT, OPTIONS, DELETE, PUT.” and returned the results . 



Moving on, I read over the Uris because I wanted to see possible entrance points on the network. I was alarmed to see how many Uris could be used to access confidential information from what would be inside of them. This is an open indicator of a File inclusion attack because the “./”’ is being directed to a private area of the Uri. I queried “Method IN uri (/admin, /etc/passwd, /config.php, /shell.php, /wp-admin, /phpmyadmin). | table ts, id.orig_h, id.resp_h, uri.” to present all results.  

Afterwards, I wanted to analyze for any large file transfers. I wanted to see what IP address was requesting a high response body, who they were making it too, where they were trying to get it, the method and user agent used, and the entire response body they wanted. This could be an exfiltration attack because large response bodies is a sign that an attacker is trying to exfiltrate data from the network. I searched “Resp_body_len >=50000 | table ts, id.orig_h, id.resp_h, uri, method, user_agent, resp_body_len | sort - resp_body_len.”.


				                                      	Conclusion 
Looking at the parts of the network I was able to see that attacks were real and were imposing on the security threat to the network. The attacks consisted of “Reconnaissance, data exfiltration, credential exfiltration, and a Command Control Server (C2)”. Those were what I was able to find but I would advise doing a rescan to see if any other attacks still ongoing. 


			                                  			IOCs
A  multitude of server errors from the status code of 500.
Often used malicious User agents to execute attacks. “Botnet-checker/1.0, Curl 7.68.0, Python-request 2.25.1, and Sqlmap 1.5.1”.
The User agents using the attacks of “Reconnaissance, data exfiltration this a MITRE code “T1041”, credential exfiltration this a MITRE code “TA0006”, and Command and Control Server (C2) this a MITRE code “T1071.001”.
Out of the regular methods being used. “Connect, Options, Delete, Put”.
The request to access potentially sensitive information inside of the URIs. beginning with a Local file inclusion attack this a a MITRE code “T1083”. 
A few requests for a large response body sizes that could be a possible large file transfer to a unknown source.

				Recomendations 
Create a Splunk alert to get server errors to immediately trouble shoot them.
Ingest worldly known User agents in an IPS to protect against known vulnerabilities.
Monitor request methods for source IP addresses and destination IP addresses making suspicious requests. 
Strengthen the network firewall to stop local file inclusion attacks from getting to private information.
Create a Splunk alert to scan over large response body sizes to see the data being requested and where they are trying to send the data to end large file transfers.
Below I imported the photos of the Users agent’s actions that were present on the system and the attacks that I found.
Towards the bottom I added the Splunk alerts for the server errors and the large body sized request.





			                                		Things I learned
Greater knowledge of the Splunk platform through SQL and tables.
Actively used malicious User agents and their actions.
Learned the descriptions of more MITRE attacks.
All the HTTP request methods that are most used.
Areas attackers would like to access inside of URIs to get confidential data. 
Connect the large body request amount to a file being transferred.
