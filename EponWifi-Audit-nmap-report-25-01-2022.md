
### wifi-Sec-Audit-nmap-report-25-01-2022.md
```
CH  2 ][ Elapsed: 6 s ][ 2022-01-25 04:43 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID
 38:94:E0:AF:AA:19  -59       15       26    2   4  130   WPA2 CCMP   PSK  EponWifi
```
* command was :- nmap --script vuln 192.168.1.0/24
```
┌──(vyshu㉿kali)-[/home/kali]
└─$ nmap --script vuln 192.168.1.0/24

Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-25 03:01 EST
Nmap scan report for RTK_GW.domain.name (192.168.1.1)
Host is up (0.039s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT    STATE    SERVICE
21/tcp  filtered ftp
23/tcp  open     telnet
53/tcp  open     domain
80/tcp  open     http
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=rtk_gw.domain.name
|   Found the following possible CSRF vulnerabilities:
|
|     Path: http://rtk_gw.domain.name:80/
|     Form id: username
|     Form action: /boaform/admin/formLogin_en
|
|     Path: http://rtk_gw.domain.name:80/diag_index_en.html
|     Form id: username
|_    Form action: /boaform/admin/formLogin_en
|_http-majordomo2-dir-traversal: ERROR: Script execution failed (use -d to debug)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| http-enum:
|_  /admin/login.asp: Possible admin folder
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-slowloris-check:
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
139/tcp filtered netbios-ssn
445/tcp filtered microsoft-ds

Nmap scan report for Galaxy-A50s.domain.name (192.168.1.2)
Host is up (0.013s latency).
All 1000 scanned ports on Galaxy-A50s.domain.name (192.168.1.2) are in ignored states.
Not shown: 1000 closed tcp ports (conn-refused)

Nmap scan report for home-PC.domain.name (192.168.1.3)
Host is up (0.044s latency).
Not shown: 985 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
554/tcp   open  rtsp
2869/tcp  open  icslap
9999/tcp  open  abyss
10000/tcp open  snet-sensor-mgmt
| http-vuln-cve2006-3392:
|   VULNERABLE:
|   Webmin File Disclosure
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2006-3392
|       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
|       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
|       to bypass the removal of "../" directory traversal sequences.
|
|     Disclosure date: 2006-06-29
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392
|       http://www.exploit-db.com/exploits/1997/
|_      http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure

10243/tcp open  unknown
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap scan report for kali.domain.name (192.168.1.7)
Host is up (0.00036s latency).
All 1000 scanned ports on kali.domain.name (192.168.1.7) are in ignored states.
Not shown: 1000 closed tcp ports (conn-refused)

Nmap scan report for I2018.domain.name (192.168.1.8)
Host is up (0.057s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
1046/tcp filtered wfremotertm
1718/tcp filtered h323gatedisc

Nmap scan report for Server.domain.name (192.168.1.9)
Host is up (0.019s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
554/tcp   open  rtsp
808/tcp   open  ccproxy-http
2869/tcp  open  icslap
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
7070/tcp  open  realserver
9000/tcp  open  cslistener
9999/tcp  open  abyss
10243/tcp open  unknown

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

Nmap scan report for 192.168.1.10
Host is up (0.020s latency).
All 1000 scanned ports on 192.168.1.10 are in ignored states.
Not shown: 1000 closed tcp ports (conn-refused)

Nmap scan report for DESKTOP-2KL6JDA.domain.name (192.168.1.15)
Host is up (0.048s latency).
Not shown: 990 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
554/tcp   open  rtsp
2869/tcp  open  icslap
5357/tcp  open  wsdapi
7070/tcp  open  realserver
9000/tcp  open  cslistener
9999/tcp  open  abyss
10243/tcp open  unknown

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false

Nmap done: 256 IP addresses (8 hosts up) scanned in 330.18 seconds
``` 
 audited by [Vaishnavu cv](https://linkedin.com/in/vaishnavucv/)
            [instagram](https://www.instagram.com/hack_with_vyshu/)
