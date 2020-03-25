# CTF-Helper
The custom scripts I've made to complete capture the flag challenges quicker. Everything is contained in a single file, "helper.py". "requests" and "paramiko" are the only required external libraries. These can be installed by "pip install requests paramiko".

## What does it do?
These scripts are highly targeted toward a certain machine but for some tools, a target may be specified with certain parameters. The program can perform the following...

1. A TCP Port Scanner w/ version checking and CVE search
2. Blind SQL Injection
3. Directory Brute Force 
4. Regex search from website page 
5. A /var/log/auth.log IP deleter 
6. SSH Brute Force (Dictionary) 
7. Quick Info (Displays system info, as well as quickly executes and outputs the result of Linux commands)
8. Malware Scanner (A VirusTotal API Key MUST be specified at beginning of file)
9. XOR Decryption (Highly tagreted based on cipher text and key length) 
