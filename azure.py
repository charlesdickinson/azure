#!/usr/bin/env python
import os
import sys
import tkFileDialog
import getpass
import telnetlib
import pexpect
import pxssh

#Implement this http://askubunt.com/questions/52138/how-do-i-change-the-icon-for-a-particular-file-type
global identity
global ipdb
global authenticated
authenticated = False
global flag
flag = 'Syndicasia'

ipdb = [
    ['b', 'f', 'baffle', '192.168.56.2']
]

def menu ():
    print 'Select from the following options:\n'
    print '1) Status Screen'
    print ':( Service Control' # Todd is doing this one
    print '3) Keychain'
    print '4) Encryption'
    print '5) Services'
    print '6) Network Assets'
    print '7) Fix routing tables'
    print '8) Miscellaneous'
    print 'q) Quit this program\n'
    menu = raw_input('Enter your selection: ')
    print '\n'
    return menu

def action (menuchoice):
    if menuchoice == '1':
        assetmonitor ()
    elif menuchoice == '2':
        vmcontrol ()
    elif menuchoice == '3':
        keymenu ()
    elif menuchoice == '4':
        crypto ()
    elif menuchoice == '5':
        services ()
    elif menuchoice == '6':
        lookup ()
    elif menuchoice == '7':
        routings ()
    elif menuchoice == '8':
        setup ()
    elif menuchoice == 'q':
        print 'Glory to Syndicasia!'
    else:
        os.system("clear")
        print "That wasn't a command, try again.\n"
        
def setup():
    os.system("clear")
    print 'Select from the following options:'
    print '1) Add azure as a bash command'
    print ':( Transfer SSH credentials'
    print ':( Bulk encrypt a file'
    print '4) Update your device tables'
    choice = raw_input("Enter your selection: ")
    if choice == '1':
        os.system("touch azure")
        os.system("echo '#!/bin/bash' >> azure")
        wd = os.popen("pwd").read().replace('\n','')
        os.system("echo 'python %s/azure.py' >> azure" %wd)
        os.system("sudo rm /usr/bin/azure")
        os.system("sudo mv azure /usr/bin/")
        os.system("sudo chmod +x /usr/bin/azure")
        os.system("clear")
    elif choice == '2':
        print 'Hokay'
    elif choice == '3':
        print 'Hokay'       
    elif choice == '4':
        ipupdate()
        
def ipupdate():
    global ipdb
    try:
        ipdb = sshlist('baffle', "ipdb.txt")
        print ipdb
    except:
        print '\nHad a bad time connecting, squire!\n'

def unamelookup(service):
    global authenticated
    global keychain
    if authenticated == False:
        authenticate()
    for n in xrange(len(keychain)):
        if keychain[n][0] == service:
            return keychain[n][1]
    return False

def iplookup(service):
    global ipdb
    for n in xrange(len(ipdb)):
        if ipdb[n][2] == service:
            return ipdb[n][3]
    return False

def pwdlookup(service):
    global authenticated
    global keychain
    if authenticated == False:
        authenticate()
    for n in xrange(len(keychain)):
        if keychain[n][0] == service:
            return keychain[n][2]
    return False
        
def assetmonitor(): #Here Randy
    assetlist = sshlist('baffle', '~/assets.txt')
    print assetlist
    print "Ping: " + str(pingcheck('baffle'))
    print "Web:  " + str(webcheck('baffle'))
    print "SSH:  " + str(sshcheck('baffle'))
    print "FTP:  " + str(ftpcheck('baffle'))
    
def sshlist(service,filepath):
    session = pxssh.pxssh()
    session.login(iplookup(service), unamelookup(service), pwdlookup(service))
    session.sendline("cat %s" %filepath)
    session.prompt()
    filecat = session.before.splitlines()
    del filecat[0]
    for n in xrange(len(filecat)):
        filecat[n] = filecat[n].split('|')
    return filecat
        
def pingcheck (service):
    try:
        check = os.popen('ping -c 1 %s' %iplookup(service)).read()
        if '1 received' in check:
            return True
        else:
            return False
    except:
        return False

def webcheck (service):
    try:
        tn = telnetlib.Telnet(iplookup(service), 80)
        tn.read_until("'^]'.")
        tn.write('GET')
        if flag in tn.read_all:
            return True
        else:
            return False
    except:
        return False

def sshcheck (service):
    try:
        session = pexpect.spawn("ssh %s@%s" %(unamelookup(service),iplookup(service)))
        i = session.expect(["assword", "EDCSA", "route to host", "timed out", flag])
        if i == 0:
            session.sendline(pwdlookup(service))
            j = session.expect([flag, "wrong"])
            if j == 0:
                return True
            elif j == 1:
                return False
        elif i == 1:
            session.sendline("yes")
            j = session.expect(["assword", flag])
            if j == 0:
                session.sendline(pwdlookup(service))
            elif j == 1:
                return True    
        elif i == 2:
            print "You not connected properly buddy"
            return False
        elif i == 3:
            print "So I reckon the machine is there, it's just not responding"
            return False
        elif i == 4:
            return True
    except:
        return False
    
def ftpcheck (service):
    try:
        session = pexpect.spawn("ftp %s" %iplookup(service))
        session.expect('ame .*: ')
        session.sendline(unamelookup(service))
        session.expect('assword:')
        session.sendline(pwdlookup(service))
        session.expect('ftp>')
        if flag in session.before:
            return True
        else:
            return False
    except:
        return False
    
def ipfind (code):
    code = code.lower()
    global ipdb
    for n in xrange(len(ipdb)):
        if ipdb[n][2] == code:
            return n
        elif ipdb[n][0] + ipdb[n][1] == code:
            return n
    return ('fail')
    
def vmcontrol ():
    os.system("clear")
    print "I can't do that Dave\n"
    
def keymenu ():
    global identity
    global keychain
    global authenticated
    os.system("clear")
    print "Select an option;"
    print "1) View all your passwords"
    print "2) Find a password"
    print "3) Add a password"
    print "4) Add a generated password"
    print "5) Create your keychain"
    print "6) Distribute keychains"
    print "x) Wipe your keychain"
    choice = raw_input("Enter your selection: ")
    if choice == '1':
        if authenticated == False:
            authenticate()
        print "#  | Service         | Username       | Password"
        print "---|----------------+----------------+----------------"
        for n in xrange(len(keychain)):
            print str(n).ljust(3) + '| ' + keychain[n][0].ljust(16) + '| ' + keychain[n][1].ljust(15) + '| ' + keychain[n][2]
        if len(keychain) > 0:
            clippo = raw_input("Enter a number to copy password to clipboard: ")
            if clippo != '':
               os.system("echo -n %s | xclip" % keychain[int(clippo)][2])
    elif choice == '2':
        if authenticated == False:
            authenticate()
        search = raw_input("Enter a string to search for: ")
        print "#  | Service         | Username       | Password"
        print "---|----------------+----------------+----------------"
        for n in xrange(len(keychain)):
            if search in keychain[n]:
                print str(n).ljust(3) + '| ' + keychain[n][0].ljust(16) + '| ' + keychain[n][1].ljust(15) + '| ' + keychain[n][2]
        if n > 0:
            clippo = raw_input("Enter a number to copy password to clipboard: ")
            if clippo != '':
               os.system("echo -n %s | xclip" % keychain[int(clippo)][2])
    elif choice == '3':
        if authenticated == False:
            authenticate()
        service = raw_input("Enter your service name: ").replace(' ','')
        uname = raw_input("Enter your username: ").replace(' ','')
        paswwd = raw_input("Enter your password: ").replace(' ','')
        keychain.append([service, uname, paswwd])
        keychainwrite()
    elif choice == '4':
        if authenticated == False:
            authenticate()
        service = raw_input("Enter your service name: ").replace(' ','')
        uname = raw_input("Enter your username: ").replace(' ','')
        plength = raw_input("How long do you like it?")
        paswwd = os.popen("openssl rand -base64 %s" %plength).read()[:int(plength)]
        os.system("echo -n %s | xclip" % paswwd)
        print ("Your password is %s and it has been copied to the clipboard" %paswwd)
        keychain.append([service, uname, paswwd])
        keychainwrite()
    elif choice == '5':
        if os.path.isfile(os.getenv("HOME") + "/.ssh/keychain_%s.blu" %identity) == True:
            print "Delete your old keychain first."
        else:
            os.system("touch ~/.ssh/keychain")
            os.system("openssl smime -encrypt -binary -aes-256-cbc -in ~/.ssh/keychain -out ~/.ssh/keychain_%s.blu -outform DER ~/.ssh/pubkeys/%s.pem" %(identity, identity))
            os.system("rm ~/.ssh/keychain")
            keychain = []
    elif choice == '6':
        decrypt("~/.ssh/keychain_%s.blu" %identity)
        pubkeys = os.popen('ls ~/.ssh/pubkeys').read().replace('.pem','').splitlines()
        os.system("mkdir ~/.ssh/keydis/")
        for n in xrange(len(pubkeys)):
            os.system("openssl smime -encrypt -binary -aes-256-cbc -in ~/.ssh/keychain -out ~/.ssh/keydis/keychain_%s.blu -outform DER ~/.ssh/pubkeys/%s.pem" %(pubkeys[n], pubkeys[n]))
        
        
        return
    elif choice == 'x':
        print("Warning: This shall delete your keychain. You must have a really good reason to do this!")
        checkphrase = "DELETE MY KEYCHAIN!!?!"
        phrase = raw_input("If you're sure, type the following: %s\n" %checkphrase)
        if phrase == checkphrase:
            os.system("rm ~/.ssh/keychain*")
            os.system("clear")
            print("It succeeded. I hope you had a good reason...")
        else:
            os.system("clear")
            print("You messed that up. Learn to type!\n")
    else:
        print "That wasn't a valid option..."
      
def ping (target, interface):
    os.system("clear")
    os.system ("ping -c 5 -I %s %s" % (interface, target))
    print ('\n')

def crypto ():
    global identity
    global authenticated
    os.system("clear")
    print 'Select from the following options:\n'
    print '1) Encrypt a file with CLI'
    print '2) Decrypt a file with CLI'
    print '3) Encrypt a file with GUI'
    print '4) Decrypt a file with GUI'
    print '5) Send SSH credentials to a receptive client'
    print '6) Perform first time setup of your credentials'
    print 'x) Wipe your credentials'
    crypmenu = raw_input('Enter your selection: ')
    if crypmenu == '1':
        encrypt(raw_input('Enter your filepath: '))
    elif crypmenu == '2':
        decrypt(raw_input('Enter your filepath: '))
    elif crypmenu == '3':
        encrypt(tkFileDialog.askopenfilename())
    elif crypmenu == '4':
        decrypt(tkFileDialog.askopenfilename())
    elif crypmenu == '5':
        sshtarget == raw_input('Enter the target with the format <username>@<host>:\n')
        os.system("ssh-copy-id %s" %sshtarget)
    elif crypmenu == '6':
        makekeys()
    elif crypmenu == 'x':
        print("Warning: This shall delete all of your credentials. You must have a really good reason to do this!")
        checkphrase = "DELETE MY CREDENTIALS!!?!"
        phrase = raw_input("If you're sure, type the following: %s\n" %checkphrase)
        if phrase == checkphrase:
            os.system("sudo rm -rf ~/.ssh/")
            os.system("clear")
            print("It succeeded. I hope you had a good reason...")
        else:
            os.system("clear")
            print("You messed that up. Learn to type!\n")
            
def makekeys():
    global identity
    global authenticated
    os.system("mkdir ~/.ssh")
    os.system("mkdir ~/.ssh/pubkeys")
    os.system("sudo chmod 700 ~/.ssh")
    os.system("sudo chmod 700 ~/.ssh/pubkeys")
    os.system("clear")
    identity = entercallsign('your')
    sshpass = getpass.getpass('Enter the passphrase for your new SSH key: ')
    os.system("ssh-keygen -t rsa -N %s -C %s -f ~/.ssh/%s " % (sshpass, identity, identity))
    os.system("openssl req -new -x509 -subj '/C=SY/ST=Syndicasia/L=Cobalt/O=Syndicasian Defence Force/OU=Cyber Defence Force/CN=%s/emailAddress=%s@aqua.ace' -passin pass:%s -passout pass:%s -key ~/.ssh/%s -out ~/.ssh/pubkeys/%s.pem" %(identity, identity, sshpass, sshpass, identity, identity))
    os.system("openssl pkcs12 -export -passin pass:%s -passout pass:%s -in ~/.ssh/pubkeys/%s.pem -inkey ~/.ssh/%s -out ~/.ssh/%s.p12" % (sshpass, sshpass, identity, identity, identity))
    authenticated = True
    
def entercallsign(pronoun):
    csign = raw_input('Enter %s callsign: ' % pronoun)
    csign = csign.lower()
    csign = csign.replace(' ','')
    return csign
    
def encrypt (filepath):
    public = publickey()
    if public == 'fail':
        return
    else:
        os.system("openssl smime -encrypt -binary -aes-256-cbc -in %s -out %s_%s.blu -outform DER ~/.ssh/pubkeys/%s.pem" %(filepath, filepath, public, public))
        
def decrypt (filepath):
    key = filepath.rpartition('_')[2]
    dest = filepath.rpartition('_')[0]
    privkey = key.rpartition('.')[0]
    if key.rpartition('.')[2] != 'blu':
        print 'Invalid file, try again!'
    else:
        os.system("openssl smime -decrypt -in %s -binary -inform DEM -inkey ~/.ssh/%s -out %s" %(filepath, privkey, dest))
    
def services ():
    os.system("clear")
    print 'Services like FTP, Web, IRC and boring stuff like that\n'
    
def lookup ():
    global ipdb
    os.system("clear")
    print 'How would you like to lookup a system?\n'
    print '1) Show me everything!'
    print '2) Filter by Flight'
    print '3) Filter by service'
    choice = raw_input('Enter your selection: ')
    if choice == '1':
        print("Flight      | Service     | Codename    | IP Address")
        print("----------------------------------------------------")
        for n in xrange(len(ipdb)):
            print flightid(ipdb[n][0]) + '| ' + servid(ipdb[n][1]) + '| ' + ipdb[n][2].ljust(12) + '| ' + ipdb[n][3]
    elif choice == '2':
        print("Which flight?")
        print("c) Centuriones Notitia")
        print("h) Haxtr33tboyz")
        print("s) Shell Shockers")
        print("k) Kairos Kode")
        print("b) AQUANET")
        flchoice = raw_input('Enter your selection: ')
        print("Service     | Codename    | IP Address")
        print("--------------------------------------")
        for n in xrange(len(ipdb)):
            if ipdb[n][0] == flchoice:
                print servid(ipdb[n][1]) + '| ' + ipdb[n][2].ljust(12) + '| ' + ipdb[n][3]
    elif choice == '3':
        print("Which service?")
        print("r)  Router")
        print("b)  Tower")
        print("w)  HTTP")
        print("ws) HTTPS")
        print("s)  SSH")
        print("f)  FTP")
        print("e)  Email")
        print("i)  IRC")
        print("c)  Chat")
        print("d)  DNS")
        print("t)  Telnet")
        svchoice = raw_input('Enter your selection: ')
        print("Flight      | Codename    | IP Address")
        print("--------------------------------------")
        for n in xrange(len(ipdb)):
            if ipdb[n][1] == svchoice:
                print flightid(ipdb[n][0]) + '| ' + ipdb[n][2].ljust(12) + '| ' + ipdb[n][3]        
        
def flaghunt (string):
    if 'SA-R2-Shell' in string:
        return 's'
    elif 'SA-A2-Kairos' in string:
        return 'k'
    elif 'SA-A3-Haxtr33t' in string:
        return 'h'
    elif 'SA-N2-Centuriones' in string:
        return 'c'
    else:
        return 'fail'

def flightid(string):
    if string == 'c':
        return 'Centuriones '
    elif string == 'h':
        return 'Haxtr33t    '
    elif string == 's':
        return 'SShockers   '
    elif string == 'k':
        return 'Kairos Kode '
    elif string == 'b':
        return 'AQUANET     '
    
def servid(string):
    if string == 'r':
        return 'Router      '
    elif string == 'b':
        return 'Tower       '
    elif string == 'w':
        return 'HTTP        '
    elif string == 'ws':
        return 'HTTPS       '
    elif string == 's':
        return 'SSH         '
    elif string == 'f':
        return 'FTP         '
    elif string == 'e':
        return 'Email       '
    elif string == 'i':
        return 'IRC         '
    elif string == 'c':
        return 'Chat        '
    elif string == 'd':
        return 'DNS         '
    elif string == 't':
        return 'Telnet      '
    
def authenticate():
    global keychain
    global identity
    global authenticated
    if 'keychain' in os.popen('ls ~/.ssh').read():
        decrypt("~/.ssh/keychain_%s.blu" %identity)
        with open("%s/.ssh/keychain" %os.getenv("HOME")) as f:
            keychain = f.read().splitlines()
            for n in xrange(len(keychain)):
                keychain[n] = keychain[n].split(' ')
        os.system("rm ~/.ssh/keychain", )
        authenticated = True
    else:
        print 'You need to create a keychain!'
        
def keychainwrite():
    global keychain
    global identity
    os.system("rm ~/.ssh/keychain_%s.blu" %identity)
    os.system("touch ~/.ssh/keychain")
    with open("%s/.ssh/keychain" %os.getenv("HOME"), 'w') as f:
        for n in xrange(len(keychain)):
            f.write(keychain[n][0] + ' ' + keychain[n][1] + ' ' + keychain[n][2] +'\n' )
    os.system("openssl smime -encrypt -binary -aes-256-cbc -in ~/.ssh/keychain -out ~/.ssh/keychain_%s.blu -outform DER ~/.ssh/pubkeys/%s.pem" %(identity, identity))
    os.system("rm ~/.ssh/keychain")
        
def privatekey():
    global identity
    pubkeys = os.popen('ls ~/.ssh/pubkeys 2> /dev/null').read().replace('.pem','').splitlines()
    privkeys = os.popen('ls -p ~/.ssh 2> /dev/null | grep -v /').read().splitlines()
    privkeys = [val for val in pubkeys if val in privkeys]
    if len(privkeys) == 0:
       print "You don't have a private key. Making one now.\n"
       makekeys()
    elif len(privkeys) == 1:
        identity = privkeys[0]
    elif len(privkeys) > 1:
        print "Select a private key:"
        for n in xrange(len(privkeys)):
            print ("%d) %s" %(n, privkeys[n]))
        identity = privkeys[int(raw_input("Enter your selection: "))]

def publickey():
    pubkeys = os.popen('ls ~/.ssh/pubkeys').read().replace('.pem','').splitlines()
    if len(pubkeys) == 0:
       print "You don't have any public keys. Go and get some."
       return 'fail'
    elif len(pubkeys) == 1:
        return pubkeys[0]
    elif len(pubkeys) > 1:
        print "Select a public key:"
        for n in xrange(len(pubkeys)):
            print ("%d) %s" %(n, pubkeys[n]))
        return pubkeys[int(raw_input("Enter your selection: "))]
    
def routings ():
    os.system("clear")
    print 'If connecting to GI-Guest, you must have passed the splash screen and then connected other interfaces'
    print 'Which provides your internet?'
    print '1) GI-Guest'
    print '2) ACE_Blue_Int'
    print '3) ACE_White_Int'
    print '4) ACE_Red_Int'
    print '5) Other'
    intchoice = raw_input('Enter your selection: ')
    if intchoice == '1':
        os.system ("sudo route del default")
        os.system ("sudo route add default gw 192.168.20.9")
        os.system ("sudo route add -net 10.0.0.0 netmask 255.255.0.0 gw 10.0.1.1")
        os.system ("sudo route add -net 192.168.0.0 netmask 255.255.0.0 gw 10.0.1.1")
    elif intchoice == '2':
        os.system ("sudo route del default")
        os.system ("sudo route add default gw 172.16.2.9")
        os.system ("sudo route add -net 10.0.0.0 netmask 255.255.0.0 gw 10.0.1.1")
        os.system ("sudo route add -net 192.168.0.0 netmask 255.255.0.0 gw 10.0.1.1")
    elif intchoice == '3':
        os.system ("sudo route del default")
        os.system ("sudo route add default gw 172.16.0.9")
        os.system ("sudo route add -net 10.0.0.0 netmask 255.255.0.0 gw 10.0.1.1")
        os.system ("sudo route add -net 192.168.0.0 netmask 255.255.0.0 gw 10.0.1.1")
    elif intchoice == '4':
        os.system ("sudo route del default")
        os.system ("sudo route add default gw 172.16.1.9")
        os.system ("sudo route add -net 10.0.0.0 netmask 255.255.0.0 gw 10.0.1.1")
        os.system ("sudo route add -net 192.168.0.0 netmask 255.255.0.0 gw 10.0.1.1")
    elif intchoice == '5':
        gw = raw_input('Enter the gateway of your internet connection:\n')
        os.system ("sudo route del default")
        os.system ("sudo route add default gw %s" % gw)
        os.system ("sudo route add -net 10.0.0.0 netmask 255.255.0.0 gw 10.0.1.1")
        os.system ("sudo route add -net 192.168.0.0 netmask 255.255.0.0 gw 10.0.1.1")
    else:
        print "Fine, don't enter a proper value then"
        
os.system ("clear")
print 'Azure, the Syndicasian Information Assurance Suite'
privatekey()
print ('Welcome %s! Good hunting.\n' %identity.upper())
choice = '0'
while choice != 'q':
    choice = menu()
    action(choice)