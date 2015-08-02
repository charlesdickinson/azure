import pexpect
import getpass
global keychain
keychain = ['assetbox', 'assetbox', 'ESKNP0zAOhV7fCo']

def sshinit(uname,ipaddress):
    asstat = pexpect.spawn("ssh %s@%s" %(uname,ipaddress))
    i = asstat.expect(['No route to host', 'synprac'])
    if i == 0:
        print ('Network connectivity issue!')
        asstat.kill(0)
    elif i == 1:
        return asstat
    
def sshlist(uname,ipaddress,filepath):
    session = sshinit(uname, ipaddress)
    session.expect("$")
    session.sendline("cat %s" %filepath)
    session.expect('\x1b')
    filecat = session.before.splitlines()
    del filecat[0]
    for n in xrange(len(filecat)):
        filecat[n] = filecat[n].split('|')
    return filecat

print sshlist('syndicasia','10.0.1.246', '~/assets.txt')
        
    


