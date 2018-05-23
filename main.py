'''
Create unique id for each hash that needs to be cracked x
write to a file x
pass the server that file x
launch hashcat under a screen session x
check if the screen session is still running
read the cracked hashes
add argument to handle the hash type
check for errors while executing command
add rule file x
add verbose mode
'''
import paramiko ##need in requirments
import getpass
import sys
import argparse
from subModules.scp import SCPClient ##add to submodules
import random
import string
import os
import time
import itertools

def parse_args():
    parser = argparse.ArgumentParser(description='Remote hashcat cracker with though ssh')
    parser.add_argument('target', help='[username[:password]@<crackerIP>] if a username or password is not passed, it will prompt', action='store')
    parser.add_argument('-f', '--hash-file', help='Path to the hashes', required=True, default='D:\GitHub\ssHC\hashes.txt')
    parser.add_argument('-w', '--wordlist', help='Path to the wordlist on the cracker box', required=False, default='/usr/share/wordlists/rockyou.txt')
    parser.add_argument('-r', '--rule-file', help='Path to the rule file on the cracker box', required=False, default='/usr/share/hashcat/rules/best64.rule')
    parser.add_argument('-v', '--verbose', help='Will show the output of hashcat throughout cracking', default=False, action='store_true')
    return parser.parse_args()

def ssh_client(host, port, user, pw):

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port, user, pw)
    except:
        sys.exit('[!]Authentication Failed')

    return client

def cracker_creds(uname=False, passwd=False, **kwargs):
    if uname and passwd:
        username = input('[*] Crckerbox username: ')
        pw = pw = getpass.getpass('[*] Crackerbox password: ')
        return username, pw
    if passwd:
        pw = getpass.getpass('[*] Crackerbox password: ')
        return pw


def generate_cmd(id, hash_file, wordlist, rule_file, verbose=False):
    command = 'hashcat --session {}'.format(id)
    command += ' -m {} '
    command += '-o /tmp/{} /tmp/{} {} -r {} --force'.format(id, hash_file, wordlist, rule_file)
    command = command.format('1000')
    if verbose:
        return command

    screen = 'screen -S {} -dm {}'. format(id, command)
    return screen

##Print out the exact output of hashcat
def runVerbose(id, args):
    print("Running verbose")
    stdin, stdout, stderr = cracker_client.exec_command(generate_cmd(id, (id+'.hash'),args.wordlist, args.rule_file, True))

    print('stdout: ', stdout.read().decode())

def main(args):
    if '@' in args.target:
        creds = args.target.split('@')[0]
        target = args.target.split('@')[1]
        if ':' not in creds:
            c_user = creds
            c_pw = cracker_creds(passwd=True)
        else:
            c_user = creds.split(':')[0]
            c_pw = creds.split(':')[1]
    else:
        target = args.target
        c_user, c_pw = cracker_creds(uname=True, passwd=True)

    global cracker_client
    cracker_client = ssh_client(target, 22, c_user, c_pw)
    cracker_scp = SCPClient(cracker_client.get_transport())

    rand = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    id = 'ssHC-' + rand

    if 'nt' in os.name:
        cracker_scp.put(os.getcwd()+'\\'+args.hash_file,'/tmp/'+id+'.hash')
    elif 'posix' in os.name:
        cracker_scp.put(os.getcwd()+'/'+args.hash_file,'/tmp/'+id+'.hash')


    print("[+]Cracking started")
    print('[*]Id is: '+ id)

    if args.verbose:
        runVerbose(id, args)
    else:
        stdin, stdout, stderr = cracker_client.exec_command(generate_cmd(id, (id+'.hash'),args.wordlist, args.rule_file))

    ##while screen session stiil exists print spinning bar
    while True:
        print(cracker_client.exec_command('screen -ls')[1].read().decode())
        if id in cracker_client.exec_command('screen -ls')[1].read().decode():
            print(next(spinner), end = '\r')
        else:
            break
    ##once the program finishs print out the output
    __, stdout, stderr = cracker_client.exec_command('cat /tmp/'+id)
    print('{}'.format(stdout.read().decode()), end='\r')
    #time.sleep(3)

if __name__ == "__main__":
    spinner = itertools.cycle(['-', '/', '|', '\\'])
    try:
        main(parse_args())
    except KeyboardInterrupt:
        print('[!]Exiting now')
        sys.exit()
