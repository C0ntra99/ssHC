'''
Create unique id for each hash that needs to be cracked x
write to a file x
pass the server that file x
launch hashcat under a screen session
check if the screen session is still running
read the cracked hashes
'''
import paramiko ##need in requirments
import getpass
import sys
import argparse
from subModules.scp import SCPClient ##add to submodules
import random
import string
import os

def parse_args():
    parser = argparse.ArgumentParser(description='Remote hashcat cracker with though ssh')
    parser.add_argument('target', help='[username[:password]@<crackerIP>] if a username or password is not passed, it will prompt', action='store')
    parser.add_argument('-f', '--hash-file', help='Path to the hashes', required=True, default='D:\GitHub\ssHC\hashes.txt')
    parser.add_argument('-w', '--wordlist', help='Path to the wordlist on the cracker box', required=False, default='/usr/share/wordlists/rockyou.txt')
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


def generate_cmd(hash_file, wordlist):
    rand = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    id = 'ssHC-' + rand
    command = 'hashcat --session {}'.format(id)
    command += ' -m {} '
    command += '-o /tmp/{} /tmp/{} {} --force'.format(id, hash_file, wordlist)
    command = command.format('1000')
    #screen = 'screen -S {} -dm {}'. format(id, command)

    print("[*]Running on cracker:")
    print("     {}".format(command))
    return command

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

    cracker_client = ssh_client(target, 22, c_user, c_pw)
    cracker_scp = SCPClient(cracker_client.get_transport())

    ##Change this to work on linux
    if 'posix' in os.name:
        cracker_scp.put(os.getcwd()+'\\'+args.hash_file,'/tmp/ssHC-'+args.hash_file)
    elif 'nt' in os.name:
        print(os.getcwd()+'/'+args.hash_file,'/tmp/ssHC-'+args.hash_file)
    #cracker_client.exec_command('touch /tmp/test')

    stdin, stdout, stderr = cracker_client.exec_command(generate_cmd(args.hash_file,'/usr/share/rockyou.txt'))

if __name__ == "__main__":
    main(parse_args())
