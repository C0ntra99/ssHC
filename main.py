import paramiko ##need in requirments
import getpass
import sys
import argparse
from scp import SCPClient ##add to submodules
import random
import string

def parse_args():
    parser = argparse.ArgumentParser(description='Remote hashcat cracker with though ssh')
    parser.add_argument('-c', '--crackerip', help='Enter the crackbox IP')
    parser.add_argument('-h', '--hash-file', help='Path to the hashes')
    parser.add_argument('-w', '--wordlist', help='Path to the wordlist on the cracker box')
    return parser.parse_args()

def ssh_client(host, port, user, pw):

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ##             host, port, user, pw
        client.connect(host, port, user, pw)
    except:
        sys.exit('[!]Authentication Failed')

    return client

def cracker_creds():
    username = input('[*] Crckerbox username: ')
    pw = getpass.getpass('[*] Crackerbox password: ')

    return username, pw

def cmd(hash_file, wordlist):
    hc_command = 'hashcat --session {randomstring} -m {hashtype} -o {outputfile} /tmp/{hash_file} {wordlist}'
    ran_str = ''.join(random.choice(string.letters) for x in range(5))
    id = 'hash-' + ran_str
    command = '{} --session {}'.format('hashcat', id)
    command += ' -m {} '
    command += '-o {} /tmp/{} {}'.format(id,hash_file, wordlist)
    print(command)

def main():
    c_user, c_pw = cracker_creds()
    cracker_client = ssh_client(IP, 22, c_user, c_pw)
    cracker_scp = SCPClient(cracker_client.get_transport())

if __name__ == "__main__":
    #main(parse_args())
    cmd("hashes", "/rockyou.txt")
    #cracker_client.exec_command('touch /tmp/passwords')
