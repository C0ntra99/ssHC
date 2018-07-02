#!/usr/bin/python3
'''
Create unique id for each hash that needs to be cracked x
write to a file x
pass the server that file x
launch hashcat under a tmux session
check if the tmux session is still running
read the cracked hashes
add argument to handle the hash type
check for errors while executing command
add rule file x
add verbose mode
write install script
specify hashcat folder? default /usr/bin
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
    parser.add_argument('-k', '--key', help='SSH key for authentication')
    parser.add_argument('-f', '--hash-file', help='Path to the hashes')#, default='D:\GitHub\ssHC\hashes.txt')
    parser.add_argument('-w', '--wordlist', help='Path to the wordlist on the cracker box', default='/usr/share/wordlists/rockyou.txt')
    parser.add_argument('-r', '--rule-file', help='Path to the rule file on the cracker box', default='/usr/share/hashcat/rules/best64.rule')
    parser.add_argument('-v', '--verbose', help="Only use for debugging, this will not run the hashcat session in a tmux session.", action='store_true')
    parser.add_argument('-n', '--name', help='Add a custom tmux/hashcat session name', action='store')
    parser.add_argument('-c', '--check', help='Check to see if a session is still running', action='store')
    args = parser.parse_args()
    if args.check and not args.hash_file:
        return args
    elif args.hash_file and not args.check:
        return args
    elif not args.hash_file and not args.check:
        parser.print_help()
        sys.exit("[!]Please use either -f or -c when running")

def ssh_client(host, port, user, pw, key=None):

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ##DOUBLE CHECK THIS
    if key:
        try:
            client.connect(host, port, user, pw, key)
        except:
            sys.exit('[!]Authentication Failed')
    else:
        try:
            client.connect(host, port, user, pw)
        except:
            sys.exit('[!]Authentication Failed')

    return client

def cracker_creds(uname=False, passwd=False, **kwargs):
    if uname and passwd:
        username = input('[*]Crackerbox username: ')
        pw = pw = getpass.getpass('[*]Crackerbox password: ')
        return username, pw
    if passwd:
        pw = getpass.getpass('[*]Crackerbox password: ')
        return pw


def generate_cmd(id, hash_file, wordlist, rule_file, verbose=False):
    command = 'hashcat --session {}'.format(id)
    command += ' -m {} '
    command += '-o /tmp/{} /tmp/{} {} -r {} --force'.format(id, hash_file, wordlist, rule_file)
    command = command.format('1000')

    if verbose:
        return command
    tmux = 'tmux new -d -s "{}" {}'. format(id, command)
    return tmux

def runVerbose(id, args):
    print("[*]Verbose mode:")
    stdin, stdout, stderr = cracker_client.exec_command(generate_cmd(id, (id+'.hash'),args.wordlist, args.rule_file, True))

    print('[*]Stdout: ',stdout.read().decode())
    print('[*]Stderr: ', stderr.read().decode())

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

    if args.name:
        id = args.name
    else:
        rand = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        id = 'ssHC-' + rand

    ##Put into function
    if args.check:
        id = args.check
        if args.check in cracker_client.exec_command('tmux ls')[1].read().decode():
            print("[*]Session {} is currently running".format(args.check))
        else:
            stdin, stdout, stderr = cracker_client.exec_command('cat /tmp/'+id)
            if not stdout.read().decode():
                print("[+]Session did not exists")
            else:
                stdin, stdout, stderr = cracker_client.exec_command('cat /tmp/'+id)
                print("[+]Passwords for session {}".format(id))
                print("{}".format(stdout.read().decode()))
    else:

        if 'nt' in os.name:
            cracker_scp.put(os.getcwd()+'\\'+args.hash_file,'/tmp/'+id+'.hash')
        elif 'posix' in os.name:
            cracker_scp.put(os.getcwd()+'/'+args.hash_file,'/tmp/'+id+'.hash')

        print('[*]Id is: '+ id)

        if args.verbose:
            runVerbose(id, args)
        else:
            stdin, stdout, stderr = cracker_client.exec_command(generate_cmd(id, (id+'.hash'),args.wordlist, args.rule_file))

            ##Watch this pls
            if stderr.read().decode():
                print("[!]Error, please run again with -v")

        while True:
            if id in cracker_client.exec_command('tmux ls')[1].read().decode():
                print("[*]Cracking hashes ",next(spinner), end = '\r')
            else:
                break
            time.sleep(.5)
        ##once the program finishs print out the output
        print('[+]Cracked hashes: \n')
        __, stdout, stderr = cracker_client.exec_command('cat /tmp/'+id)
        print('{}'.format(stdout.read().decode()), end='\r')


if __name__ == "__main__":
    spinner = itertools.cycle(['-', '/', '|', '\\'])
    args = parse_args()
    try:
        main(args)
    except KeyboardInterrupt:
        print('[!]Exiting now')
        sys.exit()
