import paramiko
import getpass
import sys
from scp import SCPClient

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
    pw = getpass.getpass()

    return username, pw

def main():
    c_user, c_pw = cracker_creds()
    cracker_client = ssh_client('18.217.232.173', 22, c_user, c_pw)
    cracker_scp = SCPClient(cracker_client.get_transport())

if __name__ == "__main__":
    main()

    #cracker_client.exec_command('touch /tmp/passwords')
