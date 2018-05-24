# ssHC
Simple tool used to crack password hashes using a remote server with HashCat. 

## Usage
Clone the repository and run the install script.

    git clone https://github.com/C0ntra99/ssHC
    cd ssHC 
    ./install.sh

After the install script is ran just run the command.
Please note that both the wordlist and the rule file have to be on the cracker box. 
  
    ./ssHC.py [username[:password]@<crackerIP>] -f [hashes] -w [wordlist] -r [rule file]
    
 Example:
 

    ./ssHC.py kraken@192.168.0.56 -f hashes.hash -w /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

*The idea of this tool was based off of autoresp by @DanMcInerney I simply took the remote hashcat functionality out of autoresp and made it its own entity*

