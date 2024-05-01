# ntlm_gen.py
ntlm_gen.py was created due to my curiosity about the history and possibly current password solutions provided by Windows. It generates Windows password hashes for research, benchmarking, or learning purposes. It can produce LM (Lan Manager), NTLM (New Technology LAN Manager), NetNTLMv1 aka NTLMv1, and NetNTLMv2 aka NTLMv2 hashes that are compatible with hashcat and other tools. 

## Installation
1. pip3 install -r requirements.txt
2. Some flavors of Debian might need to modify /etc/ssl/openssl.cnf due to MD4 disabled. - https://stackoverflow.com/questions/69938570/md4-hashlib-support-in-python-3-8

## Usage
```
usage: ntlm_gen.py [-h] [-n NUM] [--rand-pass RAND_PASS] [--password PASSWORD] [--password-file PASSWORD_FILE] [-1] [-2] [-lm] [-ntlm]
                   [-lmntlm] [--domain DOMAIN] [--user USER] [--rid RID]

ntlm_gen.py generates Windows password hashes for research, benchmarking, or learning purposes. It can produce LM (Lan Manager), NTLM
(New Technology LAN Manager), NetNTLMv1 aka NTLMv1, and NetNTLMv2 aka NTLMv2 hashes that are compatible with hashcat and other tools.

options:
  -h, --help            show this help message and exit
  -n NUM, --num NUM     The number of hashes or tokens to output
  --rand-pass RAND_PASS
                        Generate random passwords of this length. Default is 16
  --password PASSWORD   Generate a hash/token from this string.
  --password-file PASSWORD_FILE
                        Generate tokens from a file. One string per line. Not used yet.
  -1, --v1              Generate NTLMv1 aka NetNTLMv1
  -2, --v2              Generate NTLMv2 aka NetNTLMv2
  -lm                   Generate LAN Manager (LM) hash
  -ntlm                 Generate New Technology LAN Manager (NTLM) hash
  -lmntlm               Generate LM:NTLM pair
  --domain DOMAIN       Custom domain. Default is "test.me.local"
  --user USER           Custom static user. Default is randomly generated.
  --rid RID             Start at this Relative ID (RID).
```
