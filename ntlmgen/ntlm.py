# This file is part of ntlm_gen.py

from hashlib import new as new_hash

def NTLM(password):
    """Returns an NTLM hash in hex from string
    Param password (str): the value to hash
    """
    try:
        ntlm_hash = new_hash('md4', password.encode('utf-16le')).hexdigest()
    except ValueError as e:
        print(f'[!] {e}')
        print('[i] You may need to enable the insecure md4 cipher in your openssl.cnf')
        print('[i] Reference: https://github.com/amroot/ntlm_gen/issues/1#issuecomment-2692478764')
        exit(1)
    return ntlm_hash
