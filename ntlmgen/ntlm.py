# This file is part of ntlm_gen.py

from hashlib import new as new_hash

def NTLM(password):
    """Returns an NTLM hash in hex from string
    Param password (str): the value to hash
    """

    return new_hash('md4', password.encode('utf-16le')).hexdigest()
