# This file is part of ntlm_gen.py

from Crypto.Cipher import DES
from ntlmgen.expand_deskey import expand_des_key
from unicodedata import normalize


def LM(password):
    """Returns an LM hash from string.
    Param password (str): the value to hash.
    """

    # Magic key:
    magic_key = b'KGS!@#$%'
    # DES can't deal with unicode so password it to a string
    # https://docs.python.org/3/library/unicodedata.html#unicodedata.normalize
    # normalize 
    password = normalize('NFKD', password).encode('ascii', 'ignore')

    # trim or pad to 14 if needed
    password = bytes((password.decode().upper() + '\0' * 14)[:14], 'ascii')

    # create two keys from the password
    # look at calculating a parity bit
    key1 = DES.new(expand_des_key(password[0:7]), DES.MODE_ECB)
    key2 = DES.new(expand_des_key(password[7:14]), DES.MODE_ECB)
 
    # encrypt the magic key using the first key
    lm_hash = key1.encrypt(magic_key)
    # encrypt the magic key using the second key
    # and append to the first encrypted value
    lm_hash += key2.encrypt(magic_key)
    
    # return in hex format
    return lm_hash.hex()
