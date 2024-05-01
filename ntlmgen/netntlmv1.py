# This file is part of ntlm_gen.py

from Crypto.Cipher import DES
from ntlmgen.expand_deskey import expand_des_key 
from ntlmgen.ntlm import NTLM
from ntlmgen.lm import LM
from secrets import token_bytes

def NetNTLMv1(user, domain, password):
    """ Returns NTLMv1 in pwdump/hashcat format.
    username:unused:unused:lm response:ntlm response:challenge
    CORP\Administrator:::222:333:444
    Param password (str): the string to transform.
    Param domain (str): domain to include in output.
    """

    def response_hash(password_hash):
        key_bytes = bytearray(21)
        key_bytes[:16] = password_hash[:16]        
        low_key = DES.new(expand_des_key(key_bytes[0:7]), DES.MODE_ECB)
        mid_key = DES.new(expand_des_key(key_bytes[7:14]), DES.MODE_ECB)
        high_key = DES.new(expand_des_key(key_bytes[14:]), DES.MODE_ECB)
        low_response = low_key.encrypt(challenge)
        mid_response = mid_key.encrypt(challenge)
        high_response = high_key.encrypt(challenge)
        response = low_response + mid_response + high_response
        return response

    challenge = token_bytes(8)
    lm_hash = LM(password).encode()
    ntlm_hash = bytes.fromhex(NTLM(password))
    lm_response = response_hash(lm_hash)
    ntlm_response = response_hash(ntlm_hash)


    return f'{domain}\{user}:::{lm_response.hex()}:{ntlm_response.hex()}:{challenge.hex()}'