# This file is part of ntlm_gen.py

from calendar import timegm
from hashlib import md5
from hmac import new as new_hmac
from secrets import token_bytes
from time import gmtime
from ntlmgen.ntlm import NTLM


def NetNTLMv2(user, domain, password):
    """ Returns user :: domain : server challenge : nt_proof_string : blob
    Param user (str): the username
    Param domain (str): target domain name or WORKGROUP
    Param password (str): the password to create the hash
    3.3.2 NTLMv2 Authentication:
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
    """
    
    # current seconds since the epoch to tuple UTC (a.k.a. GMT)
    gmt = gmtime()
    # timestamp from GMT
    ts = timegm(gmt)
    # convert to little endian bytes
    timestamp = ts.to_bytes(8, 'little')
    # create random 8 byte client and server challenges
    client_challenge = token_bytes(8)
    server_challenge = token_bytes(8)

    responser_version = 1
    hi_responser_version = 1
    # WORKGROUP was always set as the server name in the SMB packets I parsed
    server_name = 'WORKGROUP'.encode('utf-16le')
    
    # blob is defined by Microsoft
    # the length and details of the blob are much more intense when parsing SMB packets
    # check out Wireshark filters ntlmssp.NetNTLMv2_response.* for example
    blob = (
            responser_version.to_bytes(1, 'little') 
            + hi_responser_version.to_bytes(1, 'little')
            + bytearray(6)
            + timestamp
            + client_challenge
            + bytearray(4)
            + server_name
            + bytearray(4)
        )
    
    # create an NTLM hash. it's returned as hexdigest so turn it back to bytes
    NTLM_hash = bytes.fromhex(NTLM(password))
    response_key_nt = new_hmac(NTLM_hash, (user.upper() + domain).encode('utf-16le'), md5).digest()
    nt_proof_string = new_hmac(response_key_nt, server_challenge + blob, 'md5').hexdigest()
  

    return f'{user}::{domain}:{server_challenge.hex()}:{nt_proof_string}:{blob.hex()}'
