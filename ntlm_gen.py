#!/usr/bin/env python3

from binascii import hexlify
from hashlib import new as new_hash
from hashlib import md5
from pathlib import Path
from secrets import token_bytes
from secrets import token_hex
from sys import argv
import hmac
from random import randint

def helper():
    print('Usage:')
    print(f'[i] {argv[0]} [number of hashes] or [dictionary]')
    print(f'[i] ex: {argv[0]} 100\n\tprint 100 random unlikely to be cracked hashes')
    print(f'[i] ex: {argv[0]} ./wordlist\n\ttransform each word to an NTLM hash')
    print(f'[i] ex: {argv[0]} transform a single word to an NTLM hash')
    print(f'[i] ex: {argv[0]} -1 return NTLMv1 hash instead of NTLMv2')
    exit()


def NTLMv1(transform):
    hash = new_hash('md4', transform.encode('utf-16le')).digest()
    return hexlify(hash).decode()


def NTLMv2(transform):
    ntlm = NTLMv1(transform)
    # combine username and domain to hmac_md5
    user = 'Recover'
    domain = 'Me'
    #user_domain = (user.upper() + domain).encode('utf-16le').encode('hex')
    #user_domain_hmac = hmac.new(ntlm.decode('hex'),user_domain.decode('hex'), hashlib.md5).hexdigest()


    ## User
    #Administrator

    ## Computer / Domain
    #::WIN-487IMQOIA8E
    domain = 'test.me.local'

    ## Random Client Hash
    #:997b18cc61099ba2
    random_client_hash = token_hex(8)

    ## Password
    #:3CC46296B0CCFC7A231D918AE1DAE521

    ## Blob
    #:0101000000000000B09B51939BA6D40140C54ED46AD58E890000000002000E004E004F004D00410054004300480001000A0053004D0042003100320004000A0053004D0042003100320003000A0053004D0042003100320005000A0053004D0042003100320008003000300000000000000000000000003000004289286EDA193B087E214F3E16E2BE88FEC5D9FF73197456C9A6861FF5B5D3330000000000000000
    ## look at this blob stuff!: https://www.reddit.com/r/AskNetsec/comments/mctozt/decoding_netntlmv2_blob/
    blob = '0101000000000000B09B51939BA6D40140C54ED46AD58E890000000002000E004E004F004D00410054004300480001000A0053004D0042003100320004000A0053004D0042003100320003000A0053004D0042003100320005000A0053004D0042003100320008003000300000000000000000000000003000004289286EDA193B087E214F3E16E2BE88FEC5D9FF73197456C9A6861FF5B5D3330000000000000000'

    ntlm = NTLMv1(transform)
    #NTLMv2 Hash     = HMAC-MD5(NT Hash, uppercase(username) + target)
    payload = f'{user.upper()}{domain}'
    ntlmv2_hash = hmac.new(ntlm.encode(), payload.encode(), md5)

    #NTLMv2 Update  = HMAC-MD5(NTLMv2 Hash, challenge + blob)
    payload = f'{random_client_hash}{blob}'
    ntlmv2_hash = hmac.new(ntlmv2_hash.hexdigest().encode(), payload.encode(), md5)

    NTLMv2_final = f'{user}::{domain}:{random_client_hash}:{ntlmv2_hash.hexdigest().upper()}:{blob}'

    return NTLMv2_final


if len(argv) == 1:
    helper()
elif argv[1].isnumeric():
    for __i__ in range(int(argv[1])):
        rand = token_bytes(16).decode('latin-1')
        #print(NTLMv1(rand))
        print(NTLMv2(rand))
elif Path(argv[1]).is_file():
    with open(argv[1]) as fh:
        for word in fh:
            print(NTLMv2(word.strip()))
elif type(argv[1]) == str:
    print(NTLMv2(argv[1].strip()))
    print()
    #print('looking for something like this:')
    #print('Administrator::WIN-487IMQOIA8E:997b18cc61099ba2:3CC46296B0CCFC7A231D918AE1DAE521:0101000000000000B09B51939BA6D40140C54ED46AD58E890000000002000E004E004F004D00410054004300480001000A0053004D0042003100320004000A0053004D0042003100320003000A0053004D0042003100320005000A0053004D0042003100320008003000300000000000000000000000003000004289286EDA193B087E214F3E16E2BE88FEC5D9FF73197456C9A6861FF5B5D3330000000000000000')
else:
    helper()


'''
import hmac, hashlib
ResponseKeyNT = b'myPasswd, testUser, example.com'
m = hmac.new(ResponseKeyNT, digestmod=hashlib.md5)
m.hexdigest()
'''
 
