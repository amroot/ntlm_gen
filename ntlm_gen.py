#!/usr/bin/env python3

# By Robert Gilbert (amroot.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from argparse import ArgumentParser
from datetime import datetime
from hashlib import md5
from hashlib import new as new_hash
from hmac import new as new_hmac
from pathlib import Path
from secrets import token_bytes
from secrets import token_hex
from sys import argv

def parse_args():
	parser = ArgumentParser()
	parser.add_argument('--rand',
        help='Generate this number of random passwords that is unlikely to be cracked.',
        type=int)
	parser.add_argument('--word',
		help='Generate an NTLMv(1,2) token from this word.')
	parser.add_argument('--file',
		help='Generate a token per word (one per line) from a file')
	parser.add_argument('-1', '--v1',
        action='store_true',
        help='Generate NTLMv1 rather than NTLMv2')
	parser.add_argument('--domain',
		help='Custom domain. Default is "test.me.local"')
	parser.add_argument('--user',
		help='Custom user. Default is "Recover"')
	return parser


def unix_to_nt_time(time_convert):
    return int((time_convert + 116444736000000000) * 10000000)


def NTLMv1(transform):
    hash = new_hash('md4', transform.encode('utf-16le')).hexdigest()
    print(hash)
    return hash


def NTLMv2(transform, domain='test.me.local', user='Recover', rid=1000):
    """ Retruns NTLMv2 hash(s)
    Param transform (int, str):
        The number of random hashes to generate (hard to crack),
        A single word to tranform to NTLMv2
        A file containing a list of items to transform
    Param domain (str): the domain to use to generate hash and included in output
    Param user (str): the user to use to generate hash and included in output
    """

    # NTLMv1 is the HMAC Key for NTLMv2
    NTLM = NTLMv1(transform)

    # Random Client Hash
    random_client_hash = token_hex(8)

    # Blob
    # look at this blob stuff!
    # https://www.reddit.com/r/AskNetsec/comments/mctozt/decoding_netntlmv2_blob/
    # Will update this from a static to dynamic value in the next version
    blob = '0101000000000000B09B51939BA6D40140C54ED46AD58E890000000002000E004E004F004D00410054004300480001000A0053004D0042003100320004000A0053004D0042003100320003000A0053004D0042003100320005000A0053004D0042003100320008003000300000000000000000000000003000004289286EDA193B087E214F3E16E2BE88FEC5D9FF73197456C9A6861FF5B5D3330000000000000000'
    # Blob breakdown for later
    # I'm not 100% on the blob so the following will likely show my ignorance
    # create a random signature because why not    
    # Made up signature is the last two digits of the timestamp converted to a binary value
    blob_sig = bin(int(str(datetime.now().timestamp())[-2:]))
    blob_sig = f'{blob_sig.replace("0b",""):0<8}'
    #print(blob_sig)
    # the timestamp is an NT timestamp in hex format. I this might actually be correct
    nt_timestmap = unix_to_nt_time(int(datetime.now().timestamp()))
    nt_timestamp = hex(nt_timestmap).replace('0x','').upper()
    # random hex nonce so this is probably correct
    nonce = token_hex(8)
    reserved = 00000000
    # the target info block can be learned later from so many NTLM scripts. Please complete later.
    '''
    Blob sig: 01010000
    reserved: 00000000
    timestamp: B09B51939BA6D401 (2019-01-07T15:13:42Z)
    nonce:     40C54ED46AD58E89 (random value)
    reserved: 00000000
    target info block:
        MsvAvNbDomainName: NOMATCH 02000E004E004F004D004100540043004800
        MsvAvNbComputerName: SMB12 01000A0053004D00420031003200
        MsvAvDnsDomainName: SMB12 04000A0053004D00420031003200
        MsvAvDnsComputerName: SMB12 03000A0053004D00420031003200
        MsvAvDnsTreeName: SMB12 05000A0053004D00420031003200
        MsvAvSingleHost 08003000 size: 30000000 (48 bytes)
        z4: 00000000
        customdata: 0000000000300000
        machineid: 4289286EDA193B087E214F3E16E2BE88FEC5D9FF73197456C9A6861FF5B5D333 (random value generated at boot)
        MsvAvEOL 00000000
        Reserved 00000000
    '''
    # Create first round NTLMv2 Hash
    payload = f'{user.upper()}{domain}'
    NTLMv2_hash = new_hmac(NTLM.encode(), payload.encode(), md5)
    # enum this later
    rid += 1

    # Create round two NTLMv2 Hash
    payload = f'{random_client_hash}{blob}'
    NTLMv2_hash = new_hmac(NTLMv2_hash.hexdigest().encode(), payload.encode(), md5)

    # Put it all together for hacking and cracking and tapping and snapping
    print(f'{domain}\\{user}:{rid}:{random_client_hash}:{NTLMv2_hash.hexdigest().upper()}:::')
    NTLMv2_final = f'{user}::{domain}:{random_client_hash}:{NTLMv2_hash.hexdigest().upper()}:{blob}'

    return NTLMv2_final

def main():

    parser = parse_args()
    args = parser.parse_args()

    if args.v1:
        v1 = True
    else:
        v1 = False

    if args.rand:
        for __i__ in range(int(args.rand)):
            rand = token_bytes(16).decode('latin-1')
            #print(NTLMv1(rand))
            print(NTLMv2(rand))
    elif args.word:
        if v1:
            print(NTLMv1(args.word.strip()))
        else:
            print(NTLMv2(args.word.strip()))
    elif args.file:
        if Path(args.file).is_file():
            with open(args.file) as fh:
                for word in fh:
                    print(NTLMv2(word.strip()))
        else:
            print('File passed but could not open file.')
            exit()
    else:
        parser.error('No action requested, add --rand, --word, or --file')


if __name__ == '__main__':
    main()

