#!/usr/bin/env python3

# ntlm_gen.py by Robert Gilbert (amroot.com)
#
#
# Description: 
# ntlm_gen.py generates Windows password hashes for research, benchmarking, or
# learning purposes. It can produce LM (Lan Manager), NTLM (New Technology LAN
# Manager), NetNTLMv1 aka NTLMv1, and NetNTLMv2 aka NTLMv2 hashes that are 
# compatible with hashcat and other tools.
# 
# Credit:
# The expandDesKey by Marcus McCurdy was so lovely.
# It was renamed to expand_des_key here.
# Can be found here:
#  https://github.com/50onRed/pysmb/blob/3b039f5b3402cb5a7a9020b171e42e7bb818e94e/python3/smb/ntlm.py#L179
#
# The NetNTLMv2 algorithm was based off parsing SMB packets but was reduced by
# following MS 3.3.2 NTLM v2 Authentication pseudo code found here:
#  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
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
from ntlmgen.gen_creds import gen_user, gen_pass
from ntlmgen.lm import LM
from ntlmgen.lm_ntlm import LM_NTLM_pair
from ntlmgen.netntlmv1 import NetNTLMv1
from ntlmgen.netntlmv2 import NetNTLMv2
from ntlmgen.ntlm import NTLM


def get_args():
    parser = ArgumentParser(description='''
        ntlm_gen.py generates Windows password hashes for research, 
        benchmarking, or learning purposes. It can produce LM (Lan Manager),
        NTLM (New Technology LAN Manager), NetNTLMv1 aka NTLMv1, and NetNTLMv2
        aka NTLMv2 hashes that are compatible with hashcat and other tools.
        ''')

    parser.add_argument('-n', '--num',
        type=int,
        default=1,
        help='The number of hashes or tokens to output')
 
    parser.add_argument('--rand-pass',
        type=int,
        default=0,
        help='Generate random passwords of this length. Default is 16')
 
    parser.add_argument('--password',
        help='Generate a hash/token from this string.')

    parser.add_argument('--password-file',
        help='Generate tokens from a file. One string per line. Not used yet.')

    parser.add_argument('-1', '--v1',
        action='store_true',
        help='Generate NTLMv1 aka NetNTLMv1')

    parser.add_argument('-2', '--v2',
        action='store_true',
        help='Generate NTLMv2 aka NetNTLMv2')       

    parser.add_argument('-lm',
        action='store_true',
        help='Generate LAN Manager (LM) hash')

    parser.add_argument('-ntlm',
        action='store_true',
        help='Generate New Technology LAN Manager (NTLM) hash')

    parser.add_argument('-lmntlm',
        action='store_true',
        help='Generate LM:NTLM pair')

    parser.add_argument('--domain',
        help='Custom domain. Default is "test.me.local"',
        default='test.me.local')

    parser.add_argument('--user',
        help='Custom static user. Default is randomly generated.')
    
    parser.add_argument('--rid',        
        type=int,
        default=1000,
        help='Start at this Relative ID (RID).',)


    return parser


def preflight(parser, args):
    """ Performs some preflight checks before running tasks.
    """
    if not (args.lm or args.ntlm or args.lmntlm or args.v1 or args.v2):
        parser.error('No protocols specified.')

    if (args.password and args.rand_pass):
        parser.error('--password and --rand-pass found. Please select only one password option.')

    if (args.password and args.num > 1):
        # it does not make sense to provide both options.
        # the returned hash will always be the same.
        # this will be the same with input files of passwords.         
        print('Reducing the number of outputs as a single password was provided.')


def main():
    # https://hashcat.net/wiki/doku.php?id=example_hashes
    # LM - Mode 3000
    # NTLM - Mode 1000
    # LM NTLM Pair - some password dumps (hashdump, secretsdump, etc.)
    # NTLMv1 aka NetNTLMv1 - Mode 5500
    # NTLMv2 aka NetNTLMv2 - Mode 5600
    # 

    parser = get_args()
    args = parser.parse_args()
    rid = args.rid
    num_output = args.num
    password = None
    domain = args.domain

    preflight(parser, args)

    if args.password:
        password = args.password.strip()
        num_output = 1
    
    for __i__ in range(0, num_output):

        if args.rand_pass:
            password = gen_pass(args.rand_pass)

        if not password:
            parser.error('A password is required. Try --rand-pass or --password')
    
        if args.user:
            user = args.user
        else:
            user = gen_user()
       
        if args.lm:
            print(LM(password))

        if args.ntlm:
            print(f'{user}:{NTLM(password)}')
        
        if args.lmntlm:
            print(LM_NTLM_pair(user, domain, password, rid))
            rid += 1

        if args.v1:
            print(NetNTLMv1(user, domain, password))

        if args.v2:
            print(NetNTLMv2(user, domain, password))


if __name__ == '__main__':
    main()

