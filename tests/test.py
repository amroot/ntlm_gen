# This file is part of ntlm_gen.py
#
# https://hashcat.net/wiki/doku.php?id=example_hashes
# LM - Mode 3000
# NTLM - Mode 1000
# LM NTLM Pair - some password dumps (hashdump, secretsdump, etc.)
# NTLMv1 aka NetNTLMv1 - Mode 5500
# NTLMv2 aka NetNTLMv2 - Mode 5600
# 

def test():
    # ntlm_gen.py --password hashcat -lm
    # ntlm_gen.py --password hashcat -ntlm
    # ntlm_gen.py --password hashcat -lmntlm
    # ntlm_gen.py --password hashcat -1
    # ntlm_gen.py --password hashcat -2
    print()