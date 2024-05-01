# This file is part of ntlm_gen.py

from ntlmgen.lm import LM
from ntlmgen.ntlm import NTLM

def LM_NTLM_pair(user, domain, password, rid):
    """ Returns LM NTLM pair in pwdump format.
    Param password (str): the item to hash (secret, password, whatever).
    Param domain (str): the domain to use in the pwdump output.
    Param user (str): the user to display in the pwdump output.
    Param rid (int): identifier for pwdump.
    """ 
    lm_hash = LM(password)
    ntlm_hash = NTLM(password)

    return (f'{domain}\\{user}:{rid}:{lm_hash.upper()}:{ntlm_hash.upper()}:::')