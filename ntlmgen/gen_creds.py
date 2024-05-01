# This file is part of ntlm_gen.py

from secrets import token_hex
from secrets import token_urlsafe


def gen_user(user_length=8):
    """ Returns a username according to length.
    Param user_length (int): the length of the username.
    Default 8 characters.
    """
    length = int(user_length/2)
    username = token_hex(length)
    return username.upper()


def gen_pass(pass_length=16):
    """ Returns a password token.
    Parm pass_length (int): the length of the password.
    Default 16 characters.
    """
    return token_urlsafe(pass_length)