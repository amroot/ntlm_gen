# This file is part of ntlm_gen.py

def expand_des_key(key):
    """
    Creates a parity bit for the DES key, which expands the key from a 7-byte
    password key into a 8-byte DES key.
    Credit to:
    https://github.com/50onRed/pysmb/blob/3b039f5b3402cb5a7a9020b171e42e7bb818e94e/python3/smb/ntlm.py#L179
    Param key (bin): a 7 byte binary key to expand to 8
    """
    s = [ ((key[0] >> 1) & 0x7f) << 1,
          ((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1,
          ((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1,
          ((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1,
          ((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1,
          ((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1,
          ((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1,
          (key[6] & 0x7f) << 1
        ]
    return bytes(s)