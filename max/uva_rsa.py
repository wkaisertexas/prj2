from cryptography.hazmat.primitives.asymmetric import rsa

RSA_KEY_SIZE = 2048
RSA_PUB_EXP = 65537

def rsa_gen():
    key = rsa.generate_private_key(public_exponent=RSA_PUB_EXP, key_size=RSA_KEY_SIZE)
    out = {
        "e": RSA_PUB_EXP, 
        "n": key.public_key().public_numbers().n, 
        "d": key.private_numbers().d}
    return out

def mod_exp(base, exponent, modulus):
    bits = format(exponent, 'b')
    y = 1
    for b in bits:
        y = (y * y) % modulus
        if '1' == b:
            y = (y * base) % modulus
    return y

def rsa_enc(ek, modulus, msg):
    return mod_exp(msg, ek, modulus)

def rsa_dec(dk, modulus, ct):
    return mod_exp(ct, dk, modulus)

def prefix(integer, bitlen):
    bits = format(integer, 'b')
    bits = bits.zfill(RSA_KEY_SIZE)[0:bitlen]
    return int(bits, 2)

class DecryptOracleA:
    #######################################################
    ### You shall not use member variables (we will rename it)
    #######################################################
    __d, __n = 0, 0

    def __init__(self, d, n):
        self.__n = n
        self.__d = prefix(d, 6)

    def run_6bits(self, ct):
        mod_exp(ct, self.__d, self.__n)

class DecryptOracleB:
    #######################################################
    ### You shall not use member variables (we will rename it)
    #######################################################
    __d, __n, = 0, 0

    def __init__(self, d, n):
        self.__d = d
        self.__n = n

    def run(self, ct):
        mod_exp(ct, self.__d, self.__n)
