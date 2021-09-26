#!/usr/bin/env python3
import json
import base64
import gmpy2
import math
import argparse
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, isPrime
from Crypto.PublicKey import ECC
from fastecdsa.curve import P256, P384, P521
from fastecdsa.point import Point
from fastecdsa.util import mod_sqrt

def dprint(m):
    if args.v:
        print(f"[DEBUG] : {m}")

def genKey(keysize, e):
    # generate the key manually because pycryptodome doesn't accept key sizes < 1024 bits
    d = None
    while d is None:
        p = getPrime(keysize//2)
        q = getPrime(keysize//2)
        try:
            d = int(gmpy2.invert(e, (p-1)*(q-1)))
        except ZeroDivisionError:
            d = None
    return RSA.construct((p*q, e, d, p, q), consistency_check=False)

def getHash(header, body, hashalg, key):
    # get the ASN1 formatted hash that is signed using RSASSA-PKCS1-v1_5
    # Let pycryptodome handle the ASN1 formatting for us
    message = header + "." + body
    h = hashalg.new(message.encode())
    sig = int(pkcs1_15.new(key).sign(h).hex(), 16)
    h = pow(sig, key.e, key.n)
    return h

def removeSmallPrimes(x):
    i = 2
    while i < 2000:
        while x % i == 0:
            x = x//i
            dprint(f"Removed small factor : {i}")
        i = gmpy2.next_prime(i)
    return int(x)

def getKeysize(sig):
    sig_size = sig.bit_length()
    # do not round to the nearest power of 2
    # otherwise will not be able to recover keys of non-standard sizes
    # having a small length difference with the real key does not matter in practice
    return sig_size

def recoverRSAKey(token1, token2, e, hashalg):
    header1, body1, sig1 = token1.split(".")
    header2, body2, sig2 = token2.split(".")

    sig_num1 = int(base64.b64decode(sig1 + "==").hex(), 16)
    sig_num2 = int(base64.b64decode(sig2 + "==").hex(), 16)

    if sig_num1 == sig_num2:
        print("Tokens must be different.")
        return

    ks = getKeysize(sig_num1)
    dprint(f"Estimated key size (signature size) : {ks} bits")
    tmp_key = genKey(ks, e)
    h1 = getHash(header1, body1, hashalg, tmp_key)
    h2 = getHash(header2, body2, hashalg, tmp_key)

    # transform to mpz for faster exponentiation
    sig_num1 = gmpy2.mpz(sig_num1)
    sig_num2 = gmpy2.mpz(sig_num2)
    n = gmpy2.gcd(sig_num1**e - h1, sig_num2**e - h2)
    dprint(f"GDC result : {n}")

    # returned n can be a small multiple of the real n
    n = removeSmallPrimes(n)
    if n == 1:
        print("Failed to recover public RSA key !")
        print(f"Maybe e != {e} ?")
        return
    
    # returned n should never be a prime, otherwise this means we have factored the public key
    # which should never happen in practice (but maybe in CTF challenges)
    if isPrime(n):
        print("Found a prime public key ?!")
        print(f"{n=}\n{e=}")
        print(f"You may want to rerun this script with the -v flag")
        return

    print("Found public RSA key !")
    dprint(f"Real key size : {n.bit_length()} bits")
    print(f"{n=}\n{e=}")
    print(RSA.construct((n, e)).exportKey(format="PEM").decode())


def recoverECDSAKey(tokens, hashalg, curve, compressed):

    def recoverKeys(r, s, curve):
        # compute the 2 points having r has X coordinate
        y1, y2 = mod_sqrt(r ** 3 + curve.a * r + curve.b, curve.p)
        R1 = Point(r, y1, curve)
        R2 = Point(r, y2, curve)
        # compute r^-1
        r_inv = int(gmpy2.invert(r, curve.q))
        # compute message hash
        message = header + "." + body
        h = int(hashalg.new(message.encode()).hexdigest(), 16)
        G = Point(curve.gx, curve.gy, curve)
        # recover the two possible public keys
        k1 = r_inv * (s * R1 - h * G)
        k2 = r_inv * (s * R2 - h * G)
        return k1, k2

    keys = []
    for t in tokens:
        header, body, sig = t.split(".")
        rs = base64.b64decode(sig + "==")
        n = len(rs)//2
        r = int(rs[:n].hex(), 16)
        s = int(rs[n:].hex(), 16)
        for k in recoverKeys(r, s, curve):
            if k in keys:
                # can only happen if we have at least two tokens
                # if a key is already in the set, we are sure it's the right one
                print("Found public ECDSA key !")
                print(f"x={k.x}\ny={k.y}")
                k_ = ECC.construct(curve=curve.name.lower(), point_x=k.x, point_y=k.y)
                print(k_.export_key(format="PEM", compress=compressed))
                return
            keys.append(k)
    # If we get here, it means we only got 1 token and can't distinguish the key
    k1, k2 = keys[:2]
    k1_ = ECC.construct(curve=curve.name.lower(), point_x=k1.x, point_y=k1.y)
    k2_ = ECC.construct(curve=curve.name.lower(), point_x=k2.x, point_y=k2.y)
    print("Found 2 public ECDSA keys !")
    print(f"x={k1.x}\ny={k1.y}")
    print(k1_.export_key(format="PEM", compress=compressed))
    print("")
    print(f"x={k2.x}\ny={k2.y}")
    print(k2_.export_key(format="PEM", compress=compressed))

def handleRSA(alg, tokens, e):
    if len(tokens) < 2:
        print(f"2 tokens are needed for {alg} algorithm.")
        return

    header2 = tokens[1].split(".")[0]
    # add "==" to cope with missing padding
    header2 = json.loads(base64.b64decode(header2 + "=="))
    if header2["alg"] != alg:
        print(f"Tokens don't have the same algorithm : {header2['alg']} != {alg}")
        return

    print(f"Recovering public key for algorithm {alg}...")
    t1, t2 = tokens[:2]
    if alg == "RS256":
        recoverRSAKey(t1, t2, e, SHA256)
    elif alg == "RS384":
        recoverRSAKey(t1, t2, e, SHA384)
    elif alg == "RS512":
        recoverRSAKey(t1, t2, e, SHA512)
    else:
        print(f"Algorithm {alg} not supported.")


def handleECDSA(alg, tokens, compressed):
    if len(tokens) >= 2:
        header2 = tokens[1].split(".")[0]
        # add "==" to cope with missing padding
        header2 = json.loads(base64.b64decode(header2 + "=="))
        if header2["alg"] != alg:
            print(f"Tokens don't have the same algorithm : {header2['alg']} != {alg}")
            return

    print(f"Recovering public key for algorithm {alg}...")

    if len(tokens) == 1:
        print("There are 2 public keys that can produce this signature.")
        print("As it's not possible to know which one was used, both are displayed below.")

    if alg == "ES256":
        recoverECDSAKey(tokens, SHA256, P256, compressed)
    elif alg == "ES384":
        recoverECDSAKey(tokens, SHA384, P384, compressed)
    elif alg == "ES512":
        recoverECDSAKey(tokens, SHA512, P521, compressed)
    else:
        print(f"Algorithm {alg} not supported.")


def getArgs():
    parser = argparse.ArgumentParser(description='Recover the public key used to sign JWT tokens.')
    parser.add_argument('token', type=str, nargs='+', help='A JWT token.')
    parser.add_argument("-e", type=int, help="The RSA public exponent used. (default=65537)", default=65537, required=False)
    parser.add_argument("-compressed", action="store_true", help="Use compressed points for ECDSA public key format. (default=False)", required=False)
    parser.add_argument("-v", action="store_true", help="Verbose output, useful for debugging.", required=False)
    return parser.parse_args()

if __name__ == "__main__":

    args = getArgs()
    tokens = []
    for jwt in args.token:
        tokens.append(jwt.replace("-", "+").replace("_", "/"))

    # Check type of tokens
    header1 = tokens[0].split(".")[0]
    # add "==" to cope with missing padding
    header1 = json.loads(base64.b64decode(header1 + "=="))
    alg = header1["alg"]

    # RSASSA-PKCS1v1_5
    if alg[:2] == "RS":
        handleRSA(alg, tokens, args.e)
    # RSASSA-PSS
    elif alg[:2] == "PS":
        print(f"Sadly it's not possible to recover the public key used with algorithm {alg}, because it uses a non-deterministic padding.")
    # ECDSA P-256
    elif alg[:2] == "ES":
        handleECDSA(alg, tokens, args.compressed)
    # HMAC
    elif alg[:2] == "HS":
        print(f"Algorithm {alg} is based on HMAC, which doesn't use a public key.")
    else:
        print(f"Algorithm {alg} not supported.")