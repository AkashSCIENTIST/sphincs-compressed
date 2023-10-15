"""
Hashing functions and pseudo-random generators (tweakables)
"""

from src.utils import *
from src.parameters import *
from src.adrs import *
import math
import hashlib
import random
import ctypes
# import skein

def hash(seed, adrs: ADRS, value, counter = None, digest_size=n):
    m = hashlib.sha512()
    # m = hashlib.blake2b()
    # m = skein.skein512()

    m.update(seed)
    if type(adrs) == ADRS:
        m.update(adrs.to_bin())
    else:
        m.update(adrs)
    m.update(value)

    if counter is not None:
        m.update(int_to_bytes(counter))

    hashed = m.digest()[:digest_size]

    return hashed


def hash2(seed, adrs: ADRS, value, counter = None, digest_size=n):
    m = hashlib.sha512()
    # m = hashlib.blake2b()
    # m = skein.skein512()


    m.update(seed)
    if type(adrs) == ADRS:
        m.update(adrs.to_bin())
    else:
        m.update(adrs)
    m.update(value)

    if counter is not None:
        m.update(int_to_bytes(counter))

    hashed = m.digest()[:digest_size]

    return hashed


def prf(secret_seed, adrs):
    random.seed(int.from_bytes(secret_seed + adrs.to_bin(), "big"))
    return random.randint(0, 256 ** n).to_bytes(n, byteorder='big')


def hash_msgg(r, public_seed, public_root, value, digest_size=n):
    m = hashlib.sha256()

    m.update(r)
    m.update(public_seed)
    m.update(public_root)
    m.update(value)

    hashed = m.digest()[:digest_size]

    i = 0
    while len(hashed) < digest_size:
        i += 1
        m = hashlib.sha256()

        m.update(r)
        m.update(public_seed)
        m.update(public_root)
        m.update(value)
        m.update(bytes([i]))

        hashed += m.digest()[:digest_size - len(hashed)]

    return hashed

# FORS+C
def hash_with_counter(r, public_seed, public_root, value, counter_bytes, digest_size=n): 
    m = hashlib.sha256()
    m.update(r)
    m.update(public_seed)
    m.update(public_root)
    m.update(value)
    m.update(counter_bytes)
    hashed = m.digest()[:digest_size]

    i = 0
    while len(hashed) < digest_size:
        i += 1
        m = hashlib.sha256()

        m.update(r)
        m.update(public_seed)
        m.update(public_root)
        m.update(value)
        m.update(counter_bytes)
        m.update(bytes([i]))

        hashed += m.digest()[:digest_size - len(hashed)]

    return hashed

def hash_msg(r, public_seed, public_root, value, counter, digest_size=n):
    buf = bytearray(SPX_DGST_BYTES)
    bufp = buf
    counter_bytes = bytearray(COUNTER_SIZE)
    found_flag = 1
    mask = ~(~0 << (SPX_FORS_ZERO_LAST_BITS))
    zero_bits = 0
    digest = []

    # verify stage
    if counter[0] != 0:
        counter_bytes = int.to_bytes(counter[0], COUNTER_SIZE, 'big')
        buf = hash_with_counter(r, public_seed, public_root, value, counter_bytes, digest_size=n)
        # If the expected bits are not zero the verification fails.
        zero_bits = int.from_bytes(buf, 'big') & mask
        if zero_bits != 0:
            return -1
    else:
        while found_flag:
            counter[0] += 1
            if counter[0] > MAX_HASH_TRIALS_FORS:
                return -1
            counter_bytes = int.to_bytes(counter[0], COUNTER_SIZE, 'big')
            buf = hash_with_counter(r, public_seed, public_root, value, counter_bytes, digest_size=n)
            zero_bits = int.from_bytes(buf, 'big') & mask
            if zero_bits == 0:
                found_flag = 0
                break

    # bufp += SPX_FORS_ZEROED_BYTES
    digest = buf
    # bufp += SPX_FORS_MSG_BYTES
    if SPX_TREE_BITS > 64:
        raise ValueError("For given height and depth, 64 bits cannot represent all subtrees")
    tree = int.from_bytes(buf, byteorder='big')
    tree &= (~(2**64) - 1) >> (64 - SPX_TREE_BITS)
    # bufp += SPX_TREE_BYTES
    leaf_idx = int.from_bytes(buf, byteorder='big')
    leaf_idx &= (~(2**32) - 1) >> (32 - SPX_LEAF_BITS)

    return digest

def save_fors_counter(counter, sig):
    counter_bytes = int.to_bytes(counter[0], COUNTER_SIZE, 'big')
    sig += [counter_bytes]

def get_fors_counter(sig):
    return sig[-1]
# FORS+C

def prf_msg(secret_seed, opt, m, digest_size):
    random.seed(int.from_bytes(secret_seed + opt + hash_msgg(b'0', b'0', b'0', m, digest_size * 2), "big"))
    return random.randint(0, 256 ** digest_size - 1).to_bytes(digest_size, byteorder='big')
# Input: len_X-byte string X, int w, output length out_len
# Output: out_len int array basew
def base_w(x, w, out_len):
    vin = 0
    vout = 0
    total = 0
    bits = 0
    basew = []

    for consumed in range(0, out_len):
        if bits == 0:
            total = x[vin]
            vin += 1
            bits += 8
        bits -= math.floor(math.log(w, 2))
        basew.append((total >> bits) % w)
        vout += 1

    return basew


# def sig_wots_from_sig_xmss(sig, is_counter = False):
def sig_wots_from_sig_xmss(sig):
    # if is_counter:
    #     return sig[1:len_1+1], sig[0]
    # else:
    #     return sig[0:len_1], 0
    return sig[0:len_1]


# def auth_from_sig_xmss(sig, is_counter = False):
def auth_from_sig_xmss(sig):
    # if is_counter:
    #     return sig[len_1+1:]
    # else:
    #     return sig[len_1:]
    return sig[len_1:]


def sigs_xmss_from_sig_ht(sig):
    sigs = []
    for i in range(0, d):
        sigs.append(sig[i*(h_prime + len_1):(i+1)*(h_prime + len_1)])

    return sigs


def auths_from_sig_fors(sig):
    sigs = []
    for i in range(0, k - 1):
        sigs.append([])
        sigs[i].append(sig[(a+1) * i])
        sigs[i].append(sig[((a+1) * i + 1):((a+1) * (i+1))])

    return sigs


def bytes_to_int(byte_data):
    return int.from_bytes(byte_data, 'big', signed=False)


def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big', signed=False)

def flatten(input_list):
    return [item for sublist in input_list for item in (flatten(sublist) if isinstance(sublist, list) else [sublist])]
