"""
WOTS+ Functions
"""

from src.parameters import *
from src.tweakables import *
from src.adrs import *
import math


# Input: Input string X, start index i, number of steps s, public seed PK.seed, address ADRS
# Output: value of F iterated s times on X
def chain(x, i, s, public_seed, adrs: ADRS):
    if s == 0:
        return bytes(x)

    if (i + s) > (w - 1):
        return -1

    tmp = chain(x, i, s - 1, public_seed, adrs)

    adrs.set_hash_address(i + s - 1)
    tmp = hash(public_seed, adrs, tmp, n)

    return tmp


# Input: secret seed SK.seed, address ADRS
# Output: WOTS+ private key sk
def wots_sk_gen(secret_seed, adrs: ADRS):  # Not necessary
    sk = []
    for i in range(0, len_x):
        adrs.set_chain_address(i)
        adrs.set_hash_address(0)
        sk.append(prf(secret_seed, adrs.copy()))
    return sk


# Input: secret seed SK.seed, address ADRS, public seed PK.seed
# Output: WOTS+ public key pk
def wots_pk_gen(secret_seed, public_seed, adrs: ADRS):
    wots_pk_adrs = adrs.copy()
    tmp = bytes()
    for i in range(0, len_x):
        adrs.set_chain_address(i)
        adrs.set_hash_address(0)
        sk = prf(secret_seed, adrs.copy())
        tmp += bytes(chain(sk, 0, w - 1, public_seed, adrs.copy()))

    wots_pk_adrs.set_type(ADRS.WOTS_PK)
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    pk = hash(public_seed, wots_pk_adrs, tmp)
    return pk


# Input: Message M, secret seed SK.seed, public seed PK.seed, address ADRS
# Output: WOTS+ signature sig
def wots_sign(m, secret_seed, public_seed, adrs: ADRS):

    counter = generate_counter(m, public_seed)
    # print("Counter gen", counter)
    msg = prepare_msg(m, public_seed, counter)

    sig = []
    for i in range(0, len_x):
        adrs.set_chain_address(i)
        adrs.set_hash_address(0)
        sk = prf(secret_seed, adrs.copy())
        sig += [chain(sk, 0, msg[i], public_seed, adrs.copy())]

    return sig, [int_to_bytes(counter)]


def wots_pk_from_sig(sig, m, public_seed, adrs: ADRS, counter=0):

    wots_pk_adrs = adrs.copy()
    msg = prepare_msg(m, public_seed, counter)

    tmp = bytes()
    for i in range(0, len_x):
        adrs.set_chain_address(i)
        tmp += chain(sig[i], msg[i], w - 1 - msg[i], public_seed, adrs.copy())

    wots_pk_adrs.set_type(ADRS.WOTS_PK)
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk_sig = hash(public_seed, wots_pk_adrs, tmp)
    return pk_sig


def generate_counter(m, public_seed, adrs: ADRS = ADRS()):
    mask = (~0 << (8 - WOTS_ZERO_BITS)) & 0xFFFFFFFF
    counter = 0

    # adrs.set_key_pair_address(leaf_idx)
    # adrs.set_type(ADRS.SPX_ADDR_TYPE_COMPRESS_WOTS)
    bitmask = thash_init_bitmask(adrs.copy(), public_seed)

    while True:
        counter += 1
        if(counter > MAX_HASH_TRIALS_WOTS):
            break
        adrs_bin = ull_to_bytes(
            adrs, COUNTER_SIZE, counter, SPX_OFFSER_COUNTER)
        digest = thash_fin(m, adrs_bin, bitmask, public_seed)

        if((digest[n-1] & mask) == 0):
            steps, csum = chain_lengths(digest)
            if csum == WANTED_CHECKSUM:
                break

    return counter


def prepare_msg(m, public_seed, counter, adrs: ADRS = ADRS()):
    mask = (~0 << (8 - WOTS_ZERO_BITS)) & 0xFFFFFFFF
    csum = 0
    counter = 0
    # adrs.set_key_pair_address(leaf_idx)
    adrs.set_type(SPX_ADDR_TYPE_COMPRESS_WOTS)
    bitmask = thash_init_bitmask(adrs, public_seed)
    adrs_bin = ull_to_bytes(adrs, COUNTER_SIZE, counter, SPX_OFFSER_COUNTER)
    digest = thash_fin(m, adrs_bin, bitmask, public_seed)
    msg = base_w(digest, w, len_x)
    return msg


def ull_to_bytes(adrs, outlen, in_, offset=0):
    adrs_ = bytearray(adrs.to_bin())
    for i in range(outlen-1, -1, -1):
        adrs_[i+offset] = int(in_ if in_ != b'' else 0) & int(0xff)
        in_ = int(in_ if in_ != b'' else 0) >> 8
    return adrs_


def thash_init_bitmask(adrs: ADRS, public_seed):
    return hash(public_seed, adrs, b"")


def thash_fin(m, adrs: ADRS, bitmask, public_seed):
    buf = bytearray(n+SPX_ADDR_BYTES+n)
    for i in range(len(public_seed)):
        buf[i] = public_seed[i]
    for i in range(len(adrs)):
        buf[i+n] = adrs[i]
    for i in range(n):
        buf[i+n+SPX_ADDR_BYTES] = m[i] ^ bitmask[i]
    return hash(public_seed, adrs, buf)


def chain_lengths(m):
    lengths = base_w(m, w, len_x)
    csum = wots_checksum(lengths)
    lengths = [bytes([num]) for num in lengths]
    return lengths, csum


def wots_checksum(lengths):
    csum = 0
    for i in lengths:
        csum += w-1-int(i)  # error
    return csum
