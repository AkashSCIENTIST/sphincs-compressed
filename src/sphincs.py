"""
Main SPHINCS+ functions
"""

import math
import hashlib
import random  # Only for Pseudo-randoms
import os  # Secure Randoms

from src.utils import *
from src.parameters import *
from src.tweakables import *
from src.adrs import *
from src.wots import *
from src.xmss import *
from src.hypertree import *
from src.fors import *


# Input: (none)
# Output: SPHINCS+ key pair (SK,PK)
def spx_keygen():
    secret_seed = os.urandom(n)
    secret_prf = os.urandom(n)
    public_seed = os.urandom(n)
    public_root = ht_pk_gen(secret_seed, public_seed)

    return [secret_seed, secret_prf, public_seed, public_root], [public_seed, public_root]


# Input: Message M, private key SK = (SK.seed, SK.prf, PK.seed, PK.root)
# Output: SPHINCS+ signature SIG
def spx_sign(m, secret_key):
    adrs = ADRS()

    secret_seed = secret_key[0]
    secret_prf = secret_key[1]
    public_seed = secret_key[2]
    public_root = secret_key[3]

    opt = bytes(n)
    if RANDOMIZE:
        opt = os.urandom(n)
    r = prf_msg(secret_prf, opt, m, n)
    sig = [r]

    size_md = math.floor((k * a + 7) / 8)
    size_idx_tree = math.floor((h - h // d + 7) / 8)
    size_idx_leaf = math.floor((h // d + 7) / 8)

    # FORS+C
    # counter = [0]
    digest = hash_msgg(r, public_seed, public_root, m, 
                      size_md + size_idx_tree + size_idx_leaf)
    
    # if digest == -1:
    #     raise ValueError("Digest with counter wasn't generated properly")
    
    # split the h-msg
    # digest = hash_msg(r, public_seed, public_root, m, size_md + size_idx_tree + size_idx_leaf)
    tmp_md = digest[:size_md]
    tmp_idx_tree = digest[size_md:(size_md + size_idx_tree)]
    tmp_idx_leaf = digest[(size_md + size_idx_tree):len(digest)]

    md_int = int.from_bytes(tmp_md, 'big') >> (len(tmp_md) * 8 - k * a)
    md = md_int.to_bytes(math.ceil(k * a / 8), 'big')

    idx_tree = int.from_bytes(tmp_idx_tree, 'big') >> (len(tmp_idx_tree) * 8 - (h - h // d))
    idx_leaf = int.from_bytes(tmp_idx_leaf, 'big') >> (len(tmp_idx_leaf) * 8 - (h // d))

    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    adrs.set_type(ADRS.FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)

    counter = [0]
    md = hash_msg(r, public_seed, public_root, md, counter, SPX_FORS_ZEROED_BYTES + 
                      size_md + size_idx_tree + size_idx_leaf)
    # print(temp_mhash)
    # print("md hash")
    # print(fors_sign(temp_mhash, secret_seed, public_seed, adrs.copy()))
    # print("honfboewiebofewn")
    
    sig_fors = fors_sign(md, secret_seed, public_seed, adrs.copy())
    sig += [sig_fors]

    pk_fors = fors_pk_from_sig(sig_fors, md, public_seed, adrs.copy())
    # print("sign fors")
    # print(pk_fors)

    adrs.set_type(ADRS.TREE)
    sig_ht, wots_counters = ht_sign(pk_fors, secret_seed, public_seed, idx_tree, idx_leaf)
    print("Counters", wots_counters)
    # print("sign sig_ht")
    # print(sig_ht)
    # sig_ht = sig_ht[4:]

    sig += [sig_ht]
    sig += [wots_counters]
    # print(sig_ht)
    # save at last to not disturb other indexes, as 
    # other places use indexes to access specific elements
    save_fors_counter(counter, sig)
    print("Len Sign Array", len(sig))
    print(sig[-2:])
    print("Length of signature", sum([len(i) for i in flatten(sig)]))
    return sig


# Input: Message M, signature SIG, public key PK
# Output: Boolean
def spx_verify(m, sig, public_key):
    adrs = ADRS()
    # print(sum([len(i) for i in flatten(sig)]), "Bytes")
    r = sig[0]
    sig_fors = sig[1]
    sig_ht = sig[2]
    wots_counters = sig[-2]

    public_seed = public_key[0]
    public_root = public_key[1]

    size_md = math.floor((k * a + 7) / 8)
    size_idx_tree = math.floor((h - h // d + 7) / 8)
    size_idx_leaf = math.floor((h // d + 7) / 8)

    # FORS+C
    counter = get_fors_counter(sig)
    counter = [int.from_bytes(counter[0], 'big')]

    if counter == 0:
        raise ValueError("Retrived FORS counter value is zero")
    
    digest = hash_msgg(r, public_seed, public_root, m,
                      size_md + size_idx_tree + size_idx_leaf)
    # if digest == -1:
    #     raise ValueError("Digest with FORS counter wasn't generated properly")

    # digest = hash_msg(r, public_seed, public_root, m, size_md + size_idx_tree + size_idx_leaf)
    tmp_md = digest[:size_md]
    tmp_idx_tree = digest[size_md:(size_md + size_idx_tree)]
    tmp_idx_leaf = digest[(size_md + size_idx_tree):len(digest)]

    md_int = int.from_bytes(tmp_md, 'big') >> (len(tmp_md) * 8 - k * a)
    md = md_int.to_bytes(math.ceil(k * a / 8), 'big')
    md = hash_msg(r, public_seed, public_root, md, counter, SPX_FORS_ZEROED_BYTES + 
                      size_md + size_idx_tree + size_idx_leaf)

    idx_tree = int.from_bytes(tmp_idx_tree, 'big') >> (len(tmp_idx_tree) * 8 - (h - h // d))
    idx_leaf = int.from_bytes(tmp_idx_leaf, 'big') >> (len(tmp_idx_leaf) * 8 - (h // d))

    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    adrs.set_type(ADRS.FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)

    pk_fors = fors_pk_from_sig(sig_fors, md, public_seed, adrs)
    # print("verify fors")
    # print(pk_fors)

    adrs.set_type(ADRS.TREE)
    # print("verify sig_ht")

    # sig_ht = sig_ht[:len(sig_ht) - 4]
    # print(sig_ht)
    return ht_verify(pk_fors, sig_ht, public_seed, idx_tree, idx_leaf, public_root, wots_counters)