"""
Hypertree function based on XMSS Subs-Trees
"""

from src.parameters import *
from src.tweakables import *
from src.adrs import *
from src.xmss import *

# Input: Private seed SK.seed, public seed PK.seed
# Output: HT public key PK_HT
def ht_pk_gen(secret_seed, public_seed):
    adrs = ADRS()
    adrs.set_layer_address(d - 1)
    adrs.set_tree_address(0)
    root = xmss_pk_gen(secret_seed, public_seed, adrs.copy())
    return root


# Input: Message M, private seed SK.seed, public seed PK.seed, tree index idx_tree, leaf index idx_leaf
# Output: HT signature SIG_HT
def ht_sign(m, secret_seed, public_seed, idx_tree, idx_leaf):
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)

    counters = []
    sig_tmp, counter = xmss_sign(m, secret_seed, idx_leaf, public_seed, adrs.copy())
    counters.extend(counter)
    sig_ht = sig_tmp
    root = xmss_pk_from_sig(idx_leaf, sig_tmp, m, public_seed, adrs.copy(), counter)

    for j in range(1, d):
        idx_leaf = idx_tree % 2**h_prime
        idx_tree = idx_tree >> h_prime

        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)

        sig_tmp, counter = xmss_sign(root, secret_seed, idx_leaf, public_seed, adrs.copy())
        counters.extend(counter)
        sig_ht = sig_ht + sig_tmp

        if j < d - 1:
            root = xmss_pk_from_sig(idx_leaf, sig_tmp, root, public_seed, adrs.copy(), counter)

    return sig_ht, counters


# Input: Message M, signature SIG_HT, public seed PK.seed, tree index idx_tree, leaf index idx_leaf, HT public key PK_HT
# Output: Boolean
def ht_verify(m, sig_ht, public_seed, idx_tree, idx_leaf, public_key_ht, counters):
    adrs = ADRS()
    print("Verify Counters", len(counters))
    

    sigs_xmss = sigs_xmss_from_sig_ht(sig_ht)
    sig_tmp = sigs_xmss[0]

    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    node = xmss_pk_from_sig(idx_leaf, sig_tmp, m, public_seed, adrs, counters[0])

    for j in range(1, d):
        idx_leaf = idx_tree % 2**h_prime
        #idx_tree = (idx_tree - idx_tree % (2**(h - (j+1) * h_prime))) // (2**(h - (j+1) * h_prime))
        idx_tree = idx_tree >> h_prime

        sig_tmp = sigs_xmss[j]

        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)

        node = xmss_pk_from_sig(idx_leaf, sig_tmp, node, public_seed, adrs, counters[j])

    if node == public_key_ht:
        return True
    else:
        return False
