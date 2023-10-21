"""
Parameters
"""

import math

# Randomness to signatures
RANDOMIZE = True

# Security parameter (in bytes)
n = 16

# Winternitz parameter
w = 16

# Hypertree height
h = 63

# Hypertree layers
d = 21

# FORS trees numbers
k = 19

# FORS trees height
a = 15

# Compression Factor
cf = 1

# SUB VALUES (AUTOMATICS)

# Message Lengt for WOTS
len_1 = math.ceil(8 * n / math.log(w, 2))
len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
len_0 = len_1 + len_2
len_x = len_0 - cf*len_2
if len_x <= len_0 / 2:
    len_x = math.ceil(len_0 / 2)

# XMSS Sub-Trees height
h_prime = h // d

# FORS trees leaves number
t = 2**a

# FORS+C
COUNTER_SIZE = 4
SPX_FORS_ZERO_LAST_BITS = 4
MAX_HASH_TRIALS_FORS = (1 << (SPX_FORS_ZERO_LAST_BITS + 10))
SPX_FORS_ZEROED_BYTES = ((SPX_FORS_ZERO_LAST_BITS + 7) / 8)
SPX_TREE_BITS = (h_prime * (d - 1))
SPX_TREE_BYTES = ((SPX_TREE_BITS + 7) / 8)
SPX_LEAF_BITS = h_prime
SPX_LEAF_BYTES = ((SPX_LEAF_BITS + 7) / 8)
SPX_FORS_MSG_BYTES = ((a * k + 7) / 8)
SPX_DGST_BYTES = (int)(SPX_FORS_ZEROED_BYTES + SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)


WOTS_ZERO_BITS = 2
SPX_OFFSER_COUNTER = 24 # 14 possible value
WANTED_CHECKSUM = (len_1*(w-1))//2
SPX_ADDR_BYTES = 32
SPX_WOTS_BYTES = (len_1 * n)
WOTS_COUNTER_OFFSET = (SPX_WOTS_BYTES + h * n)
MAX_HASH_TRIALS_WOTS = 1 << 20
SPX_Z = 4

SPX_ADDR_TYPE_WOTS = 0
SPX_ADDR_TYPE_WOTSPK = 1
SPX_ADDR_TYPE_HASHTREE = 2
SPX_ADDR_TYPE_FORSTREE = 3
SPX_ADDR_TYPE_FORSPK = 4
SPX_ADDR_TYPE_WOTSPRF = 5
SPX_ADDR_TYPE_FORSPRF = 6
SPX_ADDR_TYPE_COMPRESS_WOTS = 7
