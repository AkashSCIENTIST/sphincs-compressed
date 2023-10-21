from package.adrs import ADRS
import os
import math
import hashlib
import random

# Randomness to signatures
RANDOMIZE = True

# Security parameter (in bytes)
n = 16


def set_n(val):
    global n
    n = val
    recalculate_variables()


# Winternitz parameter
w = 16


def set_w(val):
    global w
    w = val
    recalculate_variables()


# Hypertree height
h = 64


def set_h(val):
    global h
    h = val
    recalculate_variables()


# Hypertree layers
d = 8


def set_d(val):
    global d
    d = val
    recalculate_variables()


# FORS trees numbers
k = 10


def set_k(val):
    global k
    k = val
    recalculate_variables()


# FORS trees height
a = 15


def set_a(val):
    global a
    a = val
    recalculate_variables()


# Compression Factor
cf = 1


def set_cf(val):
    global cf
    cf = val
    recalculate_variables()

# SUB VALUES (AUTOMATICS)


# Message Lengt for WOTS
len_1 = math.ceil(8 * n / math.log(w, 2))
len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
len_0 = len_1 + len_2
len_x = len_0 - cf*len_2

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
SPX_DGST_BYTES = (int)(SPX_FORS_ZEROED_BYTES +
                       SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)


WOTS_ZERO_BITS = 2
SPX_OFFSER_COUNTER = 24  # 14 possible value
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


def generate_key_pair():
    """
    Generate a key pair for sphincs signatures
    :return: secret key and public key
    """
    sk, pk = spx_keygen()
    sk_0, pk_0 = bytes(), bytes()

    for i in sk:
        sk_0 += i
    for i in pk:
        pk_0 += i
    return sk_0, pk_0


def sign(m, sk):
    """
    Sign a message with sphincs algorithm
    :param m: Message to be signed
    :param sk: Secret Key
    :return: Signature of m with sk
    """
    sk_tab = []

    for i in range(0, 4):
        sk_tab.append(sk[(i * n):((i + 1) * n)])

    sig_tab = spx_sign(m, sk_tab)

    sig = sig_tab[0]  # R

    for i in sig_tab[1]:  # SIG FORS
        sig += i
    for i in sig_tab[2]:  # SIG Hypertree
        sig += i
    for i in sig_tab[3]:  # WOTS Counters
        sig += i
    sig += sig_tab[4]
    # print(len(sig))
    return sig


def verify(m, sig, pk):
    """
    Check integrity of signature
    :param m: Message signed
    :param sig: Signature of m
    :param pk: Public Key
    :return: Boolean True if signature correct
    """
    pk_tab = []
    # print("Last 10", sig[-10:])

    for i in range(0, 2):
        pk_tab.append(pk[(i * n):((i + 1) * n)])

    sig_tab = []

    sig_tab += [sig[:n]]  # R

    sig_tab += [[]]  # SIG FORS
    for i in range(n,
                   n + k * (a + 1) * n,
                   n):
        sig_tab[1].append(sig[i:(i + n)])

    sig_tab += [[]]  # SIG Hypertree
    for i in range(n + (k - 1) * (a + 1) * n,
                   n + (k - 1) * (a + 1) * n + (h + d * len_1) * n,
                   n):
        sig_tab[2].append(sig[i:(i + n)])
    sig_tab += [[sig[-4:]]]

    # print(sig_tab, pk_tab)
    return spx_verify(m, sig_tab, pk_tab)


def recalculate_variables():
    global n, w, h, d, k, a, cf
    global len_0, len_1, len_2, len_x, h_prime, t, SPX_FORS_ZERO_LAST_BITS
    global MAX_HASH_TRIALS_FORS, MAX_HASH_TRIALS_WOTS, SPX_FORS_ZEROED_BYTES
    global SPX_TREE_BITS, SPX_TREE_BYTES, SPX_LEAF_BITS, SPX_LEAF_BYTES, SPX_FORS_MSG_BYTES
    global SPX_DGST_BYTES, WANTED_CHECKSUM, SPX_WOTS_BYTES, WOTS_COUNTER_OFFSET

    len_1 = math.ceil(8 * n / math.log(w, 2))
    len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
    len_0 = len_1 + len_2
    len_x = len_0 - cf*len_2
    h_prime = h // d
    t = 2**a
    SPX_TREE_BITS = (h_prime * (d - 1))
    SPX_TREE_BYTES = ((SPX_TREE_BITS + 7) / 8)
    SPX_LEAF_BITS = h_prime
    SPX_LEAF_BYTES = ((SPX_LEAF_BITS + 7) / 8)
    SPX_FORS_MSG_BYTES = ((a * k + 7) / 8)
    SPX_DGST_BYTES = (int)(SPX_FORS_ZEROED_BYTES +
                           SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)
    WANTED_CHECKSUM = (len_1*(w-1))//2
    SPX_WOTS_BYTES = (len_1 * n)
    WOTS_COUNTER_OFFSET = (SPX_WOTS_BYTES + h * n)


# Input: Secret seed SK.seed, start index s, target node height z, public seed PK.seed, address ADRS
# Output: n-byte root node - top node on Stack
def treehash(secret_seed, s, z, public_seed, adrs: ADRS):
    if s % (1 << z) != 0:
        return -1

    stack = []

    for i in range(0, 2**z):
        adrs.set_type(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(s + i)
        node = wots_pk_gen(secret_seed, public_seed, adrs.copy())

        adrs.set_type(ADRS.TREE)
        adrs.set_tree_height(1)
        adrs.set_tree_index(s + i)

        if len(stack) > 0:
            while stack[len(stack) - 1]['height'] == adrs.get_tree_height():
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = hash(public_seed, adrs.copy(),
                            stack.pop()['node'] + node, n)
                adrs.set_tree_height(adrs.get_tree_height() + 1)

                if len(stack) <= 0:
                    break

        stack.append({'node': node, 'height': adrs.get_tree_height()})

    return stack.pop()['node']


# Input: Secret seed SK.seed, public seed PK.seed, address ADRS
# Output: XMSS public key PK
def xmss_pk_gen(secret_seed, public_key, adrs: ADRS):
    pk = treehash(secret_seed, 0, h_prime, public_key, adrs.copy())
    return pk


# Input: n-byte message M, secret seed SK.seed, index idx, public seed PK.seed, address ADRS
# Output: XMSS signature SIG_XMSS = (sig || AUTH)
def xmss_sign(m, secret_seed, idx, public_seed, adrs):
    auth = []
    for j in range(0, h_prime):
        ki = math.floor(idx // 2**j)
        if ki % 2 == 1:  # XORING idx/ 2**j with 1
            ki -= 1
        else:
            ki += 1

        auth += [treehash(secret_seed, ki * 2**j, j, public_seed, adrs.copy())]

    adrs.set_type(ADRS.WOTS_HASH)
    adrs.set_key_pair_address(idx)
    # print("Auth len sign", len(auth))

    sig, counter = wots_sign(m, secret_seed, public_seed, adrs.copy())
    sig_xmss = sig + auth
    return sig_xmss, counter


# Input: index idx, XMSS signature SIG_XMSS = (sig || AUTH), n-byte message M, public seed PK.seed, address ADRS
# Output: n-byte root value node[0]
def xmss_pk_from_sig(idx, sig_xmss, m, public_seed, adrs, counter):
    adrs.set_type(ADRS.WOTS_HASH)
    adrs.set_key_pair_address(idx)
    sig = sig_wots_from_sig_xmss(sig_xmss)
    auth = auth_from_sig_xmss(sig_xmss)
    # print("Auth len verify", len(auth))

    node_0 = wots_pk_from_sig(sig, m, public_seed, adrs.copy(), counter)
    node_1 = 0

    adrs.set_type(ADRS.TREE)
    adrs.set_tree_index(idx)
    for i in range(0, h_prime):
        adrs.set_tree_height(i + 1)

        if math.floor(idx / 2**i) % 2 == 0:
            adrs.set_tree_index(adrs.get_tree_index() // 2)
            node_1 = hash(public_seed, adrs.copy(), node_0 + auth[i], n)
        else:
            adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
            node_1 = hash(public_seed, adrs.copy(), auth[i] + node_0, n)

        node_0 = node_1

    return node_0


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


def print_bytes_int(value):
    array = []
    for val in value:
        array.append(val)
    print(array)


def print_bytes_bit(value):
    array = []
    for val in value:
        for j in range(7, -1, -1):
            array.append((val >> j) % 2)
    print(array)


def hash(seed, adrs: ADRS, value, counter=None, digest_size=n):
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


def hash2(seed, adrs: ADRS, value, counter=None, digest_size=n):
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
        buf = hash_with_counter(
            r, public_seed, public_root, value, counter_bytes, digest_size=n)
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
            buf = hash_with_counter(
                r, public_seed, public_root, value, counter_bytes, digest_size=n)
            zero_bits = int.from_bytes(buf, 'big') & mask
            if zero_bits == 0:
                found_flag = 0
                break

    # bufp += SPX_FORS_ZEROED_BYTES
    digest = buf
    # bufp += SPX_FORS_MSG_BYTES
    if SPX_TREE_BITS > 64:
        raise ValueError(
            "For given height and depth, 64 bits cannot represent all subtrees")
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


def get_wots_counters(sig):
    return sig[-2]
# FORS+C


def prf_msg(secret_seed, opt, m, digest_size):
    random.seed(int.from_bytes(secret_seed + opt +
                hash_msgg(b'0', b'0', b'0', m, digest_size * 2), "big"))
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
        # print("Total, Bits :", total, bits)
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
    return sig[0:len_x]


# def auth_from_sig_xmss(sig, is_counter = False):
def auth_from_sig_xmss(sig):
    return sig[len_x:]


def sigs_xmss_from_sig_ht(sig):
    sigs = []
    for i in range(0, d):
        sigs.append(sig[i*(h_prime + len_x):(i+1)*(h_prime + len_x)])

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
    sig_tmp, counter = xmss_sign(
        m, secret_seed, idx_leaf, public_seed, adrs.copy())
    counters.extend(counter)
    sig_ht = sig_tmp
    root = xmss_pk_from_sig(idx_leaf, sig_tmp, m,
                            public_seed, adrs.copy(), counter)

    for j in range(1, d):
        idx_leaf = idx_tree % 2**h_prime
        idx_tree = idx_tree >> h_prime

        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)

        sig_tmp, counter = xmss_sign(
            root, secret_seed, idx_leaf, public_seed, adrs.copy())
        counters.extend(counter)
        sig_ht = sig_ht + sig_tmp

        if j < d - 1:
            root = xmss_pk_from_sig(
                idx_leaf, sig_tmp, root, public_seed, adrs.copy(), counter)

    return sig_ht, counters


# Input: Message M, signature SIG_HT, public seed PK.seed, tree index idx_tree, leaf index idx_leaf, HT public key PK_HT
# Output: Boolean
def ht_verify(m, sig_ht, public_seed, idx_tree, idx_leaf, public_key_ht, counters):
    adrs = ADRS()

    sigs_xmss = sigs_xmss_from_sig_ht(sig_ht)
    sig_tmp = sigs_xmss[0]

    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    node = xmss_pk_from_sig(idx_leaf, sig_tmp, m,
                            public_seed, adrs, counters[0])

    for j in range(1, d):
        idx_leaf = idx_tree % 2**h_prime
        #idx_tree = (idx_tree - idx_tree % (2**(h - (j+1) * h_prime))) // (2**(h - (j+1) * h_prime))
        idx_tree = idx_tree >> h_prime

        sig_tmp = sigs_xmss[j]

        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)

        node = xmss_pk_from_sig(idx_leaf, sig_tmp, node,
                                public_seed, adrs, counters[j])

    if node == public_key_ht:
        return True
    else:
        return False


def fors_sk_gen(secret_seed, adrs: ADRS, idx):
    adrs.set_tree_height(0)
    adrs.set_tree_index(idx)
    sk = prf(secret_seed, adrs.copy())

    return sk


# Input: Secret seed SK.seed, start index s, target node height z, public seed PK.seed, address ADRS
# Output: n-byte root node - top node on Stack
def fors_treehash(secret_seed, s, z, public_seed, adrs):
    if s % (1 << z) != 0:
        return -1

    stack = []

    for i in range(0, 2**z):
        adrs.set_tree_height(0)
        adrs.set_tree_index(s + i)
        sk = prf(secret_seed, adrs.copy())
        node = hash(public_seed, adrs.copy(), sk, n)

        adrs.set_tree_height(1)
        adrs.set_tree_index(s + i)
        if len(stack) > 0:
            while stack[len(stack) - 1]['height'] == adrs.get_tree_height():
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = hash(public_seed, adrs.copy(),
                            stack.pop()['node'] + node, n)

                adrs.set_tree_height(adrs.get_tree_height() + 1)

                if len(stack) <= 0:
                    break
        stack.append({'node': node, 'height': adrs.get_tree_height()})

    return stack.pop()['node']


# Input: Secret seed SK.seed, public seed PK.seed, address ADRS
# Output: FORS public key PK
def fors_pk_gen(secret_seed, public_seed, adrs: ADRS):
    fors_pk_adrs = adrs.copy()

    root = bytes()
    for i in range(0, k - 1):
        root += fors_treehash(secret_seed, i * t, a, public_seed, adrs)

    fors_pk_adrs.set_type(ADRS.FORS_ROOTS)
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk = hash(public_seed, fors_pk_adrs, root)
    return pk


# Input: Bit string M, secret seed SK.seed, address ADRS, public seed PK.seed
# Output: FORS signature SIG_FORS
def fors_sign(m, secret_seed, public_seed, adrs):
    m_int = int.from_bytes(m, 'big')
    sig_fors = []

    # FORS+C dont consider last tree
    for i in range(0, k - 1):
        idx = (m_int >> (k - 1 - i) * a) % t
        # print(idx)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i * t + idx)
        sig_fors += [prf(secret_seed, adrs.copy())]

        auth = []

        for j in range(0, a):
            s = math.floor(idx // 2 ** j)
            if s % 2 == 1:  # XORING idx/ 2**j with 1
                s -= 1
            else:
                s += 1

            auth += [fors_treehash(secret_seed, i * t +
                                   s * 2**j, j, public_seed, adrs.copy())]

        sig_fors += auth

    return sig_fors


# Input: FORS signature SIG_FORS, (k lg t)-bit string M, public seed PK.seed, address ADRS
# Output: FORS public key
def fors_pk_from_sig(sig_fors, m, public_seed, adrs: ADRS):
    if type(m) != int:
        m_int = int.from_bytes(m, 'big')
    else:
        m_int = m

    sigs = auths_from_sig_fors(sig_fors)
    root = bytes()

    # changed k to k - 1 to make it true
    for i in range(0, k - 1):
        idx = (m_int >> (k - 1 - i) * a) % t

        sk = sigs[i][0]
        adrs.set_tree_height(0)
        adrs.set_tree_index(i * t + idx)
        node_0 = hash(public_seed, adrs.copy(), sk)
        node_1 = 0

        auth = sigs[i][1]
        adrs.set_tree_index(i * t + idx)  # Really Useful?

        for j in range(0, a):
            adrs.set_tree_height(j+1)

            if math.floor(idx / 2**j) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node_1 = hash(public_seed, adrs.copy(), node_0 + auth[j], n)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node_1 = hash(public_seed, adrs.copy(), auth[j] + node_0, n)

            node_0 = node_1

        root += node_0

    fors_pk_adrs = adrs.copy()
    fors_pk_adrs.set_type(ADRS.FORS_ROOTS)
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    pk = hash(public_seed, fors_pk_adrs, root, n)
    return pk

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

    idx_tree = int.from_bytes(tmp_idx_tree, 'big') >> (
        len(tmp_idx_tree) * 8 - (h - h // d))
    idx_leaf = int.from_bytes(tmp_idx_leaf, 'big') >> (
        len(tmp_idx_leaf) * 8 - (h // d))

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
    sig_ht, wots_counters = ht_sign(
        pk_fors, secret_seed, public_seed, idx_tree, idx_leaf)
    # print("Counters", wots_counters)
    # print("sign sig_ht")
    # print(sig_ht)
    # sig_ht = sig_ht[4:]

    sig += [sig_ht]
    sig += [wots_counters]
    # print(sig_ht)
    # save at last to not disturb other indexes, as
    # other places use indexes to access specific elements
    save_fors_counter(counter, sig)
    # print("Len Sign Array", len(sig))
    # print(sig[-2:])
    # print("Length of signature", sum([len(i) for i in flatten(sig)]))
    return sig


# Input: Message M, signature SIG, public key PK
# Output: Boolean
def spx_verify(m, sig, public_key):
    adrs = ADRS()
    # print(sum([len(i) for i in flatten(sig)]), "Bytes")
    r = sig[0]
    sig_fors = sig[1]
    sig_ht = sig[2]
    # wots_counters = sig[-2]
    wots_counters = get_wots_counters(sig)

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

    idx_tree = int.from_bytes(tmp_idx_tree, 'big') >> (
        len(tmp_idx_tree) * 8 - (h - h // d))
    idx_leaf = int.from_bytes(tmp_idx_leaf, 'big') >> (
        len(tmp_idx_leaf) * 8 - (h // d))

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
