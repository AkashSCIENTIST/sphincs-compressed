from package.adrs import ADRS
import os
import math
import hashlib
import random


class SphincsC:
    def __init__(self):
        self._RANDOMIZE = True
        self._n = 16
        self._w = 16
        self._h = 64
        self._d = 8
        self._k = 10
        self._a = 15
        self._cf = 1
        self._len_1 = math.ceil(8 * self._n / math.log(self._w, 2))
        self._len_2 = math.floor(math.log(self._len_1 * (self._w - 1), 2) / math.log(self._w, 2)) + 1
        self._len_0 = self._len_1 + self._len_2
        self._len_x = self._len_0 - self._cf * self._len_2

        self._h_prime = self._h // self._d

        # FORS trees leaves number
        self._t = 2**self._a

        # FORS+C
        self._COUNTER_SIZE = 4
        self._SPX_FORS_ZERO_LAST_BITS = 4
        self._MAX_HASH_TRIALS_FORS = (1 << (self._SPX_FORS_ZERO_LAST_BITS + 10))
        self._SPX_FORS_ZEROED_BYTES = ((self._SPX_FORS_ZERO_LAST_BITS + 7) / 8)
        self._SPX_TREE_BITS = (self._h_prime * (self._d - 1))
        self._SPX_TREE_BYTES = ((self._SPX_TREE_BITS + 7) / 8)
        self._SPX_LEAF_BITS = self._h_prime
        self._SPX_LEAF_BYTES = ((self._SPX_LEAF_BITS + 7) / 8)
        self._SPX_FORS_MSG_BYTES = ((self._a * self._k + 7) / 8)
        self._SPX_DGST_BYTES = (int)(self._SPX_FORS_ZEROED_BYTES +
                            self._SPX_FORS_MSG_BYTES + self._SPX_TREE_BYTES + self._SPX_LEAF_BYTES)


        self._WOTS_ZERO_BITS = 2
        self._SPX_OFFSER_COUNTER = 24  # 14 possible value
        self._WANTED_CHECKSUM = (self._len_1*(self._w-1))//2
        self._SPX_ADDR_BYTES = 32
        self._SPX_WOTS_BYTES = (self._len_1 * self._n)
        self._WOTS_COUNTER_OFFSET = (self._SPX_WOTS_BYTES + self._h * self._n)
        self._MAX_HASH_TRIALS_WOTS = 1 << 20
        self._SPX_Z = 4

        self._SPX_ADDR_TYPE_WOTS = 0
        self._SPX_ADDR_TYPE_WOTSPK = 1
        self._SPX_ADDR_TYPE_HASHTREE = 2
        self._SPX_ADDR_TYPE_FORSTREE = 3
        self._SPX_ADDR_TYPE_FORSPK = 4
        self._SPX_ADDR_TYPE_WOTSPRF = 5
        self._SPX_ADDR_TYPE_FORSPRF = 6
        self._SPX_ADDR_TYPE_COMPRESS_WOTS = 7

    # Security parameter (in bytes)
    # n = 16
    def set_n(self, val):
        self._n = val
        print("Value of n changed")
        print(self._n)
        self.recalculate_variables()


    # Winternitz parameter
    # w = 16


    def set_w(self, val):
        # global w
        self._w = val
        print("Value of w changed")
        print(self._w)
        self.recalculate_variables()


    # Hypertree height
    # h = 64


    def set_h(self, val):
        # global h
        self._h = val
        print("Value of h changed")
        print(self._h)
        self.recalculate_variables()


    # Hypertree layers
    # d = 8


    def set_d(self, val):
        # global d
        self._d = val
        print("Value of d changed")
        print(self._d)
        self.recalculate_variables()


    # FORS trees numbers
    # k = 10


    def set_k(self, val):
        # global k
        self._k = val
        print("Value of  changed")
        print(self._k)
        self.recalculate_variables()


    # FORS trees height
    # a = 15


    def set_a(self, val):
        # global a
        self._a = val
        print("Value of a changed")
        print(self._a)
        self.recalculate_variables()


    # Compression Factor
    # cf = 1


    def set_cf(self, val):
        # global cf
        self._cf = val
        print("Value of cf changed")
        print(self._cf)
        self.recalculate_variables()
    


    def generate_key_pair(self):
        """
        Generate a key pair for sphincs signatures
        :return: secret key and public key
        """
        sk, pk = self.spx_keygen()
        sk_0, pk_0 = bytes(), bytes()

        for i in sk:
            sk_0 += i
        for i in pk:
            pk_0 += i
        return sk_0, pk_0


    def sign(self, m, sk):
        """
        Sign a message with sphincs algorithm
        :param m: Message to be signed
        :param sk: Secret Key
        :return: Signature of m with sk
        """
        sk_tab = []

        for i in range(0, 4):
            sk_tab.append(sk[(i * self._n):((i + 1) * self._n)])

        sig_tab = self.spx_sign(m, sk_tab)

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


    def verify(self, m, sig, pk):
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
            pk_tab.append(pk[(i * self._n):((i + 1) * self._n)])

        sig_tab = []

        sig_tab += [sig[:self._n]]  # R

        sig_tab += [[]]  # SIG FORS
        for i in range(self._n,
                    self._n + self._k * (self._a + 1) * self._n,
                    self._n):
            sig_tab[1].append(sig[i:(i + self._n)])

        sig_tab += [[]]  # SIG Hypertree
        for i in range(self._n + (self._k - 1) * (self._a + 1) * self._n,
                    self._n + (self._k - 1) * (self._a + 1) * self._n + (self._h + self._d * self._len_1) * self._n,
                    self._n):
            sig_tab[2].append(sig[i:(i + self._n)])
        sig_tab += [[sig[-4:]]]

        # print(sig_tab, pk_tab)
        return self.spx_verify(m, sig_tab, pk_tab)


    def recalculate_variables(self):
        print("Recalculation called")
        self._len_1 = math.ceil(8 * self._n / math.log(self._w, 2))
        self._len_2 = math.floor(math.log(self._len_1 * (self._w - 1), 2) / math.log(self._w, 2)) + 1
        self._len_0 = self._len_1 + self._len_2
        self._len_x = self._len_0 - self._cf * self._len_2

        self._h_prime = self._h // self._d

        # FORS trees leaves number
        self._t = 2**self._a

        # FORS+C
        self._COUNTER_SIZE = 4
        self._SPX_FORS_ZERO_LAST_BITS = 4
        self._MAX_HASH_TRIALS_FORS = (1 << (self._SPX_FORS_ZERO_LAST_BITS + 10))
        self._SPX_FORS_ZEROED_BYTES = ((self._SPX_FORS_ZERO_LAST_BITS + 7) / 8)
        self._SPX_TREE_BITS = (self._h_prime * (self._d - 1))
        self._SPX_TREE_BYTES = ((self._SPX_TREE_BITS + 7) / 8)
        self._SPX_LEAF_BITS = self._h_prime
        self._SPX_LEAF_BYTES = ((self._SPX_LEAF_BITS + 7) / 8)
        self._SPX_FORS_MSG_BYTES = ((self._a * self._k + 7) / 8)
        self._SPX_DGST_BYTES = (int)(self._SPX_FORS_ZEROED_BYTES +
                            self._SPX_FORS_MSG_BYTES + self._SPX_TREE_BYTES + self._SPX_LEAF_BYTES)


        self._WOTS_ZERO_BITS = 2
        self._SPX_OFFSER_COUNTER = 24  # 14 possible value
        self._WANTED_CHECKSUM = (self._len_1*(self._w-1))//2
        self._SPX_ADDR_BYTES = 32
        self._SPX_WOTS_BYTES = (self._len_1 * self._n)
        self._WOTS_COUNTER_OFFSET = (self._SPX_WOTS_BYTES + self._h * self._n)
        self._MAX_HASH_TRIALS_WOTS = 1 << 20
        self._SPX_Z = 4

        self._SPX_ADDR_TYPE_WOTS = 0
        self._SPX_ADDR_TYPE_WOTSPK = 1
        self._SPX_ADDR_TYPE_HASHTREE = 2
        self._SPX_ADDR_TYPE_FORSTREE = 3
        self._SPX_ADDR_TYPE_FORSPK = 4
        self._SPX_ADDR_TYPE_WOTSPRF = 5
        self._SPX_ADDR_TYPE_FORSPRF = 6
        self._SPX_ADDR_TYPE_COMPRESS_WOTS = 7
        


    # Input: Secret seed SK.seed, start index s, target node height z, public seed PK.seed, address ADRS
    # Output: n-byte root node - top node on Stack
    def treehash(self, secret_seed, s, z, public_seed, adrs: ADRS):
        if s % (1 << z) != 0:
            return -1

        stack = []

        for i in range(0, 2**z):
            adrs.set_type(ADRS.WOTS_HASH)
            adrs.set_key_pair_address(s + i)
            node = self.wots_pk_gen(secret_seed, public_seed, adrs.copy())

            adrs.set_type(ADRS.TREE)
            adrs.set_tree_height(1)
            adrs.set_tree_index(s + i)

            if len(stack) > 0:
                while stack[len(stack) - 1]['height'] == adrs.get_tree_height():
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node = self.hash(public_seed, adrs.copy(),
                                stack.pop()['node'] + node, self._n)
                    adrs.set_tree_height(adrs.get_tree_height() + 1)

                    if len(stack) <= 0:
                        break

            stack.append({'node': node, 'height': adrs.get_tree_height()})

        return stack.pop()['node']


    # Input: Secret seed SK.seed, public seed PK.seed, address ADRS
    # Output: XMSS public key PK
    def xmss_pk_gen(self, secret_seed, public_key, adrs: ADRS):
        pk = self.treehash(secret_seed, 0, self._h_prime, public_key, adrs.copy())
        return pk


    # Input: n-byte message M, secret seed SK.seed, index idx, public seed PK.seed, address ADRS
    # Output: XMSS signature SIG_XMSS = (sig || AUTH)
    def xmss_sign(self, m, secret_seed, idx, public_seed, adrs):
        auth = []
        for j in range(0, self._h_prime):
            ki = math.floor(idx // 2**j)
            if ki % 2 == 1:  # XORING idx/ 2**j with 1
                ki -= 1
            else:
                ki += 1

            auth += [self.treehash(secret_seed, ki * 2**j, j, public_seed, adrs.copy())]

        adrs.set_type(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(idx)
        # print("Auth len sign", len(auth))

        sig, counter = self.wots_sign(m, secret_seed, public_seed, adrs.copy())
        sig_xmss = sig + auth
        return sig_xmss, counter


    # Input: index idx, XMSS signature SIG_XMSS = (sig || AUTH), n-byte message M, public seed PK.seed, address ADRS
    # Output: n-byte root value node[0]
    def xmss_pk_from_sig(self, idx, sig_xmss, m, public_seed, adrs, counter):
        adrs.set_type(ADRS.WOTS_HASH)
        adrs.set_key_pair_address(idx)
        sig = self.sig_wots_from_sig_xmss(sig_xmss)
        auth = self.auth_from_sig_xmss(sig_xmss)
        # print("Auth len verify", len(auth))

        node_0 = self.wots_pk_from_sig(sig, m, public_seed, adrs.copy(), counter)
        node_1 = 0

        adrs.set_type(ADRS.TREE)
        adrs.set_tree_index(idx)
        for i in range(0, self._h_prime):
            adrs.set_tree_height(i + 1)

            if math.floor(idx / 2**i) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node_1 = self.hash(public_seed, adrs.copy(), node_0 + auth[i], self._n)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node_1 = self.hash(public_seed, adrs.copy(), auth[i] + node_0, self._n)

            node_0 = node_1

        return node_0


    # Input: Input string X, start index i, number of steps s, public seed PK.seed, address ADRS
    # Output: value of F iterated s times on X
    def chain(self, x, i, s, public_seed, adrs: ADRS):
        if s == 0:
            return bytes(x)

        if (i + s) > (self._w - 1):
            return -1

        tmp = self.chain(x, i, s - 1, public_seed, adrs)

        adrs.set_hash_address(i + s - 1)
        tmp = self.hash(public_seed, adrs, tmp, self._n)

        return tmp


    # Input: secret seed SK.seed, address ADRS
    # Output: WOTS+ private key sk
    def wots_sk_gen(self, secret_seed, adrs: ADRS):  # Not necessary
        sk = []
        for i in range(0, self._len_x):
            adrs.set_chain_address(i)
            adrs.set_hash_address(0)
            sk.append(self.prf(secret_seed, adrs.copy()))
        return sk


    # Input: secret seed SK.seed, address ADRS, public seed PK.seed
    # Output: WOTS+ public key pk
    def wots_pk_gen(self, secret_seed, public_seed, adrs: ADRS):
        wots_pk_adrs = adrs.copy()
        tmp = bytes()
        for i in range(0, self._len_x):
            adrs.set_chain_address(i)
            adrs.set_hash_address(0)
            sk = self.prf(secret_seed, adrs.copy())
            tmp += bytes(self.chain(sk, 0, self._w - 1, public_seed, adrs.copy()))

        wots_pk_adrs.set_type(ADRS.WOTS_PK)
        wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

        pk = self.hash(public_seed, wots_pk_adrs, tmp)
        return pk


    # Input: Message M, secret seed SK.seed, public seed PK.seed, address ADRS
    # Output: WOTS+ signature sig
    def wots_sign(self, m, secret_seed, public_seed, adrs: ADRS):

        counter = self.generate_counter(m, public_seed)
        # print("Counter gen", counter)
        msg = self.prepare_msg(m, public_seed, counter)

        sig = []
        for i in range(0, self._len_x):
            adrs.set_chain_address(i)
            adrs.set_hash_address(0)
            sk = self.prf(secret_seed, adrs.copy())
            sig += [self.chain(sk, 0, msg[i], public_seed, adrs.copy())]

        return sig, [self.int_to_bytes(counter)]


    def wots_pk_from_sig(self, sig, m, public_seed, adrs: ADRS, counter=0):

        wots_pk_adrs = adrs.copy()
        msg = self.prepare_msg(m, public_seed, counter)

        tmp = bytes()
        for i in range(0, self._len_x):
            adrs.set_chain_address(i)
            tmp += self.chain(sig[i], msg[i], self._w - 1 - msg[i], public_seed, adrs.copy())

        wots_pk_adrs.set_type(ADRS.WOTS_PK)
        wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk_sig = self.hash(public_seed, wots_pk_adrs, tmp)
        return pk_sig


    def generate_counter(self, m, public_seed, adrs: ADRS = ADRS()):
        mask = (~0 << (8 - self._WOTS_ZERO_BITS)) & 0xFFFFFFFF
        counter = 0

        # adrs.set_key_pair_address(leaf_idx)
        # adrs.set_type(ADRS.SPX_ADDR_TYPE_COMPRESS_WOTS)
        bitmask = self.thash_init_bitmask(adrs.copy(), public_seed)

        while True:
            counter += 1
            if(counter > self._MAX_HASH_TRIALS_WOTS):
                break
            adrs_bin = self.ull_to_bytes(
                adrs, self._COUNTER_SIZE, counter, self._SPX_OFFSER_COUNTER)
            digest = self.thash_fin(m, adrs_bin, bitmask, public_seed)

            if((digest[self._n-1] & mask) == 0):
                steps, csum = self.chain_lengths(digest)
                if csum == self._WANTED_CHECKSUM:
                    break

        return counter


    def prepare_msg(self, m, public_seed, counter, adrs: ADRS = ADRS()):
        mask = (~0 << (8 - self._WOTS_ZERO_BITS)) & 0xFFFFFFFF
        csum = 0
        counter = 0
        # adrs.set_key_pair_address(leaf_idx)
        adrs.set_type(self._SPX_ADDR_TYPE_COMPRESS_WOTS)
        bitmask = self.thash_init_bitmask(adrs, public_seed)
        adrs_bin = self.ull_to_bytes(adrs, self._COUNTER_SIZE, counter, self._SPX_OFFSER_COUNTER)
        digest = self.thash_fin(m, adrs_bin, bitmask, public_seed)
        msg = self.base_w(digest, self._w, self._len_x)
        return msg


    def ull_to_bytes(self, adrs, outlen, in_, offset=0):
        adrs_ = bytearray(adrs.to_bin())
        for i in range(outlen-1, -1, -1):
            adrs_[i+offset] = int(in_ if in_ != b'' else 0) & int(0xff)
            in_ = int(in_ if in_ != b'' else 0) >> 8
        return adrs_


    def thash_init_bitmask(self, adrs: ADRS, public_seed):
        return self.hash(public_seed, adrs, b"")


    def thash_fin(self, m, adrs: ADRS, bitmask, public_seed):
        buf = bytearray(self._n+self._SPX_ADDR_BYTES+self._n)
        for i in range(len(public_seed)):
            buf[i] = public_seed[i]
        for i in range(len(adrs)):
            buf[i+self._n] = adrs[i]
        for i in range(self._n):
            buf[i+self._n+self._SPX_ADDR_BYTES] = m[i] ^ bitmask[i]
        return self.hash(public_seed, adrs, buf)


    def chain_lengths(self, m):
        lengths = self.base_w(m, self._w, self._len_x)
        csum = self.wots_checksum(lengths)
        lengths = [bytes([num]) for num in lengths]
        return lengths, csum


    def wots_checksum(self, lengths):
        csum = 0
        for i in lengths:
            csum += self._w-1-int(i)  # error
        return csum


    def print_bytes_int(self, value):
        array = []
        for val in value:
            array.append(val)
        print(array)


    def print_bytes_bit(self, value):
        array = []
        for val in value:
            for j in range(7, -1, -1):
                array.append((val >> j) % 2)
        print(array)


    def hash(self, seed, adrs: ADRS, value, counter=None, digest_size=None):
        if(digest_size == None):
            digest_size = self._n
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
            m.update(self.int_to_bytes(counter))

        hashed = m.digest()[:digest_size]

        return hashed


    def hash2(self, seed, adrs: ADRS, value, counter=None, digest_size=None):
        if(digest_size == None):
            digest_size = self._n
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
            m.update(self.int_to_bytes(counter))

        hashed = m.digest()[:digest_size]

        return hashed


    def prf(self, secret_seed, adrs):
        random.seed(int.from_bytes(secret_seed + adrs.to_bin(), "big"))
        return random.randint(0, 256 ** self._n).to_bytes(self._n, byteorder='big')


    def hash_msgg(self, r, public_seed, public_root, value, digest_size=None):
        if(digest_size == None):
            digest_size = self._n
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


    def hash_with_counter(self, r, public_seed, public_root, value, counter_bytes, digest_size=None):
        if(digest_size == None):
            digest_size = self._n
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


    def hash_msg(self, r, public_seed, public_root, value, counter, digest_size=None):
        if(digest_size == None):
            digest_size = self._n
        buf = bytearray(self._SPX_DGST_BYTES)
        bufp = buf
        counter_bytes = bytearray(self._COUNTER_SIZE)
        found_flag = 1
        mask = ~(~0 << (self._SPX_FORS_ZERO_LAST_BITS))
        zero_bits = 0
        digest = []

        # verify stage
        if counter[0] != 0:
            counter_bytes = int.to_bytes(counter[0], self._COUNTER_SIZE, 'big')
            buf = self.hash_with_counter(
                r, public_seed, public_root, value, counter_bytes, digest_size=self._n)
            # If the expected bits are not zero the verification fails.
            zero_bits = int.from_bytes(buf, 'big') & mask
            if zero_bits != 0:
                return -1
        else:
            while found_flag:
                counter[0] += 1
                if counter[0] > self._MAX_HASH_TRIALS_FORS:
                    return -1
                counter_bytes = int.to_bytes(counter[0], self._COUNTER_SIZE, 'big')
                buf = self.hash_with_counter(
                    r, public_seed, public_root, value, counter_bytes, digest_size = self._n)
                zero_bits = int.from_bytes(buf, 'big') & mask
                if zero_bits == 0:
                    found_flag = 0
                    break

        # bufp += SPX_FORS_ZEROED_BYTES
        digest = buf
        # bufp += SPX_FORS_MSG_BYTES
        if self._SPX_TREE_BITS > 64:
            raise ValueError(
                "For given height and depth, 64 bits cannot represent all subtrees")
        tree = int.from_bytes(buf, byteorder='big')
        tree &= (~(2**64) - 1) >> (64 - self._SPX_TREE_BITS)
        # bufp += SPX_TREE_BYTES
        leaf_idx = int.from_bytes(buf, byteorder='big')
        leaf_idx &= (~(2**32) - 1) >> (32 - self._SPX_LEAF_BITS)

        return digest


    def save_fors_counter(self, counter, sig):
        counter_bytes = int.to_bytes(counter[0], self._COUNTER_SIZE, 'big')
        sig += [counter_bytes]


    def get_fors_counter(self, sig):
        return sig[-1]


    def get_wots_counters(self, sig):
        return sig[-2]
    # FORS+C


    def prf_msg(self, secret_seed, opt, m, digest_size):
        random.seed(int.from_bytes(secret_seed + opt +
                    self.hash_msgg(b'0', b'0', b'0', m, digest_size * 2), "big"))
        return random.randint(0, 256 ** digest_size - 1).to_bytes(digest_size, byteorder='big')
    # Input: len_X-byte string X, int w, output length out_len
    # Output: out_len int array basew


    def base_w(self, x, w, out_len):
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
    def sig_wots_from_sig_xmss(self, sig):
        return sig[0:self._len_x]


    # def auth_from_sig_xmss(sig, is_counter = False):
    def auth_from_sig_xmss(self, sig):
        return sig[self._len_x:]


    def sigs_xmss_from_sig_ht(self, sig):
        sigs = []
        for i in range(0, self._d):
            sigs.append(sig[i*(self._h_prime + self._len_x):(i+1)*(self._h_prime + self._len_x)])

        return sigs


    def auths_from_sig_fors(self, sig):
        sigs = []
        for i in range(0, self._k - 1):
            sigs.append([])
            sigs[i].append(sig[(self._a+1) * i])
            sigs[i].append(sig[((self._a+1) * i + 1):((self._a+1) * (i+1))])

        return sigs


    def bytes_to_int(self, byte_data):
        return int.from_bytes(byte_data, 'big', signed=False)


    def int_to_bytes(self, n):
        return n.to_bytes((n.bit_length() + 7) // 8, 'big', signed=False)


    def flatten(self, input_list):
        return [item for sublist in input_list for item in (self.flatten(sublist) if isinstance(sublist, list) else [sublist])]


    # Input: Private seed SK.seed, public seed PK.seed
    # Output: HT public key PK_HT
    def ht_pk_gen(self, secret_seed, public_seed):
        adrs = ADRS()
        adrs.set_layer_address(self._d - 1)
        adrs.set_tree_address(0)
        root = self.xmss_pk_gen(secret_seed, public_seed, adrs.copy())
        return root


    # Input: Message M, private seed SK.seed, public seed PK.seed, tree index idx_tree, leaf index idx_leaf
    # Output: HT signature SIG_HT
    def ht_sign(self, m, secret_seed, public_seed, idx_tree, idx_leaf):
        adrs = ADRS()
        adrs.set_layer_address(0)
        adrs.set_tree_address(idx_tree)

        counters = []
        sig_tmp, counter = self.xmss_sign(
            m, secret_seed, idx_leaf, public_seed, adrs.copy())
        counters.extend(counter)
        sig_ht = sig_tmp
        root = self.xmss_pk_from_sig(idx_leaf, sig_tmp, m,
                                public_seed, adrs.copy(), counter)

        for j in range(1, self._d):
            idx_leaf = idx_tree % 2**self._h_prime
            idx_tree = idx_tree >> self._h_prime

            adrs.set_layer_address(j)
            adrs.set_tree_address(idx_tree)

            sig_tmp, counter = self.xmss_sign(
                root, secret_seed, idx_leaf, public_seed, adrs.copy())
            counters.extend(counter)
            sig_ht = sig_ht + sig_tmp

            if j < self._d - 1:
                root = self.xmss_pk_from_sig(
                    idx_leaf, sig_tmp, root, public_seed, adrs.copy(), counter)

        return sig_ht, counters


    # Input: Message M, signature SIG_HT, public seed PK.seed, tree index idx_tree, leaf index idx_leaf, HT public key PK_HT
    # Output: Boolean
    def ht_verify(self, m, sig_ht, public_seed, idx_tree, idx_leaf, public_key_ht, counters):
        adrs = ADRS()

        sigs_xmss = self.sigs_xmss_from_sig_ht(sig_ht)
        sig_tmp = sigs_xmss[0]

        adrs.set_layer_address(0)
        adrs.set_tree_address(idx_tree)
        node = self.xmss_pk_from_sig(idx_leaf, sig_tmp, m,
                                public_seed, adrs, counters[0])

        for j in range(1, self._d):
            idx_leaf = idx_tree % 2**self._h_prime
            #idx_tree = (idx_tree - idx_tree % (2**(h - (j+1) * h_prime))) // (2**(h - (j+1) * h_prime))
            idx_tree = idx_tree >> self._h_prime

            sig_tmp = sigs_xmss[j]

            adrs.set_layer_address(j)
            adrs.set_tree_address(idx_tree)

            node = self.xmss_pk_from_sig(idx_leaf, sig_tmp, node,
                                    public_seed, adrs, counters[j])

        if node == public_key_ht:
            return True
        else:
            return False


    def fors_sk_gen(self, secret_seed, adrs: ADRS, idx):
        adrs.set_tree_height(0)
        adrs.set_tree_index(idx)
        sk = self.prf(secret_seed, adrs.copy())

        return sk


    # Input: Secret seed SK.seed, start index s, target node height z, public seed PK.seed, address ADRS
    # Output: n-byte root node - top node on Stack
    def fors_treehash(self, secret_seed, s, z, public_seed, adrs):
        if s % (1 << z) != 0:
            return -1

        stack = []

        for i in range(0, 2**z):
            adrs.set_tree_height(0)
            adrs.set_tree_index(s + i)
            sk = self.prf(secret_seed, adrs.copy())
            node = self.hash(public_seed, adrs.copy(), sk, self._n)

            adrs.set_tree_height(1)
            adrs.set_tree_index(s + i)
            if len(stack) > 0:
                while stack[len(stack) - 1]['height'] == adrs.get_tree_height():
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node = self.hash(public_seed, adrs.copy(),
                                stack.pop()['node'] + node, self._n)

                    adrs.set_tree_height(adrs.get_tree_height() + 1)

                    if len(stack) <= 0:
                        break
            stack.append({'node': node, 'height': adrs.get_tree_height()})

        return stack.pop()['node']


    # Input: Secret seed SK.seed, public seed PK.seed, address ADRS
    # Output: FORS public key PK
    def fors_pk_gen(self, secret_seed, public_seed, adrs: ADRS):
        fors_pk_adrs = adrs.copy()

        root = bytes()
        for i in range(0, self._k - 1):
            root += self.fors_treehash(secret_seed, i * self._t, self._a, public_seed, adrs)

        fors_pk_adrs.set_type(ADRS.FORS_ROOTS)
        fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
        pk = self.hash(public_seed, fors_pk_adrs, root)
        return pk


    # Input: Bit string M, secret seed SK.seed, address ADRS, public seed PK.seed
    # Output: FORS signature SIG_FORS
    def fors_sign(self, m, secret_seed, public_seed, adrs):
        m_int = int.from_bytes(m, 'big')
        sig_fors = []

        # FORS+C dont consider last tree
        for i in range(0, self._k - 1):
            idx = (m_int >> (self._k - 1 - i) * self._a) % self._t
            # print(idx)
            adrs.set_tree_height(0)
            adrs.set_tree_index(i * self._t + idx)
            sig_fors += [self.prf(secret_seed, adrs.copy())]

            auth = []

            for j in range(0, self._a):
                s = math.floor(idx // 2 ** j)
                if s % 2 == 1:  # XORING idx/ 2**j with 1
                    s -= 1
                else:
                    s += 1

                auth += [self.fors_treehash(secret_seed, i * self._t +
                                    s * 2**j, j, public_seed, adrs.copy())]

            sig_fors += auth

        return sig_fors


    # Input: FORS signature SIG_FORS, (k lg t)-bit string M, public seed PK.seed, address ADRS
    # Output: FORS public key
    def fors_pk_from_sig(self, sig_fors, m, public_seed, adrs: ADRS):
        if type(m) != int:
            m_int = int.from_bytes(m, 'big')
        else:
            m_int = m

        sigs = self.auths_from_sig_fors(sig_fors)
        root = bytes()

        # changed k to k - 1 to make it true
        for i in range(0, self._k - 1):
            idx = (m_int >> (self._k - 1 - i) * self._a) % self._t

            sk = sigs[i][0]
            adrs.set_tree_height(0)
            adrs.set_tree_index(i * self._t + idx)
            node_0 = self.hash(public_seed, adrs.copy(), sk)
            node_1 = 0

            auth = sigs[i][1]
            adrs.set_tree_index(i * self._t + idx)  # Really Useful?

            for j in range(0, self._a):
                adrs.set_tree_height(j+1)

                if math.floor(idx / 2**j) % 2 == 0:
                    adrs.set_tree_index(adrs.get_tree_index() // 2)
                    node_1 = self.hash(public_seed, adrs.copy(), node_0 + auth[j], self._n)
                else:
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node_1 = self.hash(public_seed, adrs.copy(), auth[j] + node_0, self._n)

                node_0 = node_1

            root += node_0

        fors_pk_adrs = adrs.copy()
        fors_pk_adrs.set_type(ADRS.FORS_ROOTS)
        fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

        pk = self.hash(public_seed, fors_pk_adrs, root, self._n)
        return pk

    # Input: (none)
    # Output: SPHINCS+ key pair (SK,PK)


    def spx_keygen(self):
        secret_seed = os.urandom(self._n)
        secret_prf = os.urandom(self._n)
        public_seed = os.urandom(self._n)
        public_root = self.ht_pk_gen(secret_seed, public_seed)

        return [secret_seed, secret_prf, public_seed, public_root], [public_seed, public_root]


    # Input: Message M, private key SK = (SK.seed, SK.prf, PK.seed, PK.root)
    # Output: SPHINCS+ signature SIG
    def spx_sign(self, m, secret_key):
        adrs = ADRS()

        secret_seed = secret_key[0]
        secret_prf = secret_key[1]
        public_seed = secret_key[2]
        public_root = secret_key[3]

        opt = bytes(self._n)
        if self._RANDOMIZE:
            opt = os.urandom(self._n)
        r = self.prf_msg(secret_prf, opt, m, self._n)
        sig = [r]

        size_md = math.floor((self._k * self._a + 7) / 8)
        size_idx_tree = math.floor((self._h - self._h // self._d + 7) / 8)
        size_idx_leaf = math.floor((self._h // self._d + 7) / 8)

        # FORS+C
        # counter = [0]
        digest = self.hash_msgg(r, public_seed, public_root, m,
                        size_md + size_idx_tree + size_idx_leaf)

        # if digest == -1:
        #     raise ValueError("Digest with counter wasn't generated properly")

        # split the h-msg
        # digest = hash_msg(r, public_seed, public_root, m, size_md + size_idx_tree + size_idx_leaf)
        tmp_md = digest[:size_md]
        tmp_idx_tree = digest[size_md:(size_md + size_idx_tree)]
        tmp_idx_leaf = digest[(size_md + size_idx_tree):len(digest)]

        md_int = int.from_bytes(tmp_md, 'big') >> (len(tmp_md) * 8 - self._k * self._a)
        md = md_int.to_bytes(math.ceil(self._k * self._a / 8), 'big')

        idx_tree = int.from_bytes(tmp_idx_tree, 'big') >> (
            len(tmp_idx_tree) * 8 - (self._h - self._h // self._d))
        idx_leaf = int.from_bytes(tmp_idx_leaf, 'big') >> (
            len(tmp_idx_leaf) * 8 - (self._h // self._d))

        adrs.set_layer_address(0)
        adrs.set_tree_address(idx_tree)
        adrs.set_type(ADRS.FORS_TREE)
        adrs.set_key_pair_address(idx_leaf)

        counter = [0]
        md = self.hash_msg(r, public_seed, public_root, md, counter, self._SPX_FORS_ZEROED_BYTES +
                    size_md + size_idx_tree + size_idx_leaf)
        # print(temp_mhash)
        # print("md hash")
        # print(fors_sign(temp_mhash, secret_seed, public_seed, adrs.copy()))
        # print("honfboewiebofewn")

        sig_fors = self.fors_sign(md, secret_seed, public_seed, adrs.copy())
        sig += [sig_fors]

        pk_fors = self.fors_pk_from_sig(sig_fors, md, public_seed, adrs.copy())
        # print("sign fors")
        # print(pk_fors)

        adrs.set_type(ADRS.TREE)
        sig_ht, wots_counters = self.ht_sign(
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
        self.save_fors_counter(counter, sig)
        # print("Len Sign Array", len(sig))
        # print(sig[-2:])
        # print("Length of signature", sum([len(i) for i in flatten(sig)]))
        return sig


    # Input: Message M, signature SIG, public key PK
    # Output: Boolean
    def spx_verify(self, m, sig, public_key):
        adrs = ADRS()
        # print(sum([len(i) for i in flatten(sig)]), "Bytes")
        r = sig[0]
        sig_fors = sig[1]
        sig_ht = sig[2]
        # wots_counters = sig[-2]
        wots_counters = self.get_wots_counters(sig)

        public_seed = public_key[0]
        public_root = public_key[1]

        size_md = math.floor((self._k * self._a + 7) / 8)
        size_idx_tree = math.floor((self._h - self._h // self._d + 7) / 8)
        size_idx_leaf = math.floor((self._h // self._d + 7) / 8)

        # FORS+C
        counter = self.get_fors_counter(sig)
        counter = [int.from_bytes(counter[0], 'big')]

        if counter == 0:
            raise ValueError("Retrived FORS counter value is zero")

        digest = self.hash_msgg(r, public_seed, public_root, m,
                        size_md + size_idx_tree + size_idx_leaf)
        # if digest == -1:
        #     raise ValueError("Digest with FORS counter wasn't generated properly")

        # digest = hash_msg(r, public_seed, public_root, m, size_md + size_idx_tree + size_idx_leaf)
        tmp_md = digest[:size_md]
        tmp_idx_tree = digest[size_md:(size_md + size_idx_tree)]
        tmp_idx_leaf = digest[(size_md + size_idx_tree):len(digest)]

        md_int = int.from_bytes(tmp_md, 'big') >> (len(tmp_md) * 8 - self._k * self._a)
        md = md_int.to_bytes(math.ceil(self._k * self._a / 8), 'big')
        md = self.hash_msg(r, public_seed, public_root, md, counter, self._SPX_FORS_ZEROED_BYTES +
                    size_md + size_idx_tree + size_idx_leaf)

        idx_tree = int.from_bytes(tmp_idx_tree, 'big') >> (
            len(tmp_idx_tree) * 8 - (self._h - self._h // self._d))
        idx_leaf = int.from_bytes(tmp_idx_leaf, 'big') >> (
            len(tmp_idx_leaf) * 8 - (self._h // self._d))

        adrs.set_layer_address(0)
        adrs.set_tree_address(idx_tree)
        adrs.set_type(ADRS.FORS_TREE)
        adrs.set_key_pair_address(idx_leaf)

        pk_fors = self.fors_pk_from_sig(sig_fors, md, public_seed, adrs)
        # print("verify fors")
        # print(pk_fors)

        adrs.set_type(ADRS.TREE)
        # print("verify sig_ht")

        # sig_ht = sig_ht[:len(sig_ht) - 4]
        # print(sig_ht)
        return self.ht_verify(pk_fors, sig_ht, public_seed, idx_tree, idx_leaf, public_root, wots_counters)

