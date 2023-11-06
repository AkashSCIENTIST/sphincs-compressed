from adrs import ADRS
digest = ""
size_md = 0
size_idx_tree = 0
size_idx_leaf = 0
md = ""
sign_fors = []
public_seed = 0
adrs = None
sig_ht = ""
sig_fors = ""
idx_tree = 0
idx_leaf = 0
public_root = ""
wots_counters = []


def spx_verify(self, m, sig, public_key):

        counter = self.get_fors_counter(sig)
        counter = [int.from_bytes(counter[0], 'big')]

        if counter == 0:
            raise ValueError("Retrived FORS counter value is zero")

        pk_fors = self.fors_pk_from_sig(sig_fors, md, public_seed, adrs)
        return self.ht_verify(pk_fors, sig_ht, public_seed, idx_tree, idx_leaf, public_root, wots_counters)