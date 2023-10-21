from package.sphincsc import SphincsC
from package import parameters
from Server2 import digitalSignature,add_block

sphincs = SphincsC()
# sphincs.set_n(16)
# print("Parameters n", sphincs._n)
# print("SPHINCS n", sphincs.get_security())
# sphincs.set_winternitz(4)
# sphincs.set_cf(1)
# sphincs.set_a(8)


def compare(value):
    sk, pk = sphincs.generate_key_pair()
    return digitalSignature([sk, pk], value, sphincs)

print(compare("Hello"))
