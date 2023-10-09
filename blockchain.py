import datetime
import hashlib
import json
from sibc.sidh import SIKE, default_parameters
import time
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block(proof=1, previous_hash='0')

    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash}
        print(block)
        self.chain.append(block)
        return block

    def print_previous_block(self):
        if len(self.chain)==0:
            return -1
        return self.chain[-1]['previous_hash']
    def get_previous_block(self):
        return self.chain[-1]
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False

        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            if hash_operation[:5] == '00000':
                check_proof = True
            else:
                new_proof += 1

        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False

            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof ** 2 - previous_proof ** 2).encode()).hexdigest()

            if hash_operation[:5] != '00000':
                return False
            previous_block = block
            block_index += 1

        return True

sike = SIKE(**default_parameters)
class Transaction:
    def __init__(self):
        # self.client1 = Ntru(7, 29, 491531)
        # # f(x) = 1 + x - x^2 - x^4 + x^5
        # f = [1, 1, -1, 0, -1, 1]
        # # g(x) = -1 + x^2 + x^3 - x^6
        # g = [-1, 0, 1, 1, 0, 0, -1]
        # d = 2
        # self.client1.genPublicKey(f, g, 2)
        
        self.s, self.private_key, self.public_key = sike.KeyGen()
        # self.pub_key, self.pri_key = self.client1.getPublicKey()

    def cmp1(self):
        c, K = sike.Encaps(self.public_key)
        K_ = sike.Decaps((self.s, self.private_key, self.public_key), c)
        return K==K_
    

    def signVerification(self):
        if(self.cmp1()):
            return True
        else:
            return False




blockchain = Blockchain()
tran = Transaction()
# Mining a new block
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    block = blockchain.create_block(proof, previous_hash)
    print(block)
if(tran.cmp1()):
        if(blockchain.print_previous_block()==-1):
            blockchain.create_block(1,'0')
        else:
            mine_block()
else:
    print("Valid Key is required")