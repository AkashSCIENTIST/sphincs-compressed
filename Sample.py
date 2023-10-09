import falcon
sk=falcon.SecretKey(512)
pk=falcon.PublicKey(sk)

print(sk)

print(pk)

sig=sk.sign(b"Hello")
print(sig)
print(pk.verify(b"Hello",sig))