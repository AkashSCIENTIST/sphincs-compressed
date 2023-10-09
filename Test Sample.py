from sibc.sidh import SIKE, default_parameters
sike = SIKE(**default_parameters)
s, sk3, pk3 = sike.KeyGen()
c, K = sike.Encaps(pk3)
K_ = sike.Decaps((s, sk3, pk3), c)
print(sk3)
print('-----------------------------------=------------------------------------')
print(pk3)


# import cryptography

# # import the relevant parts of the cryptography module
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding

# private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,)
# public_key = private_key.public_key()
# message = "In spite of all their friends could say, on a winter's morn, on a stormy day, in a Sieve they went to sea!"

# # generate a signature for this message using our private key
# signature = private_key.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

# try:
#     public_key.verify(
#         signature,
#         message,
#         padding.PSS(
#             mgf=padding.MGF1(hashes.SHA256()),
#             salt_length=padding.PSS.MAX_LENGTH
#         ),
#         hashes.SHA256()
#     )
#     print('The signature is valid.')
# except:
#     # an exception was thrown
#     print('Invalid signature.  Be careful!')


# message = b"In spite of all their friends could say, on a winter's morn, on a stormy day, in a Sieve they went to sea!"

# # create the encrypted message, a.k.a. the cyphertext
# ciphertext = public_key.encrypt(
#     message,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )

# # show the ciphertext
# print(ciphertext)
# plaintext = private_key.decrypt(
#     ciphertext,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )
# print(plaintext)