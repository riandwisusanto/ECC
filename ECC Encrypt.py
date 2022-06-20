# first intsall "pip install eciespy"
from ecies.utils import generate_eth_key
from ecies import encrypt
import time

eth_k = generate_eth_key()
privKey = eth_k.to_hex()
pubKey = eth_k.public_key.to_hex()
msg = input("Input Text : ")
enc = encrypt(pubKey, msg.encode("utf8"))
encrypt_time = time.time()
# waktu eksekusi
print("Original Text : ", msg)
print("Private Key   : ", privKey)
print("Public Key    : ", pubKey)
print("Chipper Text  : ", enc)
print("Time Execute  :  %s seconds" % (time.time() - encrypt_time))