import time
from Cryptodome.PublicKey import RSA

key = RSA.generate(2048)
start_time = time.time()
public_key = key.publickey().export_key()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
print('RSA 2048 bit takes time: %s seconds' % (time.time() - start_time))

key = RSA.generate(3072)
start_time = time.time()
public_key = key.publickey().export_key()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
print('RSA 3072 bit takes time: %s seconds' % (time.time() - start_time))

key = RSA.generate(4096)
start_time = time.time()
public_key = key.publickey().export_key()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
print('RSA 4096 bit takes time: %s seconds' % (time.time() - start_time))