import hashlib
import random
import time
from Crypto import Random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


# FOR EAX MODE
print('>>>>>>>>>>>>>>>>> AES in MODE_EAX')
key = get_random_bytes(16)

# 1GB file
print('---------------- 1GB File -------------------')
cipher = AES.new(key, AES.MODE_EAX)
start_time = time.time()
with open('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test1.txt', 'rb') as afile:
    buf = afile.read()
print('Encryption in process...')
ciphertext, tag = cipher.encrypt_and_digest(buf)
print('Encryption Complete!')
print('Writing file to encryption.bin')
file_out = open("encrypted.bin", "wb")
[ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
print('Writing Complete!')

print('Reading the encrypted file')
file_in = open("encrypted.bin", "rb")
nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
print('Reading Complete!')
print('Decryption in process...')
# let's assume that the key is somehow available again
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print('Decryption Complete!')
file_out.close()
file_in.close()
print()
print('1GB: %s seconds' % (time.time() - start_time))
print('\n')

# 2GB file
print('---------------- 2GB File -------------------')
cipher = AES.new(key, AES.MODE_EAX)
start_time = time.time()
with open('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test2.txt', 'rb') as afile:
    buf = afile.read()
print('Encryption in process...')
ciphertext, tag = cipher.encrypt_and_digest(buf)
print('Encryption Complete!')
print('Writing file to encryption.bin')
file_out = open("encrypted.bin", "wb")
[ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
print('Writing Complete!')

print('Reading the encrypted file')
file_in = open("encrypted.bin", "rb")
nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
print('Reading Complete!')
print('Decryption in process...')
# let's assume that the key is somehow available again
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print('Decryption Complete!')
file_out.close()
file_in.close()
print()
print('2GB: %s seconds' % (time.time() - start_time))
print('\n')

# 3GB file
print('---------------- 3GB File -------------------')
cipher = AES.new(key, AES.MODE_EAX)
start_time = time.time()
with open('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test3.txt', 'rb') as afile:
    buf = afile.read()
print('Encryption in process...')
ciphertext, tag = cipher.encrypt_and_digest(buf)
print('Encryption Complete!')
print('Writing file to encryption.bin')
file_out = open("encrypted.bin", "wb")
[ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
print('Writing Complete!')

print('Reading the encrypted file')
file_in = open("encrypted.bin", "rb")
nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
print('Reading Complete!')
print('Decryption in process...')
# let's assume that the key is somehow available again
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print('Decryption Complete!')
print()
print('3GB: %s seconds' % (time.time() - start_time))
print('\n')

# 4GB file
print('---------------- 4GB File -------------------')
cipher = AES.new(key, AES.MODE_EAX)
start_time = time.time()
with open('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test4.txt', 'rb') as afile:
    buf = afile.read()
print('Encryption in process...')
ciphertext, tag = cipher.encrypt_and_digest(buf)
print('Encryption Complete!')
print('Writing file to encryption.bin')
file_out = open("encrypted.bin", "wb")
[ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
print('Writing Complete!')

print('Reading the encrypted file')
file_in = open("encrypted.bin", "rb")
nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
print('Reading Complete!')
print('Decryption in process...')
# let's assume that the key is somehow available again
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print('Decryption Complete!')
print()
print('4GB: %s seconds' % (time.time() - start_time))
print('\n')

print('----------------------------------------------')



## FOR CBC MODE
print('>>>>>>>>>>>>>>>>> AES in MODE_CBC')
password = 'CryptoNice'.encode('utf-8')
key = hashlib.sha256(password).digest()
iv = ''.join([chr(random.randint(0, 0xFF)) for i in range(16)])

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    print('Encryption in process...')
    enc = encrypt(plaintext, key)
    print('Encryption Complete!')
    print('Writing file to encryption.bin')
    with open('encrypted.bin', 'wb') as fo:
        fo.write(enc)
    print('Writing Complete!')

def decrypt_file(file_name, key):
    print('Reading the encrypted file')
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    print('Reading Complete!')
    print('Decryption in process...')
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)
    print('Decryption Complete!')

# 1GB File
print('---------------- 1GB File -------------------')
start_time = time.time()
encrypt_file('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test1.txt', key)
decrypt_file('encrypted.bin', key)
print()
print('1GB: %s seconds' % (time.time() - start_time))
print('\n')

# 2GB File
print('---------------- 2GB File -------------------')
start_time = time.time()
encrypt_file('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test2.txt', key)
decrypt_file('encrypted.bin', key)
print()
print('2GB: %s seconds' % (time.time() - start_time))
print('\n')

# 3GB File
print('---------------- 3GB File -------------------')
start_time = time.time()
encrypt_file('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test3.txt', key)
decrypt_file('encrypted.bin', key)
print()
print('3GB: %s seconds' % (time.time() - start_time))
print('\n')

# 4GB File
print('---------------- 4GB File -------------------')
start_time = time.time()
encrypt_file('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test4.txt', key)
decrypt_file('encrypted.bin', key)
print()
print('4GB: %s seconds' % (time.time() - start_time))
print('\n')
