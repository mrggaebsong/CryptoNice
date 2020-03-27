from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
import time

print('>>>>>>>>>>>>> RSA 4096')

# Public Key Generator
key = RSA.generate(4096)
private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
# Private Key Generator
public_key = key.publickey().export_key()
file_out = open("public.pem", "wb")
file_out.write(public_key)

print('-------------------- 1GB File --------------------------')
start_time = time.time()
print('Open the file...')
with open('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test1.txt', 'rb') as afile:
    buf = afile.read()
print('File Opened!')

digest = SHA256.new()
digest.update(buf)

# Read shared key from file
print('Import private key')
private_key = False
with open("private.pem", "r") as myfile:
    private_key = RSA.importKey(myfile.read())

# Load private key and sign message
print('Signing message...')
signer = PKCS1_v1_5.new(private_key)
sig = signer.sign(digest)
print('Sign complete!')

# Load public key and verify message
print('Verifing message...')
verifier = PKCS1_v1_5.new(private_key.publickey())
verified = verifier.verify(digest, sig)
assert verified, 'Signature verification failed'
print('Successfully verified message')
print('Sign and Verify Time: %s seconds' % (time.time() - start_time))
print('\n')

print('-------------------- 2GB File --------------------------')
start_time = time.time()
print('Open the file...')
with open('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test2.txt', 'rb') as afile:
    buf = afile.read()
print('File Opened!')

digest = SHA256.new()
digest.update(buf)

# Read shared key from file
print('Import private key')
private_key = False
with open("private.pem", "r") as myfile:
    private_key = RSA.importKey(myfile.read())

# Load private key and sign message
print('Signing message...')
signer = PKCS1_v1_5.new(private_key)
sig = signer.sign(digest)
print('Sign complete!')

# Load public key and verify message
print('Verifing message...')
verifier = PKCS1_v1_5.new(private_key.publickey())
verified = verifier.verify(digest, sig)
assert verified, 'Signature verification failed'
print('Successfully verified message')
print('Sign and Verify Time: %s seconds' % (time.time() - start_time))
print('\n')

print('-------------------- 3GB File --------------------------')
start_time = time.time()
print('Open the file...')
with open('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test3.txt', 'rb') as afile:
    buf = afile.read()
print('File Opened!')

digest = SHA256.new()
digest.update(buf)

# Read shared key from file
print('Import private key')
private_key = False
with open("private.pem", "r") as myfile:
    private_key = RSA.importKey(myfile.read())

# Load private key and sign message
print('Signing message...')
signer = PKCS1_v1_5.new(private_key)
sig = signer.sign(digest)
print('Sign complete!')

# Load public key and verify message
print('Verifing message...')
verifier = PKCS1_v1_5.new(private_key.publickey())
verified = verifier.verify(digest, sig)
assert verified, 'Signature verification failed'
print('Successfully verified message')
print('Sign and Verify Time: %s seconds' % (time.time() - start_time))
print('\n')

print('-------------------- 4GB File --------------------------')
start_time = time.time()
print('Open the file...')
with open('/mnt/c/Users/User/Documents/Github/CryptoNice/Random Files/test4.txt', 'rb') as afile:
    buf = afile.read()
print('File Opened!')

digest = SHA256.new()
digest.update(buf)

# Read shared key from file
print('Import private key')
private_key = False
with open("private.pem", "r") as myfile:
    private_key = RSA.importKey(myfile.read())

# Load private key and sign message
print('Signing message...')
signer = PKCS1_v1_5.new(private_key)
sig = signer.sign(digest)
print('Sign complete!')

# Load public key and verify message
print('Verifing message...')
verifier = PKCS1_v1_5.new(private_key.publickey())
verified = verifier.verify(digest, sig)
assert verified, 'Signature verification failed'
print('Successfully verified message')
print('Sign and Verify Time: %s seconds' % (time.time() - start_time))
print('\n')