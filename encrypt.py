from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256

'''
the encrypt function. first generate the initialization vector
then generate the cipher
then pad the message which is necessary for the chaining nature of 
    CBC to work; the plaintext is a multiple of the block size
then encrypt the message
'''
def encrypt(msg, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_msg = pad(msg.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_msg)
    hmac = HMAC.new(key, iv + ciphertext, digestmod=SHA256)
    return iv + ciphertext + hmac.digest()

# ask the user for a key length
key_len = int(input("enter a key length: "))

# generate a random IV/key of the specified length
key = get_random_bytes(key_len)

print("your key is: ", key.hex())

# ask the user for a msg
msg = input("enter a message: ")

# encrypt it
encrypted_msg = encrypt(msg, key)

# print out the encrypted msg
print("encrypted msg is:", encrypted_msg.hex())
