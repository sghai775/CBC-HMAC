'''
written by nick thoennes and surya ghai
'''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256

'''
the decrypt function. 
first generate the IV from the encrypted msg according to the block size
then recreate the cipher from the key
then decrypt the encrypted message
then unpad the msg
then decode the msg
'''
def decrypt(encrypted_msg, key):
    block_size = AES.block_size
    iv = encrypted_msg[:block_size]
    
    hmac_start = len(encrypted_msg) - SHA256.digest_size
    cipher = encrypted_msg[block_size:hmac_start]
    hmac = encrypted_msg[hmac_start:]

    # verify the HMAC
    expected_hmac = HMAC.new(key, iv+cipher, digestmod=SHA256)
    expected_hmac = expected_hmac.digest()
    if expected_hmac != hmac:
        raise ValueError("verification failed")

    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = cipher.decrypt(encrypted_msg[block_size:hmac_start])
    msg = unpad(msg, block_size)
    return msg.decode()

# ask the user for the encrypted msg
encrypted_msg = bytes.fromhex(input("enter the encrypted message: "))  # Input as byte string

# ask the user for the key
key = bytes.fromhex(input("enter the key: "))

# decrypt the message and print it out
decrypted_msg = decrypt(encrypted_msg, key)
print("decrypted message is:", decrypted_msg)
