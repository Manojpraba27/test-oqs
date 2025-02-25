import pyoqs

# Example: Using Kyber512 (a post-quantum encryption algorithm)
# 1. Generate key pair
public_key, private_key = pyoqs.kyber512.keypair()

# 2. Encryption
plaintext = b"Hello, post-quantum cryptography!"
ciphertext = pyoqs.kyber512.encrypt(public_key, plaintext)

# 3. Decryption
decrypted_message = pyoqs.kyber512.decrypt(private_key, ciphertext)

# Output the results
print(f"Original Message: {plaintext.decode()}")
print(f"Encrypted Message (ciphertext): {ciphertext}")
print(f"Decrypted Message: {decrypted_message.decode()}")
