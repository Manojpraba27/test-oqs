import oqs
import hashlib

# Function to derive a symmetric key from the shared secret
def derive_key(shared_secret):
    return hashlib.sha256(shared_secret).digest()

# Get user input
message = input("Enter a message to encrypt: ").encode()

# Generate key pair
with oqs.KeyEncapsulation("Kyber1024") as kem:
    public_key = kem.generate_keypair()  # Generate public and private keys

    # Encrypt (Encapsulate) to get a shared secret
    ciphertext, shared_secret_enc = kem.encap_secret(public_key)
    symmetric_key = derive_key(shared_secret_enc)  # Derive encryption key

    # Encrypt the message using XOR (simple encryption)
    encrypted_message = bytes([b ^ symmetric_key[i % len(symmetric_key)] for i, b in enumerate(message)])
    print(f"Ciphertext (Kyber Encapsulation): {ciphertext.hex()}")
    print(f"Encrypted Message: {encrypted_message.hex()}")

    # Decrypt (Decapsulate)
    shared_secret_dec = kem.decap_secret(ciphertext)
    symmetric_key_dec = derive_key(shared_secret_dec)  # Derive same encryption key

    # Decrypt the message using XOR
    decrypted_message = bytes([b ^ symmetric_key_dec[i % len(symmetric_key_dec)] for i, b in enumerate(encrypted_message)])

    print(f"Decrypted Message: {decrypted_message.decode()}")

# Check if the message is successfully decrypted
if decrypted_message == message:
    print("Encryption and decryption successful!")
else:
    print("Decryption failed!")
