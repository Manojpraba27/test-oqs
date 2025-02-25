import oqs

# Generate key pair
with oqs.KeyEncapsulation("Kyber1024") as kem:
    public_key = kem.generate_keypair()  # Generate public and private keys
    secret_key = kem.export_secret_key()  # Export the private key

    # Encrypt (Encapsulate)
    ciphertext, shared_secret_enc = kem.encap_secret(public_key)
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Shared Secret (Encapsulated): {shared_secret_enc.hex()}")

    # Decrypt (Decapsulate) using the same object
    shared_secret_dec = kem.decap_secret(ciphertext)
    print(f"Shared Secret (Decapsulated): {shared_secret_dec.hex()}")

# Check if the shared secrets match
if shared_secret_enc == shared_secret_dec:
    print("Encryption and decryption successful!")
else:
    print("Mismatch in shared secrets!")
