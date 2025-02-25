import socket
import oqs
import hashlib

HOST = "127.0.0.1"
PORT = 12345

# Function to derive a symmetric key from the shared secret
def derive_key(shared_secret):
    return hashlib.sha256(shared_secret).digest()

# Connect to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))

    # Receive the public key from the server
    public_key = client.recv(1024)

    # Generate a Kyber shared secret
    with oqs.KeyEncapsulation("Kyber1024") as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
        symmetric_key = derive_key(shared_secret)

        # Send ciphertext (encrypted shared secret)
        client.sendall(ciphertext)

        # Get user input and encrypt the message
        message = input("Enter message: ").encode()
        encrypted_message = bytes([b ^ symmetric_key[i % len(symmetric_key)] for i, b in enumerate(message)])

        # Send encrypted message
        client.sendall(encrypted_message)

        # Receive and decrypt the server's response
        encrypted_response = client.recv(1024)
        decrypted_response = bytes([b ^ symmetric_key[i % len(symmetric_key)] for i, b in enumerate(encrypted_response)])

        print(f"Server response: {decrypted_response.decode()}")
