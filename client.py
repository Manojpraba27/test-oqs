import socket
import oqs
import hashlib

HOST = "127.0.0.1"
PORT = 12345

# Function to derive a symmetric key from the shared secret
def derive_key(shared_secret):
    return hashlib.sha256(shared_secret).digest()

# Start server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen()
    print(f"Server listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print(f"Connected by {addr}")

        # Kyber key pair generation
        with oqs.KeyEncapsulation("Kyber1024") as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()

            # Send the public key to the client
            conn.sendall(public_key)

            # Receive encrypted data (ciphertext + encrypted message)
            ciphertext = conn.recv(1024)
            encrypted_message = conn.recv(1024)

            # Decrypt the shared secret
            shared_secret = kem.decap_secret(ciphertext)
            symmetric_key = derive_key(shared_secret)

            # Decrypt the message using XOR
            decrypted_message = bytes([b ^ symmetric_key[i % len(symmetric_key)] for i, b in enumerate(encrypted_message)])

            print(f"Client says: {decrypted_message.decode()}")

            # Respond to the client
            response = "Message received!".encode()
            encrypted_response = bytes([b ^ symmetric_key[i % len(symmetric_key)] for i, b in enumerate(response)])
            conn.sendall(encrypted_response)
