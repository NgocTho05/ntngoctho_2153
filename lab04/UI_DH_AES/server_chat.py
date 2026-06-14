import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST = 'localhost'
PORT = 12345

clients = [] # List to keep track of (client_socket, aes_key, client_address)

def generate_or_load_dh_parameters():
    pem_path = "server_public_key.pem"
    if os.path.exists(pem_path):
        print("[*] Loading existing DH parameters from server_public_key.pem")
        with open(pem_path, "rb") as f:
            server_public_key = serialization.load_pem_public_key(f.read())
        return server_public_key.parameters()
    else:
        print("[*] Generating new DH parameters (this may take a few seconds)...")
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        # Generate a dummy private/public key to save as PEM, just to hold the parameters
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        with open(pem_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("[*] Saved DH parameters to server_public_key.pem")
        return parameters

def encrypt_message(aes_key, message):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_message(aes_key, enc_msg):
    iv, ct = enc_msg[:16], enc_msg[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

def broadcast(message, sender_socket):
    for client_socket, aes_key, addr in clients:
        if client_socket != sender_socket:
            try:
                # Encrypt the plaintext message with this specific client's AES key
                enc_msg = encrypt_message(aes_key, message)
                client_socket.send(enc_msg)
            except Exception as e:
                print(f"[-] Error broadcasting to {addr}: {e}")

def handle_client(client_socket, client_address, dh_parameters):
    print(f"[+] Connection established with {client_address}")
    
    try:
        # 1. Server generates its DH key pair based on parameters
        private_key = dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        
        # 2. Server sends its public key to the client
        client_socket.send(public_key.public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
        # 3. Server receives the client's public key
        peer_pub_bytes = client_socket.recv(2048)
        peer_public_key = serialization.load_pem_public_key(peer_pub_bytes)
        
        # 4. Compute Shared Secret and derive AES key
        shared_secret = private_key.exchange(peer_public_key)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), 
            length=32, 
            salt=b'HUTECH_P2P_SALT', 
            iterations=100000
        )
        aes_key = kdf.derive(shared_secret)
        print(f"[+] DH Key Exchange successful with {client_address}")
        
        # Add client to active list
        clients.append((client_socket, aes_key, client_address))
        
        # Notify others
        # broadcast(f"Server: {client_address} đã tham gia phòng chat.", client_socket)

        # 5. Listen for messages
        while True:
            data = client_socket.recv(2048)
            if not data:
                break
            
            # Decrypt message from sender
            decrypted_msg = decrypt_message(aes_key, data)
            print(f"[{client_address}] {decrypted_msg}")
            
            # Broadcast the decrypted message to other clients
            broadcast(decrypted_msg, client_socket)

    except Exception as e:
        print(f"[-] Client {client_address} disconnected abruptly: {e}")
    finally:
        # Remove client and close socket
        clients_copy = list(clients)
        for client in clients_copy:
            if client[0] == client_socket:
                clients.remove(client)
                break
        client_socket.close()
        print(f"[-] Connection closed for {client_address}")

def start_server():
    parameters = generate_or_load_dh_parameters()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    
    print(f"[*] Central Secure Chat Server listening on {HOST}:{PORT}")
    
    while True:
        client_socket, client_address = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address, parameters))
        thread.start()

if __name__ == "__main__":
    start_server()
