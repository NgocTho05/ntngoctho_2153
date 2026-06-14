import os
import socket
import threading
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hutech_secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# Dictionary to map SocketIO session IDs (sid) to their backend TCP client info
# clients[sid] = {'socket': tcp_socket, 'aes_key': aes_key, 'thread': thread, 'username': str}
clients = {}

SERVER_HOST = 'localhost'
SERVER_PORT = 12345

def encrypt_message(aes_key, message):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_message(aes_key, enc_msg):
    iv, ct = enc_msg[:16], enc_msg[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

def load_server_pem():
    try:
        with open("server_public_key.pem", "rb") as f:
            return serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        return None

def tcp_receive_thread(sid, tcp_sock, aes_key):
    while True:
        try:
            data = tcp_sock.recv(2048)
            if not data:
                break
            decrypted_msg = decrypt_message(aes_key, data)
            # Send to the specific web client
            socketio.emit('receive_message', {'message': decrypted_msg}, to=sid)
        except Exception as e:
            print(f"[Client {sid}] Disconnected: {e}")
            break
    
    # Cleanup on disconnect
    if sid in clients:
        tcp_sock.close()
        del clients[sid]
        socketio.emit('status', {'msg': 'Mất kết nối tới Server Chat.'}, to=sid)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    print(f"[Web] Browser connected: {sid}")

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in clients:
        try:
            clients[sid]['socket'].close()
        except:
            pass
        del clients[sid]
    print(f"[Web] Browser disconnected: {sid}")

@socketio.on('join')
def handle_join(data):
    sid = request.sid
    username = data.get('username', 'Anonymous')
    
    server_pub_key = load_server_pem()
    if not server_pub_key:
        emit('status', {'msg': 'Lỗi: Không tìm thấy server_public_key.pem. Hãy chạy Server trước.'}, to=sid)
        return

    try:
        # Connect to the central chat server
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect((SERVER_HOST, SERVER_PORT))
        
        # 1. Receive server's public key
        server_pub_bytes = tcp_sock.recv(2048)
        peer_public_key = serialization.load_pem_public_key(server_pub_bytes)
        
        # 2. Generate client's DH key pair
        parameters = server_pub_key.parameters()
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        # 3. Send client's public key to server
        tcp_sock.send(public_key.public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
        # 4. Compute Shared Secret & AES key
        shared_secret = private_key.exchange(peer_public_key)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), 
            length=32, 
            salt=b'HUTECH_P2P_SALT', 
            iterations=100000
        )
        aes_key = kdf.derive(shared_secret)
        
        # Start background thread to listen to TCP server
        thread = threading.Thread(target=tcp_receive_thread, args=(sid, tcp_sock, aes_key), daemon=True)
        thread.start()
        
        clients[sid] = {
            'socket': tcp_sock,
            'aes_key': aes_key,
            'thread': thread,
            'username': username
        }
        
        emit('status', {'msg': 'Kết nối Server thành công. Kênh mã hóa DH-AES đã sẵn sàng!'}, to=sid)
        
        # Send a join message
        join_msg = f"{username} đã tham gia."
        enc_msg = encrypt_message(aes_key, join_msg)
        tcp_sock.send(enc_msg)
        
    except Exception as e:
        emit('status', {'msg': f'Lỗi kết nối tới Server: {str(e)}'}, to=sid)

@socketio.on('send_message')
def handle_send_message(data):
    sid = request.sid
    if sid not in clients:
        emit('status', {'msg': 'Chưa kết nối tới Server.'}, to=sid)
        return
        
    username = clients[sid]['username']
    text = data.get('message', '')
    if not text:
        return
        
    full_msg = f"{username}: {text}"
    aes_key = clients[sid]['aes_key']
    tcp_sock = clients[sid]['socket']
    
    try:
        enc_msg = encrypt_message(aes_key, full_msg)
        tcp_sock.send(enc_msg)
        # Echo back to sender
        emit('receive_message', {'message': full_msg, 'is_me': True}, to=sid)
    except Exception as e:
        emit('status', {'msg': f'Lỗi gửi tin nhắn: {str(e)}'}, to=sid)

if __name__ == '__main__':
    # Ensure templates folder exists
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    print("[*] Starting Web Client on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
