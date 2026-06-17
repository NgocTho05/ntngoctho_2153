import socket
import threading
import customtkinter as ctk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Cấu hình giao diện CustomTkinter hiện đại
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class P2P_DH_ChatClient:
    def __init__(self, port=55555):
        self.port = port
        self.aes_key = None
        self.sock = None
        
        # Khởi tạo cửa sổ chính
        self.window = ctk.CTk()
        self.window.title("HUTECH P2P Secure Chat (DH-AES)")
        self.window.geometry("500x650")

        # Cơ chế tự động hóa thông minh:
        # Thử kết nối làm Client trước, nếu thất bại (chưa có ai mở cổng) thì tự chuyển thành Host
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            test_sock.connect(('localhost', self.port))
            # Nếu kết nối thành công -> Gán socket này và chạy chế độ Client
            self.sock = test_sock
            self.build_chat_ui("🤝 Đã kết nối (Chế độ: Client). Đang thiết lập khóa...")
            threading.Thread(target=self.start_handshake_as_client, daemon=True).start()
        except:
            # Nếu không kết nối được -> Chưa có ai làm Host -> Mình tự làm Host
            test_sock.close()
            self.start_automatic_host()

        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.window.mainloop()

    def build_chat_ui(self, title_text):
        # Dựng màn hình giao diện chat bong bóng
        self.top_frame = ctk.CTkFrame(self.window, height=50, corner_radius=0, fg_color="#e67e22")
        self.top_frame.pack(fill="x", side="top")
        self.title_label = ctk.CTkLabel(self.top_frame, text=title_text, font=("Arial", 14, "bold"), text_color="white")
        self.title_label.pack(pady=12, padx=15, anchor="w")

        self.chat_frame = ctk.CTkScrollableFrame(self.window, corner_radius=10)
        self.chat_frame.pack(padx=15, pady=(15, 10), fill="both", expand=True)

        self.input_frame = ctk.CTkFrame(self.window, fg_color="transparent")
        self.input_frame.pack(padx=15, pady=(0, 15), fill="x", side="bottom")

        self.msg_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Nhập tin nhắn mã hóa AES...", height=45, corner_radius=20)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.msg_entry.bind("<Return>", lambda e: self.send_message())

        self.send_button = ctk.CTkButton(self.input_frame, text="Gửi", width=90, height=45, corner_radius=20, fg_color="#e67e22", hover_color="#d35400", command=self.send_message)
        self.send_button.pack(side="right")

    def load_server_pem(self):
        # Đọc file PEM từ Server thô của bạn để lấy tham số p, g đúng chuẩn đề bài
        try:
            with open("server_public_key.pem", "rb") as f:
                return serialization.load_pem_public_key(f.read())
        except FileNotFoundError:
            messagebox.showerror("Thiếu File", "Không tìm thấy file 'server_public_key.pem'.\nHãy chạy file Server thô 1 lần để sinh ra file này đặt vào đây!")
            exit()

    def start_automatic_host(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', self.port))
        server_socket.listen(1)
        
        self.build_chat_ui("⏳ Chế độ: Host. Đang chờ máy kia mở lên kết nối...")
        
        def accept_thread():
            try:
                self.sock, addr = server_socket.accept()
                self.title_label.configure(text=f"🤝 Đã kết nối với máy kia qua cổng: {addr[1]}")
                
                # Thực hiện quy trình lấy tham số DH từ file PEM
                server_public_key = self.load_server_pem()
                parameters = server_public_key.parameters()
                private_key = parameters.generate_private_key()
                public_key = private_key.public_key()
                
                # Gửi Public Key của mình đi và nhận lại từ đối phương
                self.sock.send(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
                peer_pub_bytes = self.sock.recv(2048)
                peer_public_key = serialization.load_pem_public_key(peer_pub_bytes)
                
                # Tính Shared Secret -> Tạo khóa AES
                shared_secret = private_key.exchange(peer_public_key)
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'HUTECH_P2P_SALT', iterations=100000)
                self.aes_key = kdf.derive(shared_secret)
                
                self.title_label.configure(text="🔒 Kênh chat P2P bảo mật (DH-AES) đã sẵn sàng!")
                threading.Thread(target=self.receive_messages, daemon=True).start()
            except Exception as e:
                print(f"Lỗi Host: {e}")

        threading.Thread(target=accept_thread, daemon=True).start()

    def start_handshake_as_client(self):
        try:
            # Thực hiện quy trình lấy tham số DH từ file PEM
            server_public_key = self.load_server_pem()
            parameters = server_public_key.parameters()
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            # Nhận Public Key của đối phương trước, rồi gửi Public Key của mình đi
            peer_pub_bytes = self.sock.recv(2048)
            self.sock.send(public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            peer_public_key = serialization.load_pem_public_key(peer_pub_bytes)
            
            # Tính Shared Secret -> Tạo khóa AES
            shared_secret = private_key.exchange(peer_public_key)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'HUTECH_P2P_SALT', iterations=100000)
            self.aes_key = kdf.derive(shared_secret)
            
            self.title_label.configure(text="🔒 Kênh chat P2P bảo mật (DH-AES) đã sẵn sàng!")
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            print(f"Lỗi Client Handshake: {e}")

    def encrypt_message(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        return cipher.iv + cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))

    def decrypt_message(self, enc_msg):
        iv, ct = enc_msg[:16], enc_msg[16:]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

    def send_message(self):
        msg = self.msg_entry.get().strip()
        if msg and self.aes_key:
            try:
                self.sock.send(self.encrypt_message(msg))
                self.display_bubble(msg, True)
                self.msg_entry.delete(0, "end")
            except:
                self.display_bubble("❌ Thất bại: Đối phương đã ngắt kết nối!", True)

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(1024)
                if data: 
                    self.display_bubble(self.decrypt_message(data), False)
            except: 
                break

    def display_bubble(self, msg, is_me):
        row = ctk.CTkFrame(self.chat_frame, fg_color="transparent")
        row.pack(fill="x", pady=5)
        color = "#e67e22" if is_me else ("#e1e4e8", "#2f363d")
        txt_clr = "white" if is_me else ("#24292e", "white")
        bubble = ctk.CTkLabel(row, text=msg, fg_color=color, text_color=txt_clr, corner_radius=15, padx=12, pady=8)
        bubble.pack(side="right" if is_me else "left")
        self.chat_frame._parent_canvas.yview_moveto(1.0)

    def on_closing(self):
        if self.sock:
            self.sock.close()
        self.window.destroy()

if __name__ == "__main__":
    P2P_DH_ChatClient()