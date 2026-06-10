import socket
import threading
import customtkinter as ctk
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# Cấu hình giao diện hiện đại (Chủ đề tối/sáng và màu chủ đạo)
ctk.set_appearance_mode("System")  # Tự động theo giao diện máy tính (Light/Dark)
ctk.set_default_color_theme("blue")

class SecureChatClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.aes_key = None
        
        # --- Khởi tạo Socket & Mã hóa ---
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.setup_connection()

        # --- Khởi tạo Cửa sổ ứng dụng ---
        self.window = ctk.CTk()
        self.window.title("HUTECH Secure Chat (AES-RSA)")
        self.window.geometry("500x650")
        self.window.minsize(400, 500)

        # --- Tiêu đề ứng dụng ---
        self.top_frame = ctk.CTkFrame(self.window, height=50, corner_radius=0, fg_color="#1f538d")
        self.top_frame.pack(fill="x", side="top")
        
        self.title_label = ctk.CTkLabel(
            self.top_frame, 
            text="🔒 SECURE CHAT ROOM", 
            font=ctk.CTkFont(family="Arial", size=16, weight="bold"),
            text_color="white"
        )
        self.title_label.pack(pady=12, padx=15, anchor="w")

        # --- Khu vực hiển thị tin nhắn (Scrolled Frame) ---
        self.chat_frame = ctk.CTkScrollableFrame(self.window, corner_radius=10)
        self.chat_frame.pack(padx=15, pady=(15, 10), fill="both", expand=True)

        # --- Khung nhập liệu ở phía dưới ---
        self.input_frame = ctk.CTkFrame(self.window, fg_color="transparent")
        self.input_frame.pack(padx=15, pady=(0, 15), fill="x", side="bottom")

        self.msg_entry = ctk.CTkEntry(
            self.input_frame, 
            placeholder_text="Nhập tin nhắn bảo mật tại đây...", 
            height=45,
            corner_radius=20,
            font=("Arial", 13)
        )
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.msg_entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = ctk.CTkButton(
            self.input_frame, 
            text="Gửi", 
            width=90, 
            height=45,
            corner_radius=20,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#2ecc71",
            hover_color="#27ae60",
            command=self.send_message
        )
        self.send_button.pack(side="right")

        # Thread nhận tin ngầm
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.window.mainloop()

    def setup_connection(self):
        try:
            self.client_socket.connect((self.host, self.port))
            client_key = RSA.generate(2048)
            server_pub_key_raw = self.client_socket.recv(2048)
            
            self.client_socket.send(client_key.publickey().export_key(format='PEM'))
            
            encrypted_aes_key = self.client_socket.recv(2048)
            cipher_rsa = PKCS1_OAEP.new(client_key)
            self.aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        except Exception as e:
            print(f"Lỗi kết nối: {e}")
            exit()

    def encrypt_message(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
        return cipher.iv + ciphertext

    def decrypt_message(self, encrypted_message):
        iv = encrypted_message[:AES.block_size]
        ciphertext = encrypted_message[AES.block_size:]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_message.decode()

    def send_message(self):
        message = self.msg_entry.get().strip()
        if message:
            if message.lower() == 'exit':
                self.on_closing()
                return
            
            encrypted_msg = self.encrypt_message(message)
            self.client_socket.send(encrypted_msg)
            
            # Hiển thị tin nhắn của Bạn (Bên phải, màu xanh dương)
            self.display_bubble(message, is_me=True)
            self.msg_entry.delete(0, "end")

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    break
                
                decrypted_message = self.decrypt_message(encrypted_message)
                # Hiển thị tin nhắn Đối phương (Bên trái, màu xám)
                self.display_bubble(decrypted_message, is_me=False)
            except:
                break

    def display_bubble(self, message, is_me):
        # Tạo một khung chứa dòng tin nhắn để căn lề trái/phải
        row_frame = ctk.CTkFrame(self.chat_frame, fg_color="transparent")
        row_frame.pack(fill="x", pady=5)

        if is_me:
            # Tin nhắn của mình: lệch phải, nền xanh, chữ trắng
            bubble = ctk.CTkLabel(
                row_frame, 
                text=message, 
                fg_color="#1f538d", 
                text_color="white",
                corner_radius=15,
                padx=12,
                pady=8,
                font=("Arial", 13),
                wraplength=250
            )
            bubble.pack(side="right", padx=(50, 5))
        else:
            # Tin nhắn người khác: lệch trái, nền xám nhẹ
            bubble = ctk.CTkLabel(
                row_frame, 
                text=message, 
                fg_color=("#e1e4e8", "#2f363d"), # Màu tương ứng cho [Light, Dark] mode
                text_color=("#24292e", "white"),
                corner_radius=15,
                padx=12,
                pady=8,
                font=("Arial", 13),
                wraplength=250
            )
            bubble.pack(side="left", padx=(5, 50))
            
        # Tự động cuộn xuống dưới cùng khi có tin mới
        self.chat_frame._parent_canvas.yview_moveto(1.0)

    def on_closing(self):
        self.client_socket.close()
        self.window.destroy()
#  pip install customtkinter de sinh thu vien giao dien
if __name__ == "__main__":
    SecureChatClient()