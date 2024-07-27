import os
import socket
import argparse
import threading
import hashlib
import hmac
import base64
from datetime import datetime
from colorama import init, Fore, Style
import cryptography.fernet
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox

init(autoreset=True)

class EncryptedChatClient:
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key
        self.client_socket = None
        self.username = None
        self.message_lock = threading.Lock()
        self.setup_cipher()
        self.root = tk.Tk()
        self.root.title("Decentralized Chat App")
        self.chat_display = None
        self.input_field = None

    def setup_cipher(self):
        hashed_key = hashlib.sha256(self.key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(hashed_key)
        self.cipher = Fernet(fernet_key)

    def extract_hmac_from_transaction(transaction):
        secret_key = b'my_secret_key'
        message = transaction.encode('utf-8')
        expected_hmac = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
        return expected_hmac

    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
        except ConnectionRefusedError as e:
            print(f"An unknown error occurred {e}")
            return False
        return True

    def get_username(self):
        try:
            encrypted_username_prompt = self.client_socket.recv(1024)
            username_prompt = self.cipher.decrypt(encrypted_username_prompt).decode('utf-8')
            print(Fore.CYAN + username_prompt, end="")
            username = input()
            encrypted_username = self.cipher.encrypt(username.encode('utf-8'))
            self.client_socket.send(encrypted_username)
            encrypted_response = self.client_socket.recv(1024)
            response = self.cipher.decrypt(encrypted_response).decode('utf-8')
            if "Please enter a different name." in response:
                print(Fore.RED + response)
                return False
            self.username = username
            print(Fore.BLUE + "Help Menu:")
            print("\t/help       -> Help menu")
            return True
        except cryptography.fernet.InvalidToken:
            print(Fore.RED + "Error: The encryption key is invalid or data is corrupted.")
            return False

    def createBlock(self, transaction):
        # Generate a block containing the transaction data
        block = {
            'transaction': transaction,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        return block

    def verifyTransaction(self, transaction):
        # Implement HMAC verification for the transaction
        secret_key = b'my_secret_key'
        message = transaction.encode('utf-8')  # UTF-8 encoding
        received_hmac = self.extract_hmac_from_transaction(transaction)
        if received_hmac is None:
            return False  # Unable to extract HMAC, transaction is invalid
    
        expected_hmac = hmac.new(secret_key, message, hashlib.sha256).hexdigest()  # UTF-8 encoding
        return hmac.compare_digest(expected_hmac, received_hmac)

    def mineBlock(self, block):
        # Implement proof of work or any equivalent mining process
        nonce = 0
        while True:
            block['nonce'] = nonce
            if self.valid_proof(block):
                return block
            nonce += 1

    def valid_proof(self, block):
        # Example: Check if the hash of the block meets a specific condition (e.g., starts with '0000')
        block_hash = hashlib.sha256(str(block).encode()).hexdigest()
        return block_hash.startswith('0000')

    def viewUser(self):
        try:
            # Request viewing all successful transactions against the user
            encrypted_request = self.cipher.encrypt("/view_user".encode('utf-8'))
            self.client_socket.send(encrypted_request)

            # Receive and decrypt the response
            encrypted_response = self.client_socket.recv(1024)
            decrypted_response = self.cipher.decrypt(encrypted_response).decode('utf-8')

            # Print the response
            print(decrypted_response)

        except cryptography.fernet.InvalidToken:
            print(Fore.RED + "Error: The encryption key is invalid or data is corrupted.")
            return False

    def listen_to_server(self):
        while True:
            try:
                encrypted_data = self.client_socket.recv(1024)
                decrypted_data = self.cipher.decrypt(encrypted_data).decode('utf-8')

                if decrypted_data == "/clear":
                    os.system('cls' if os.name == 'nt' else 'clear')
                    continue

                with self.message_lock:
                    self.chat_display.config(state=tk.NORMAL)
                    self.chat_display.insert(tk.END, f"{decrypted_data}\n")
                    self.chat_display.config(state=tk.DISABLED)
                    self.chat_display.see(tk.END)

            except cryptography.fernet.InvalidToken:
                continue
            except BrokenPipeError as e:
                if e.errno == 32:
                    continue
                else:
                    print(f"An unknown error occurred: {e}")

    def send_message(self, message):
        try:
            encrypted_message = self.cipher.encrypt(message.encode('utf-8'))
            self.client_socket.send(encrypted_message)
        except cryptography.fernet.InvalidToken:
            print(Fore.RED + "Error: The encryption key is invalid or data is corrupted.")

    def create_gui(self):
        self.root.configure(bg='black')  # Set background color of the window

        self.chat_display = tk.Text(self.root, state="disabled", bg='black', fg='white', wrap='word')
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        self.input_field = tk.Entry(self.root, bg='white', fg='black')
        self.input_field.pack(fill=tk.X)

        send_button = tk.Button(self.root, text="Send", command=self.on_send, bg='blue', fg='white')
        send_button.pack(fill=tk.X)

        threading.Thread(target=self.listen_to_server, daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_send(self):
        message = self.input_field.get()
        self.send_message(message)
        self.input_field.delete(0, tk.END)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.send_message("/exit")
            self.root.destroy()
            self.client_socket.close()

    def run(self):
        if self.connect():
            if self.get_username():
                self.create_gui()
        else:
            self.client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect to the chat server.")
    parser.add_argument("--host", default="127.0.0.1", help="The server's IP address.")
    parser.add_argument("--port", type=int, default=12345, help="The port number of the server.")
    parser.add_argument("--key", default="mysecretpassword", help="The secret key for encryption.")
    args = parser.parse_args()

    client = EncryptedChatClient(args.host, args.port, args.key)
    client.run()
